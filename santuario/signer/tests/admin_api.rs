//! v0.3.0 "Oculus" — end-to-end integration test for the Admin gRPC surface.
//!
//! Task #17 from SPRINT-v0.3.0 Phase A. Contracts under test:
//!
//!   (1) Every Admin RPC (`GetMetrics`, `TailAuditLog`, `ListPeers`) is
//!       callable independently of the signer's state machine — the
//!       Admin service is constructed *without* any `SignerState`,
//!       vault, keystore, or critic collaborator. The fact that this
//!       test compiles at all is half the proof; the RPC calls returning
//!       OK is the other half.
//!
//!   (2) `GetMetricsResponse.schema_version` is stable and matches the
//!       constant exported by the library. Bumping the constant without
//!       bumping the proto is a contract violation; this test catches it.
//!
//!   (3) `TailAuditLog` returns byte-identical JSON to what's on disk.
//!       Forensic integrity depends on the War Room reading what was
//!       actually written, not a server-reshaped version of it.
//!
//! The test spins up a real tonic server on an ephemeral loopback TCP
//! port and dials it with `AdminClient`, exercising the wire format too
//! (not just the in-process tokio-test path already covered by
//! `admin.rs`'s `#[cfg(test)]` unit tests).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Endpoint, Server};

use santuario_integrity::{AlertEvidence, AlertKind, AuditLog, IntegrityAlert};
use santuario_signer::admin::pb::admin_client::AdminClient;
use santuario_signer::admin::pb::{GetMetricsRequest, ListPeersRequest, TailAuditLogRequest};
use santuario_signer::admin::{self, AdminService, METRICS_SCHEMA_VERSION, TAIL_LIMIT_DEFAULT};
use santuario_signer::metrics::MetricsRegistry;
use santuario_signer::peers::PeerSnapshotReader;
use santuario_signer::sentinel_metrics::SentinelMetricsReader;

/// Harness: tempdir, an AdminService wired over it, and the bound
/// SocketAddr of a tonic server serving it in a background task.
struct Harness {
    _tmp: tempfile::TempDir,
    addr: SocketAddr,
    audit_log_path: std::path::PathBuf,
    sentinel_metrics_path: std::path::PathBuf,
    peers_path: std::path::PathBuf,
    metrics: Arc<MetricsRegistry>,
    audit_log: AuditLog,
}

impl Harness {
    async fn start() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().to_path_buf();

        let audit_log_path = dir.join("audit.jsonl");
        let sentinel_metrics_path = dir.join("sentinel_metrics.json");
        let peers_path = dir.join("peers.json");

        let metrics = Arc::new(MetricsRegistry::default());
        let audit_log = AuditLog::new(audit_log_path.clone());

        let svc = AdminService {
            node_id: "Prometheus-test".to_string(),
            metrics: metrics.clone(),
            audit_log: audit_log.clone(),
            peers: PeerSnapshotReader::new(peers_path.clone()),
            sentinel_metrics: SentinelMetricsReader::new(sentinel_metrics_path.clone()),
        };

        // Ephemeral port — bind first to learn the address, then hand
        // the live listener to tonic as an incoming stream.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let incoming = TcpListenerStream::new(listener);

        tokio::spawn(async move {
            Server::builder()
                .add_service(admin::server(svc))
                .serve_with_incoming(incoming)
                .await
                .expect("server task");
        });

        // Give tonic a beat to start accepting before the client dials.
        // In practice `TcpListener::bind` already has the socket listening
        // — tonic's layer-7 wiring is what we're waiting for.
        tokio::time::sleep(Duration::from_millis(50)).await;

        Self {
            _tmp: tmp,
            addr,
            audit_log_path,
            sentinel_metrics_path,
            peers_path,
            metrics,
            audit_log,
        }
    }

    async fn client(&self) -> AdminClient<Channel> {
        let uri = format!("http://{}", self.addr);
        let ep = Endpoint::from_shared(uri)
            .expect("endpoint")
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(2));
        let ch = ep.connect().await.expect("connect");
        AdminClient::new(ch)
    }
}

// --- tests -----------------------------------------------------------------

/// Contract (1) + (2): every RPC returns OK on a fresh harness, the
/// schema_version matches the library constant, and no RPC depends on
/// any signer-side state (we never constructed one).
#[tokio::test]
async fn admin_rpcs_return_on_blank_state_and_report_stable_schema() {
    let h = Harness::start().await;
    let mut client = h.client().await;

    // GetMetrics — empty registry, no files on disk; still must return OK.
    let resp = client
        .get_metrics(GetMetricsRequest {})
        .await
        .expect("get_metrics OK")
        .into_inner();
    assert_eq!(resp.schema_version, METRICS_SCHEMA_VERSION);
    assert_eq!(resp.node_id, "Prometheus-test");
    assert!(resp.counters.is_empty());
    assert!(resp.gauges.is_empty());
    assert!(resp.quantiles.is_empty());

    // TailAuditLog — no file on disk; empty response, not error.
    let resp = client
        .tail_audit_log(TailAuditLogRequest { limit: 0 })
        .await
        .expect("tail_audit_log OK")
        .into_inner();
    assert!(resp.lines.is_empty());

    // ListPeers — no file on disk; empty peers, snapshot_utc filled with now.
    let resp = client
        .list_peers(ListPeersRequest {})
        .await
        .expect("list_peers OK")
        .into_inner();
    assert!(resp.peers.is_empty());
    assert!(resp.snapshot_utc > 0);
}

/// Contract (1) elaborated: after we stuff data into both the Rust-side
/// MetricsRegistry and the Sentinel-side JSON file, GetMetrics merges
/// them. Proves the disjoint-namespace merge survives the HTTP/2 hop.
#[tokio::test]
async fn get_metrics_merges_rust_and_sentinel_sources_over_the_wire() {
    let h = Harness::start().await;

    // Rust-side telemetry.
    h.metrics.incr_by("santuario_sign_total", 4);
    h.metrics.incr("santuario_sign_accept_total");
    h.metrics.set_gauge("santuario_vault_sealed", 0.0);
    h.metrics.observe("santuario_sign_latency_seconds", 0.012);

    // Sentinel-side telemetry — published atomically by the Python side.
    let sentinel_json = r#"{
        "snapshot_utc": 1713542400,
        "counters": {
            "aeterna_gossip_rx_total": 17,
            "aeterna_block_tx_total": 2
        },
        "gauges": {
            "aeterna_task_queue_depth": 3.0
        }
    }"#;
    std::fs::write(&h.sentinel_metrics_path, sentinel_json).expect("write sentinel metrics");

    let mut client = h.client().await;
    let resp = client
        .get_metrics(GetMetricsRequest {})
        .await
        .expect("get_metrics OK")
        .into_inner();

    // Namespace: santuario_* from Rust-side registry.
    assert_eq!(resp.counters["santuario_sign_total"], 4);
    assert_eq!(resp.counters["santuario_sign_accept_total"], 1);
    assert_eq!(resp.gauges["santuario_vault_sealed"], 0.0);
    assert!(resp
        .quantiles
        .contains_key("santuario_sign_latency_seconds"));

    // Namespace: aeterna_* from Sentinel-side JSON.
    assert_eq!(resp.counters["aeterna_gossip_rx_total"], 17);
    assert_eq!(resp.counters["aeterna_block_tx_total"], 2);
    assert_eq!(resp.gauges["aeterna_task_queue_depth"], 3.0);

    // schema_version is a hard contract — clients pin on it.
    assert_eq!(resp.schema_version, METRICS_SCHEMA_VERSION);
}

/// Contract (3): the `json` field of each TailAuditLog line must be
/// byte-identical to the corresponding line on disk. This is the
/// forensic-integrity rule from admin.proto / SPRINT-v0.3.0 §7.3.
#[tokio::test]
async fn tail_audit_log_returns_byte_identical_json_over_the_wire() {
    let h = Harness::start().await;

    // Seed a handful of alerts with distinct evidence shapes.
    for i in 0..3u32 {
        let alert = IntegrityAlert {
            kind: AlertKind::Alpha,
            ts_utc: 1_713_542_400 + i as i64,
            node_id: "Prometheus-test".to_string(),
            evidence: AlertEvidence::AlphaMismatch {
                path: std::path::PathBuf::from(format!("MANIFESTO-{i}.md")),
                expected_sha256: "aa".repeat(32),
                observed_sha256: "bb".repeat(32),
            },
        };
        h.audit_log.log_alert(&alert).expect("log alert");
    }

    // Snapshot what's on disk BEFORE dialing — this is the ground truth.
    let raw = std::fs::read_to_string(&h.audit_log_path).expect("read audit log");
    let on_disk_lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(on_disk_lines.len(), 3);

    let mut client = h.client().await;
    let resp = client
        .tail_audit_log(TailAuditLogRequest { limit: 10 })
        .await
        .expect("tail_audit_log OK")
        .into_inner();
    assert_eq!(resp.lines.len(), 3);

    // Byte-identical check — each `.json` field matches the on-disk line
    // EXACTLY, including whitespace and field order. If the server ever
    // round-trips through `serde_json::to_string` this test will fail.
    for (got, expected_raw) in resp.lines.iter().zip(on_disk_lines.iter()) {
        assert_eq!(got.json, *expected_raw, "JSON bytes must match on-disk");
        assert_eq!(got.record, "alert");
        assert!(got.ts_utc >= 1_713_542_400);
    }
}

/// Contract guard-rail: the server-side defaults for `TailAuditLog`
/// hold across the wire — limit=0 means "default", which must equal
/// the library-exported constant.
#[tokio::test]
async fn tail_audit_log_default_limit_is_respected_over_the_wire() {
    let h = Harness::start().await;

    // Write MORE lines than TAIL_LIMIT_DEFAULT so clipping is observable.
    let surplus = (TAIL_LIMIT_DEFAULT + 5) as i64;
    for i in 0..surplus {
        let alert = IntegrityAlert {
            kind: AlertKind::Alpha,
            ts_utc: 1_713_542_400 + i,
            node_id: "Prometheus-test".to_string(),
            evidence: AlertEvidence::AlphaMismatch {
                path: std::path::PathBuf::from(format!("M-{i}.md")),
                expected_sha256: "aa".repeat(32),
                observed_sha256: "bb".repeat(32),
            },
        };
        h.audit_log.log_alert(&alert).expect("log alert");
    }

    let mut client = h.client().await;
    let resp = client
        .tail_audit_log(TailAuditLogRequest { limit: 0 })
        .await
        .expect("tail_audit_log OK")
        .into_inner();
    assert_eq!(resp.lines.len(), TAIL_LIMIT_DEFAULT as usize);
}

/// Contract (1) hardened: write a live peers snapshot and confirm the
/// same record comes back through `ListPeers`. The `PeerSnapshotReader`
/// reads lazily on every call, so this also proves the Admin service
/// sees fresh data without a process restart.
#[tokio::test]
async fn list_peers_reflects_live_snapshot_file() {
    let h = Harness::start().await;

    let peers_json = r#"{
        "snapshot_utc": 1713542400,
        "peers": [
            {
                "address": "udp://192.168.1.19:4444",
                "node_id": "Prometheus-2",
                "last_seen_utc": 1713542390,
                "rx_count": 12,
                "tx_count": 7,
                "is_bootstrap": true
            },
            {
                "address": "udp://203.0.113.10:4444",
                "node_id": "",
                "last_seen_utc": 0,
                "rx_count": 0,
                "tx_count": 0,
                "is_bootstrap": false
            }
        ]
    }"#;
    std::fs::write(&h.peers_path, peers_json).expect("write peers snapshot");

    let mut client = h.client().await;
    let resp = client
        .list_peers(ListPeersRequest {})
        .await
        .expect("list_peers OK")
        .into_inner();
    assert_eq!(resp.snapshot_utc, 1_713_542_400);
    assert_eq!(resp.peers.len(), 2);

    let bootstrap = resp
        .peers
        .iter()
        .find(|p| p.address == "udp://192.168.1.19:4444")
        .expect("bootstrap peer present");
    assert!(bootstrap.is_bootstrap);
    assert_eq!(bootstrap.node_id, "Prometheus-2");
    assert_eq!(bootstrap.rx_count, 12);
    assert_eq!(bootstrap.tx_count, 7);

    let discovered = resp
        .peers
        .iter()
        .find(|p| p.address == "udp://203.0.113.10:4444")
        .expect("discovered peer present");
    assert!(!discovered.is_bootstrap);
}
