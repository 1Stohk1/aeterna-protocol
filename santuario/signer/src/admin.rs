//! v0.3.0 "Oculus" — read-only observability surface.
//!
//! The Admin service is strictly an observer. It never signs, never
//! unseals the vault, never mutates the signer's state machine. Every
//! RPC is callable from *any* signer verdict — a suspended signer is
//! still fully visible to its operator, by contract
//! (see docs/SPRINT-v0.3.0.md §2).
//!
//! The service is mounted on the SAME listener as `Signer` via
//! `Server::builder().add_service(signer).add_service(admin)` — one
//! port, two services. This matters for the Windows dev path where we
//! fall back from UDS to loopback TCP on `$SANTUARIO_PORT`.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::metrics::MetricsRegistry;
use crate::peers::PeerSnapshotReader;
use crate::sentinel_metrics::SentinelMetricsReader;

use santuario_integrity::AuditLog;

pub mod pb {
    tonic::include_proto!("santuario.admin.v1");
}

use pb::admin_server::{Admin, AdminServer};
use pb::{
    AuditLogLine, GetMetricsRequest, GetMetricsResponse, ListPeersRequest, ListPeersResponse,
    Peer as PbPeer, Quantiles as PbQuantiles, TailAuditLogRequest, TailAuditLogResponse,
};

/// Bumped whenever a new counter/gauge/quantile key is added.
/// See admin.proto `GetMetricsResponse.schema_version`.
pub const METRICS_SCHEMA_VERSION: u32 = 1;

/// Server-side cap on `TailAuditLogRequest.limit` (see admin.proto).
pub const TAIL_LIMIT_MAX: u32 = 1000;
/// Default when the client asks for 0 / unset.
pub const TAIL_LIMIT_DEFAULT: u32 = 20;

#[derive(Clone)]
pub struct AdminService {
    pub node_id: String,
    pub metrics: Arc<MetricsRegistry>,
    pub audit_log: AuditLog,
    pub peers: PeerSnapshotReader,
    /// v0.3.0 — the Python Sentinel publishes `aeterna_*` counters
    /// and gauges via an atomic JSON file; the Admin service merges
    /// them into its response at query time.
    pub sentinel_metrics: SentinelMetricsReader,
}

#[tonic::async_trait]
impl Admin for AdminService {
    async fn get_metrics(
        &self,
        _req: Request<GetMetricsRequest>,
    ) -> Result<Response<GetMetricsResponse>, Status> {
        let snap = self.metrics.snapshot();
        let quantiles = snap
            .quantiles
            .into_iter()
            .map(|(k, (p50, p90, p99))| (k, PbQuantiles { p50, p90, p99 }))
            .collect();

        // Merge in the Sentinel-side `aeterna_*` contribution. By
        // contract (admin.proto + SPRINT-v0.3.0 §7.2), the namespaces
        // are disjoint so an insert-on-first-write merge is safe; on
        // collision the Rust-side value wins (source-of-truth rule —
        // `santuario_*` is authoritative for anything Rust-side).
        let sentinel = self.sentinel_metrics.read();
        let mut counters = snap.counters;
        for (k, v) in sentinel.counters {
            counters.entry(k).or_insert(v);
        }
        let mut gauges = snap.gauges;
        for (k, v) in sentinel.gauges {
            gauges.entry(k).or_insert(v);
        }

        Ok(Response::new(GetMetricsResponse {
            schema_version: METRICS_SCHEMA_VERSION,
            node_id: self.node_id.clone(),
            ts_utc: santuario_integrity::now_utc(),
            counters,
            gauges,
            quantiles,
            metric_window_seconds: snap.window_seconds,
        }))
    }

    async fn tail_audit_log(
        &self,
        req: Request<TailAuditLogRequest>,
    ) -> Result<Response<TailAuditLogResponse>, Status> {
        let mut limit = req.into_inner().limit;
        if limit == 0 {
            limit = TAIL_LIMIT_DEFAULT;
        }
        if limit > TAIL_LIMIT_MAX {
            limit = TAIL_LIMIT_MAX;
        }
        let lines = read_audit_tail(&self.audit_log, limit as usize)
            .map_err(|e| Status::internal(format!("audit tail read failed: {e}")))?;
        Ok(Response::new(TailAuditLogResponse { lines }))
    }

    async fn list_peers(
        &self,
        _req: Request<ListPeersRequest>,
    ) -> Result<Response<ListPeersResponse>, Status> {
        let snap = self.peers.read();
        let snapshot_utc = if snap.snapshot_utc > 0 {
            snap.snapshot_utc
        } else {
            santuario_integrity::now_utc()
        };
        let peers = snap
            .peers
            .into_iter()
            .map(|p| PbPeer {
                address: p.address,
                node_id: p.node_id,
                last_seen_utc: p.last_seen_utc,
                rx_count: p.rx_count,
                tx_count: p.tx_count,
                is_bootstrap: p.is_bootstrap,
            })
            .collect();
        Ok(Response::new(ListPeersResponse {
            peers,
            snapshot_utc,
        }))
    }
}

/// Read the audit log as raw JSONL and peel off the last `limit`
/// non-empty lines, preserving the byte-identical raw JSON and parsing
/// only enough to populate `ts_utc` and `record`. Per admin.proto: the
/// server MUST NOT re-shape the JSON — forensic integrity depends on
/// byte-equality between the War Room view and what landed on disk.
fn read_audit_tail(log: &AuditLog, limit: usize) -> std::io::Result<Vec<AuditLogLine>> {
    if !log.path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&log.path)?;
    let all: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = all.len().saturating_sub(limit);
    let mut out = Vec::with_capacity(all.len() - start);
    for l in &all[start..] {
        let (ts_utc, record) = parse_line_meta(l);
        out.push(AuditLogLine {
            ts_utc,
            record,
            json: (*l).to_string(),
        });
    }
    Ok(out)
}

fn parse_line_meta(raw: &str) -> (i64, String) {
    // Best-effort parse — never errors. If the JSON is off-shape we
    // still surface the raw line; the client can parse it however it
    // likes.
    let v: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return (0, String::new()),
    };
    let ts = v.get("ts_utc").and_then(|x| x.as_i64()).unwrap_or(0);
    let rec = v
        .get("record")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    (ts, rec)
}

/// Wrap an `AdminService` in the tonic `AdminServer` ready to be added
/// to a `Server::builder()` chain.
pub fn server(svc: AdminService) -> AdminServer<AdminService> {
    AdminServer::new(svc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use santuario_integrity::{AlertEvidence, AlertKind, IntegrityAlert};

    fn make_service_in(dir: &std::path::Path) -> AdminService {
        AdminService {
            node_id: "Prometheus-test".to_string(),
            metrics: Arc::new(MetricsRegistry::default()),
            audit_log: AuditLog::new(dir.join("audit.jsonl")),
            peers: PeerSnapshotReader::new(dir.join("peers.json")),
            sentinel_metrics: SentinelMetricsReader::new(
                dir.join("sentinel_metrics.json"),
            ),
        }
    }

    #[tokio::test]
    async fn get_metrics_empty_registry() {
        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());
        let resp = svc
            .get_metrics(Request::new(GetMetricsRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.schema_version, METRICS_SCHEMA_VERSION);
        assert_eq!(resp.node_id, "Prometheus-test");
        assert!(resp.counters.is_empty());
        assert!(resp.gauges.is_empty());
        assert!(resp.quantiles.is_empty());
    }

    #[tokio::test]
    async fn get_metrics_round_trips_incrs() {
        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());
        svc.metrics.incr("santuario_sign_total");
        svc.metrics.incr_by("santuario_sign_accept_total", 3);
        svc.metrics.set_gauge("santuario_vault_sealed", 0.0);
        svc.metrics.observe("santuario_sign_latency_seconds", 0.010);
        let resp = svc
            .get_metrics(Request::new(GetMetricsRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.counters["santuario_sign_total"], 1);
        assert_eq!(resp.counters["santuario_sign_accept_total"], 3);
        assert_eq!(resp.gauges["santuario_vault_sealed"], 0.0);
        assert!(resp
            .quantiles
            .contains_key("santuario_sign_latency_seconds"));
    }

    #[tokio::test]
    async fn tail_missing_log_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());
        let resp = svc
            .tail_audit_log(Request::new(TailAuditLogRequest { limit: 10 }))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.lines.is_empty());
    }

    #[tokio::test]
    async fn tail_caps_at_1000_and_defaults_to_20() {
        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());
        // 25 records so we can see the 20-default cap kick in.
        for _ in 0..25 {
            let alert = IntegrityAlert {
                kind: AlertKind::Alpha,
                ts_utc: 1_713_542_400,
                node_id: "Prometheus-test".to_string(),
                evidence: AlertEvidence::AlphaMismatch {
                    path: std::path::PathBuf::from("M.md"),
                    expected_sha256: "aa".repeat(32),
                    observed_sha256: "bb".repeat(32),
                },
            };
            svc.audit_log.log_alert(&alert).unwrap();
        }
        let resp_default = svc
            .tail_audit_log(Request::new(TailAuditLogRequest { limit: 0 }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp_default.lines.len(), TAIL_LIMIT_DEFAULT as usize);
        let resp_cap = svc
            .tail_audit_log(Request::new(TailAuditLogRequest { limit: 9999 }))
            .await
            .unwrap()
            .into_inner();
        // We only have 25 lines on disk; the cap doesn't matter here,
        // but the request having been accepted DOES.
        assert_eq!(resp_cap.lines.len(), 25);
    }

    #[tokio::test]
    async fn tail_preserves_raw_json_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());
        let alert = IntegrityAlert {
            kind: AlertKind::Alpha,
            ts_utc: 1_713_542_400,
            node_id: "Prometheus-test".to_string(),
            evidence: AlertEvidence::AlphaMismatch {
                path: std::path::PathBuf::from("MANIFESTO.md"),
                expected_sha256: "aa".repeat(32),
                observed_sha256: "bb".repeat(32),
            },
        };
        svc.audit_log.log_alert(&alert).unwrap();
        let raw = std::fs::read_to_string(&svc.audit_log.path).unwrap();
        let expected_first_line = raw.lines().next().unwrap().to_string();
        let resp = svc
            .tail_audit_log(Request::new(TailAuditLogRequest { limit: 10 }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.lines.len(), 1);
        assert_eq!(resp.lines[0].json, expected_first_line);
        assert_eq!(resp.lines[0].ts_utc, 1_713_542_400);
        assert_eq!(resp.lines[0].record, "alert");
    }

    #[tokio::test]
    async fn get_metrics_merges_sentinel_file() {
        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());
        svc.metrics.incr("santuario_sign_total");

        // Write a plausible Sentinel snapshot.
        let sentinel_json = r#"{
            "snapshot_utc": 1713542400,
            "counters": {"aeterna_gossip_rx_total": 99},
            "gauges":   {"aeterna_task_queue_depth": 4.0}
        }"#;
        std::fs::write(&svc.sentinel_metrics.path, sentinel_json).unwrap();

        let resp = svc
            .get_metrics(Request::new(GetMetricsRequest {}))
            .await
            .unwrap()
            .into_inner();
        // Rust signal still there.
        assert_eq!(resp.counters["santuario_sign_total"], 1);
        // Sentinel signal merged in.
        assert_eq!(resp.counters["aeterna_gossip_rx_total"], 99);
        assert_eq!(resp.gauges["aeterna_task_queue_depth"], 4.0);
    }

    #[tokio::test]
    async fn get_metrics_rust_wins_on_collision() {
        // Defensive — the namespaces are disjoint by contract, but if
        // a buggy Sentinel wrote a `santuario_*` key the Rust value
        // must still win (source-of-truth rule).
        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());
        svc.metrics.incr_by("santuario_sign_total", 5);

        let rogue = r#"{
            "snapshot_utc": 1,
            "counters": {"santuario_sign_total": 999},
            "gauges": {}
        }"#;
        std::fs::write(&svc.sentinel_metrics.path, rogue).unwrap();
        let resp = svc
            .get_metrics(Request::new(GetMetricsRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.counters["santuario_sign_total"], 5);
    }

    #[tokio::test]
    async fn list_peers_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());
        let resp = svc
            .list_peers(Request::new(ListPeersRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.peers.is_empty());
        // snapshot_utc is filled with "now" when no file exists.
        assert!(resp.snapshot_utc > 0);
    }
}
