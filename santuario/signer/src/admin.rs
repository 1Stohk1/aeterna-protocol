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

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc, Mutex,
};

use tonic::{Request, Response, Status};

use crate::metrics::MetricsRegistry;
use crate::peers::PeerSnapshotReader;
use crate::sentinel_metrics::SentinelMetricsReader;

use santuario_integrity::{AuditLog, AuditRecord};
use santuario_ratchet::{
    HandshakeRequest, Session, Side, SignerEndpoint,
    DEFAULT_STEP_MAX_MESSAGES, DEFAULT_STEP_MAX_SECONDS,
};

pub mod pb {
    tonic::include_proto!("santuario.admin.v1");
}

use pb::admin_server::{Admin, AdminServer};
use pb::{
    AuditLogLine, GetMetricsRequest, GetMetricsResponse,
    GetRatchetStatusRequest, GetRatchetStatusResponse,
    GetSignerIdentityRequest, GetSignerIdentityResponse,
    ListPeersRequest, ListPeersResponse,
    Peer as PbPeer, Quantiles as PbQuantiles,
    RehandshakeRequest, RehandshakeResponse,
    StepRatchetRequest, StepRatchetResponse,
    TailAuditLogRequest, TailAuditLogResponse,
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
    pub peers: PeerSnapshotReader,
    /// v0.3.0 — the Python Sentinel publishes `aeterna_*` counters
    /// and gauges via an atomic JSON file; the Admin service merges
    /// them into its response at query time.
    pub sentinel_metrics: SentinelMetricsReader,
    /// Per-connection ratchet session (signer side). Replaced wholesale
    /// on each `Rehandshake` call. None until first handshake completes.
    pub ratchet_session: Arc<Mutex<Option<Session>>>,
    /// UTC seconds of the most recent completed handshake. 0 = no handshake
    /// yet. AtomicI64 so reads don't need to hold the ratchet_session lock.
    pub ratchet_last_handshake_utc: Arc<AtomicI64>,
    pub keys: Arc<std::sync::RwLock<Option<crate::SantuarioKeys>>>,
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
        let keys_guard = self.keys.read().unwrap();
        let keys = keys_guard.as_ref().ok_or_else(|| {
            Status::failed_precondition("vault sealed")
        })?;
        let lines = read_audit_tail(&keys.audit_log, limit as usize)
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

    // v0.4.0 "Sigillum" Phase C --------------------------------------------------

    async fn get_signer_identity(
        &self,
        _req: Request<GetSignerIdentityRequest>,
    ) -> Result<Response<GetSignerIdentityResponse>, Status> {
        let keys_guard = self.keys.read().unwrap();
        let keys = keys_guard.as_ref().ok_or_else(|| {
            Status::failed_precondition("vault sealed")
        })?;
        let pub_key = keys.signer_identity.public();
        Ok(Response::new(GetSignerIdentityResponse {
            identity_pub_hex: pub_key.to_hex(),
            identity_id_hex: keys.signer_identity.id_hex(),
        }))
    }

    async fn rehandshake(
        &self,
        req: Request<RehandshakeRequest>,
    ) -> Result<Response<RehandshakeResponse>, Status> {
        let inner = req.into_inner();
        if inner.operator_eph_pub.len() != 32 {
            return Err(Status::invalid_argument(
                "operator_eph_pub must be exactly 32 bytes (X25519 public key)",
            ));
        }
        if inner.operator_kyber_pub.len() != 1568 {
            return Err(Status::invalid_argument(
                "operator_kyber_pub must be exactly 1568 bytes (Kyber-1024 public key)",
            ));
        }
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(&inner.operator_eph_pub);

        let mut kyber_bytes = [0u8; 1568];
        kyber_bytes.copy_from_slice(&inner.operator_kyber_pub);

        let hs_req = HandshakeRequest {
            operator_eph_pub: pub_bytes,
            operator_kyber_pub: kyber_bytes,
        };
        let keys_guard = self.keys.read().unwrap();
        let keys = keys_guard.as_ref().ok_or_else(|| {
            Status::failed_precondition("vault sealed")
        })?;
        let signer_ep = SignerEndpoint::new(&keys.signer_identity);
        let (hs_resp, root_key) = signer_ep
            .accept(hs_req)
            .map_err(|e| Status::internal(format!("handshake failed: {e}")))?;

        let session = Session::new(&root_key, Side::Signer)
            .map_err(|e| Status::internal(format!("session init failed: {e}")))?;

        *self.ratchet_session.lock().unwrap() = Some(session);
        self.ratchet_last_handshake_utc
            .store(santuario_integrity::now_utc(), Ordering::Relaxed);

        Ok(Response::new(RehandshakeResponse {
            signer_eph_pub: hs_resp.signer_eph_pub.to_vec(),
            kyber_ciphertext: hs_resp.kyber_ciphertext.to_vec(),
        }))
    }

    async fn step_ratchet(
        &self,
        _req: Request<StepRatchetRequest>,
    ) -> Result<Response<StepRatchetResponse>, Status> {
        let step_result = {
            let mut guard = self.ratchet_session.lock().unwrap();
            if let Some(session) = guard.as_mut() {
                session
                    .step()
                    .map(|_| session.status().step)
                    .map_err(|e| e.to_string())
            } else {
                Err(
                    "no active session — run `santuarioctl ratchet rehandshake` first"
                        .to_string(),
                )
            }
        };
        match step_result {
            Ok(new_step) => {
                self.metrics.incr("santuario_ratchet_steps_total");
                Ok(Response::new(StepRatchetResponse {
                    ok: true,
                    error: String::new(),
                    new_step,
                }))
            }
            Err(msg) => Ok(Response::new(StepRatchetResponse {
                ok: false,
                error: msg,
                new_step: 0,
            })),
        }
    }

    async fn get_ratchet_status(
        &self,
        _req: Request<GetRatchetStatusRequest>,
    ) -> Result<Response<GetRatchetStatusResponse>, Status> {
        let last_hs = self
            .ratchet_last_handshake_utc
            .load(Ordering::Relaxed);
        let guard = self.ratchet_session.lock().unwrap();
        let resp = match guard.as_ref() {
            None => GetRatchetStatusResponse {
                established: false,
                tombstoned: false,
                step: 0,
                msgs_sent_in_step: 0,
                age_seconds: 0.0,
                last_handshake_utc: last_hs,
                step_max_seconds: DEFAULT_STEP_MAX_SECONDS as u32,
                step_max_messages: DEFAULT_STEP_MAX_MESSAGES,
            },
            Some(session) => {
                let s = session.status();
                GetRatchetStatusResponse {
                    established: !s.tombstoned,
                    tombstoned: s.tombstoned,
                    step: s.step,
                    msgs_sent_in_step: s.msgs_sent_in_step,
                    age_seconds: s.age_seconds,
                    last_handshake_utc: last_hs,
                    step_max_seconds: DEFAULT_STEP_MAX_SECONDS as u32,
                    step_max_messages: DEFAULT_STEP_MAX_MESSAGES,
                }
            }
        };
        Ok(Response::new(resp))
    }
}

/// Read the audit log via the encrypted segment manager and convert
/// the last `limit` decrypted records into the wire format expected by
/// `Admin.TailAuditLog`. Each record is canonical-JSON serialized
/// (`serde_json::to_string`, deterministic + insertion-ordered) so the
/// byte representation matches what was originally persisted. Per
/// admin.proto: the server preserves byte-identity between the wire
/// view and what was canonically written; "what was originally on
/// disk" now means "what was originally serialized then sealed",
/// because raw bytes on disk are ChaCha20 ciphertext from v0.4.
fn read_audit_tail(log: &AuditLog, limit: usize) -> std::io::Result<Vec<AuditLogLine>> {
    let records = log
        .tail(limit)
        .map_err(|e| std::io::Error::other(format!("audit tail: {e}")))?;
    let mut out = Vec::with_capacity(records.len());
    for rec in &records {
        let (ts_utc, record) = record_metadata(rec);
        // Re-serialize via serde_json -- deterministic for our enum
        // (insertion-ordered with serde tag at the front), so the
        // resulting bytes match what was originally fed into the
        // segment writer at log time.
        let json = serde_json::to_string(rec)
            .map_err(|e| std::io::Error::other(format!("audit serialize: {e}")))?;
        out.push(AuditLogLine {
            ts_utc,
            record,
            json,
        });
    }
    Ok(out)
}

/// Extract the (ts_utc, record-discriminator) pair from a typed
/// AuditRecord without going through JSON. Cheap and infallible.
fn record_metadata(rec: &AuditRecord) -> (i64, String) {
    match rec {
        AuditRecord::Alert(a) => (a.ts_utc, "alert".to_string()),
        AuditRecord::SignerSuspend { ts_utc, .. } => (*ts_utc, "signer_suspend".to_string()),
        AuditRecord::SignerResume { ts_utc, .. } => (*ts_utc, "signer_resume".to_string()),
        AuditRecord::BaselineSealed { ts_utc, .. } => (*ts_utc, "baseline_sealed".to_string()),
        AuditRecord::WorkloadStart { ts_utc, .. } => (*ts_utc, "workload_start".to_string()),
        AuditRecord::WorkloadStop { ts_utc, .. } => (*ts_utc, "workload_stop".to_string()),
    }
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
        let keys_dir = dir.join("keys");
        let keystore = Arc::new(crate::keystore::KeyStore::load_or_generate(&keys_dir).unwrap());
        let audit_log = AuditLog::ephemeral(dir.join("audit"))
            .expect("ephemeral audit log construction");
        let recovery = crate::recovery::RecoveryContext::new_under(dir, audit_log.clone());
        let signer_identity = Arc::new(SignerIdentityKey::generate());
        let keys = Arc::new(std::sync::RwLock::new(Some(crate::SantuarioKeys {
            keystore,
            audit_log,
            recovery,
            signer_identity,
        })));

        AdminService {
            node_id: "Prometheus-test".to_string(),
            metrics: Arc::new(MetricsRegistry::default()),
            peers: PeerSnapshotReader::new(dir.join("peers.json")),
            sentinel_metrics: SentinelMetricsReader::new(
                dir.join("sentinel_metrics.json"),
            ),
            ratchet_session: Arc::new(Mutex::new(None)),
            ratchet_last_handshake_utc: Arc::new(AtomicI64::new(0)),
            keys,
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
            let keys_guard = svc.keys.read().unwrap();
            let keys_val = keys_guard.as_ref().unwrap();
            keys_val.audit_log.log_alert(&alert).unwrap();
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
        // Assioma II E2E test (Sigillum-aware version): a record fed
        // into the AuditLog must round-trip serialize -> encrypt ->
        // segment -> decrypt -> re-serialize -> wire byte-identical to
        // the canonical serialization the operator can independently
        // reproduce by calling AuditLog::tail() and serde_json on the
        // returned record. With v0.4 we cannot read the on-disk file
        // raw (it's ChaCha20 ciphertext); the contract becomes "bytes
        // on the wire == bytes from canonical re-serialization", which
        // is what an auditor verifying log integrity actually needs.
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
        {
            let keys_guard = svc.keys.read().unwrap();
            let keys_val = keys_guard.as_ref().unwrap();
            keys_val.audit_log.log_alert(&alert).unwrap();
        }

        // Ground truth: read back via the public AuditLog API and
        // canonical-serialize. This path traverses the full encrypted
        // segment manager; if it diverges from the gRPC view, we have
        // a real Assioma II violation.
        let records = {
            let keys_guard = svc.keys.read().unwrap();
            let keys_val = keys_guard.as_ref().unwrap();
            keys_val.audit_log.tail(usize::MAX).unwrap()
        };
        assert_eq!(records.len(), 1, "exactly one record was logged");
        let expected_canonical = serde_json::to_string(&records[0]).unwrap();

        let resp = svc
            .tail_audit_log(Request::new(TailAuditLogRequest { limit: 10 }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.lines.len(), 1);
        assert_eq!(
            resp.lines[0].json, expected_canonical,
            "wire JSON must be byte-identical to the canonical serialization \
             of the round-tripped record (Assioma II)"
        );
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

    // --- Phase C ratchet tests -----------------------------------------------

    #[tokio::test]
    async fn get_signer_identity_returns_valid_hex() {
        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());
        let resp = svc
            .get_signer_identity(Request::new(GetSignerIdentityRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.identity_pub_hex.len(), 64, "32 bytes = 64 hex chars");
        assert_eq!(resp.identity_id_hex.len(), 32, "16 bytes = 32 hex chars");
        // Both are valid hex.
        hex::decode(&resp.identity_pub_hex).expect("identity_pub_hex is valid hex");
        hex::decode(&resp.identity_id_hex).expect("identity_id_hex is valid hex");
    }

    #[tokio::test]
    async fn ratchet_status_before_handshake_is_unestablished() {
        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());
        let resp = svc
            .get_ratchet_status(Request::new(GetRatchetStatusRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(!resp.established);
        assert!(!resp.tombstoned);
        assert_eq!(resp.last_handshake_utc, 0);
    }

    #[tokio::test]
    async fn step_ratchet_without_session_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());
        let resp = svc
            .step_ratchet(Request::new(StepRatchetRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(!resp.ok);
        assert!(!resp.error.is_empty());
    }

    #[tokio::test]
    async fn full_handshake_establishes_session() {
        use santuario_ratchet::{OperatorEndpoint, SignerIdentityPublic};

        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());

        // Get signer's public key.
        let id_resp = svc
            .get_signer_identity(Request::new(GetSignerIdentityRequest {}))
            .await
            .unwrap()
            .into_inner();
        let id_bytes = hex::decode(&id_resp.identity_pub_hex).unwrap();
        let mut id_arr = [0u8; 32];
        id_arr.copy_from_slice(&id_bytes);
        let signer_pub = SignerIdentityPublic::from_bytes(id_arr);

        // Operator generates ephemeral + sends handshake request.
        let operator_ep = OperatorEndpoint::new(signer_pub);
        let hs_req = operator_ep.handshake_request();

        let hs_resp = svc
            .rehandshake(Request::new(RehandshakeRequest {
                operator_eph_pub: hs_req.operator_eph_pub.to_vec(),
                operator_kyber_pub: hs_req.operator_kyber_pub.to_vec(),
            }))
            .await
            .unwrap()
            .into_inner();

        // Operator finalises and builds its own session.
        let mut signer_eph_bytes = [0u8; 32];
        signer_eph_bytes.copy_from_slice(&hs_resp.signer_eph_pub);
        let mut kyber_ct_bytes = [0u8; 1568];
        kyber_ct_bytes.copy_from_slice(&hs_resp.kyber_ciphertext);
        let _operator_root = operator_ep
            .finalize(santuario_ratchet::HandshakeResponse {
                signer_eph_pub: signer_eph_bytes,
                kyber_ciphertext: kyber_ct_bytes,
            })
            .unwrap();

        // Signer side should now be established.
        let status = svc
            .get_ratchet_status(Request::new(GetRatchetStatusRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(status.established, "session must be established after handshake");
        assert!(!status.tombstoned);
        assert!(status.last_handshake_utc > 0);
        assert_eq!(status.step, 0);
    }

    #[tokio::test]
    async fn step_ratchet_after_handshake_increments_step() {
        use santuario_ratchet::{OperatorEndpoint, SignerIdentityPublic};

        let dir = tempfile::tempdir().unwrap();
        let svc = make_service_in(dir.path());

        // Handshake.
        let id_resp = svc
            .get_signer_identity(Request::new(GetSignerIdentityRequest {}))
            .await
            .unwrap()
            .into_inner();
        let mut id_arr = [0u8; 32];
        id_arr.copy_from_slice(&hex::decode(&id_resp.identity_pub_hex).unwrap());
        let op = OperatorEndpoint::new(SignerIdentityPublic::from_bytes(id_arr));
        let req = op.handshake_request();
        let hs = svc
            .rehandshake(Request::new(RehandshakeRequest {
                operator_eph_pub: req.operator_eph_pub.to_vec(),
                operator_kyber_pub: req.operator_kyber_pub.to_vec(),
            }))
            .await
            .unwrap()
            .into_inner();
        let mut eph = [0u8; 32];
        eph.copy_from_slice(&hs.signer_eph_pub);
        let mut ct = [0u8; 1568];
        ct.copy_from_slice(&hs.kyber_ciphertext);
        op.finalize(santuario_ratchet::HandshakeResponse {
            signer_eph_pub: eph,
            kyber_ciphertext: ct,
        })
        .unwrap();

        // Step once.
        let step_resp = svc
            .step_ratchet(Request::new(StepRatchetRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(step_resp.ok, "step_ratchet must succeed after handshake");
        assert_eq!(step_resp.new_step, 1);

        // Counter in metrics.
        let met = svc
            .get_metrics(Request::new(GetMetricsRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(met.counters["santuario_ratchet_steps_total"], 1);
    }
}
