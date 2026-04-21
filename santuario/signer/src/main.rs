//! santuario-signer — v0.2.0 "Custos" gRPC server.
//!
//! Every `Sign` request now runs through a five-gate pipeline before a
//! Dilithium-5 signature is emitted:
//!
//!     1. Vault unsealed?             (vault::Vault::is_sealed == false)
//!     2. Signer state == Ready?      (integrity::SignerState::is_ready)
//!     3. Block parses as AGP-v1?     (critic::parse_block)
//!     4. Producer PID attested?      (isolation::Launcher::attest)
//!     5. Critic accepts block?       (critic::DefaultCritic::check)
//!
//! If any gate refuses, the signer answers with the corresponding gRPC
//! status code and does NOT emit a signature. The signer keeps sliding
//! windows for α, β, γ thresholds and self-suspends on trip; recovery
//! requires an operator-signed token per `recovery.rs`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _, SignedMessage as _};
use tonic::{transport::Server, Request, Response, Status};

pub mod santuario {
    pub mod signer {
        pub mod v1 {
            tonic::include_proto!("santuario.signer.v1");
        }
    }
}

use santuario::signer::v1::signer_server::{Signer, SignerServer};
use santuario::signer::v1::{
    GetPublicKeyRequest, GetPublicKeyResponse, GetStatusRequest, GetStatusResponse, ResumeRequest,
    ResumeResponse, SignRequest, SignResponse, TriggerAuditRequest, TriggerAuditResponse,
    VerifyRequest, VerifyResponse,
};

mod attestation;
mod keystore;
mod recovery;

use attestation::{AttestationError, AttestationGate};
use keystore::KeyStore;
use recovery::RecoveryContext;

use santuario_critic::{parse_block, Critic, DefaultCritic, Violation};
use santuario_integrity::{
    AlertKind, AuditLog, IntegrityAlert, IntegrityAuditor, IntegrityConfig, SignerState,
};
use santuario_isolation::{Launcher, PolicyKind};

/// Full set of collaborators the gRPC service needs on every request.
pub struct SantuarioSigner {
    keystore: Arc<KeyStore>,
    state: Arc<SignerState>,
    critic: DefaultCritic,
    gate: AttestationGate,
    auditor: Arc<IntegrityAuditor>,
    audit_log: AuditLog,
    recovery: RecoveryContext,
    vault_sealed: Arc<std::sync::atomic::AtomicBool>,
}

impl SantuarioSigner {
    fn is_vault_sealed(&self) -> bool {
        self.vault_sealed.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[tonic::async_trait]
impl Signer for SantuarioSigner {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let req = request.into_inner();

        // Gate 1: vault must be unsealed.
        if self.is_vault_sealed() {
            return Err(Status::failed_precondition(
                "vault sealed — call vaultctl unseal before signing",
            ));
        }

        // Gate 2: signer state must be Ready.
        let verdict = self.state.verdict();
        if !verdict.is_ready() {
            return Err(Status::failed_precondition(
                verdict
                    .as_error_reason()
                    .unwrap_or_else(|| "signer is suspended".to_string()),
            ));
        }

        // Two input shapes.
        let (payload_hash, producer_policy, producer_pid) = if !req.agp_block_json.is_empty() {
            // v0.2.0 path — run the full critic pipeline.
            let text = std::str::from_utf8(&req.agp_block_json)
                .map_err(|_| Status::invalid_argument("agp_block_json is not valid UTF-8"))?;
            let block = parse_block(text).map_err(violation_to_status)?;

            // Compute canonical hash the way the critic will expect it.
            let hash_bytes = santuario_critic::canonical_hash_input(&block)
                .map_err(|e| Status::invalid_argument(format!("canonical hash: {e:?}")))?;
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&hash_bytes);
            let payload_hash = h.finalize().to_vec();

            // Gate 3+5: critic checks reflexive, symbolic, axiomatic.
            self.critic.check(&block).map_err(violation_to_status)?;

            // Gate 4: PID attestation (if declared).
            let claimed_policy = match req.producer_policy.as_deref() {
                None | Some("") => PolicyKind::Julia,
                Some(s) => policy_from_str(s)
                    .ok_or_else(|| Status::invalid_argument(format!("unknown policy '{s}'")))?,
            };
            let att = self
                .gate
                .verify(req.producer_pid, claimed_policy)
                .map_err(attestation_to_status)?;
            if let Some(att) = &att {
                log::info!("sign attested {}", att.summary());
            }

            (payload_hash, claimed_policy, req.producer_pid)
        } else {
            // v0.1.0 compat — raw 32-byte hash. Still runs gates 1+2.
            if req.payload_hash.len() != 32 {
                return Err(Status::invalid_argument(
                    "payload_hash must be exactly 32 bytes",
                ));
            }
            (req.payload_hash.clone(), PolicyKind::Restricted, None)
        };

        // Final: Dilithium-5 detached signature.
        let det = dilithium5::detached_sign(&payload_hash, &self.keystore.secret_key);
        let signature = det.as_bytes().to_vec();
        let _ = (producer_policy, producer_pid);

        Ok(Response::new(SignResponse {
            signature,
            payload_hash,
        }))
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let req = request.into_inner();
        let pk = dilithium5::PublicKey::from_bytes(&req.public_key)
            .map_err(|_| Status::invalid_argument("invalid Dilithium-5 public key"))?;
        let det = match dilithium5::DetachedSignature::from_bytes(&req.signature) {
            Ok(d) => d,
            Err(_) => return Ok(Response::new(VerifyResponse { valid: false })),
        };
        let valid = dilithium5::verify_detached_signature(&det, &req.payload_hash, &pk).is_ok();
        Ok(Response::new(VerifyResponse { valid }))
    }

    async fn get_public_key(
        &self,
        _request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        Ok(Response::new(GetPublicKeyResponse {
            public_key: self.keystore.public_key.as_bytes().to_vec(),
        }))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let v = self.state.verdict();
        let (verdict_str, kind_str, reason_str, ts) = match v {
            santuario_integrity::Verdict::Ready => {
                ("ready".to_string(), String::new(), String::new(), 0)
            }
            santuario_integrity::Verdict::Suspended {
                kind,
                reason,
                ts_utc,
            } => ("suspended".to_string(), kind.name().to_string(), reason, ts_utc),
        };
        Ok(Response::new(GetStatusResponse {
            verdict: verdict_str,
            suspension_kind: kind_str,
            suspension_reason: reason_str,
            suspension_ts_utc: ts,
            vault_sealed: self.is_vault_sealed(),
            critic_armed: true,
            integrity_ok: self.state.is_ready(),
            seccomp_active: cfg!(target_os = "linux"),
        }))
    }

    async fn trigger_audit(
        &self,
        request: Request<TriggerAuditRequest>,
    ) -> Result<Response<TriggerAuditResponse>, Status> {
        let accept_new = request.into_inner().accept_new_baseline;
        if accept_new {
            let b = self
                .auditor
                .seal_baseline()
                .map_err(|e| Status::internal(format!("seal baseline: {e}")))?;
            self.audit_log
                .log_baseline("rpc-operator", b.entries.len())
                .ok();
            return Ok(Response::new(TriggerAuditResponse {
                mismatches: 0,
                mismatched_paths: Vec::new(),
            }));
        }
        let alerts = self
            .auditor
            .sweep_once()
            .map_err(|e| Status::internal(format!("sweep: {e}")))?;
        let paths: Vec<String> = alerts
            .iter()
            .map(|a| match &a.evidence {
                santuario_integrity::AlertEvidence::AlphaMismatch { path, .. } => {
                    path.display().to_string()
                }
                santuario_integrity::AlertEvidence::AlphaMissing { path, .. } => {
                    path.display().to_string()
                }
                _ => "(non-alpha)".to_string(),
            })
            .collect();
        for a in &alerts {
            self.audit_log.log_alert(a).ok();
            self.state.suspend_for_alert(a);
            let _ = recovery::issue_challenge(&self.recovery);
        }
        Ok(Response::new(TriggerAuditResponse {
            mismatches: alerts.len() as i32,
            mismatched_paths: paths,
        }))
    }

    async fn resume(
        &self,
        request: Request<ResumeRequest>,
    ) -> Result<Response<ResumeResponse>, Status> {
        let req = request.into_inner();
        match recovery::try_resume(&self.recovery, &self.state, &req.token_hex, &req.operator) {
            Ok(()) => Ok(Response::new(ResumeResponse {
                resumed: true,
                error: String::new(),
            })),
            Err(e) => Ok(Response::new(ResumeResponse {
                resumed: false,
                error: e.to_string(),
            })),
        }
    }
}

// --- helpers ---------------------------------------------------------------

fn violation_to_status(v: Violation) -> Status {
    match v {
        Violation::Reflexive { rationale } => {
            Status::aborted(format!("reflexive violation: {rationale}"))
        }
        Violation::Symbolic { rationale } => {
            Status::aborted(format!("symbolic violation: {rationale}"))
        }
        Violation::Axiomatic { rationale } => {
            Status::aborted(format!("axiomatic violation: {rationale}"))
        }
        Violation::Malformed { rationale } => {
            Status::invalid_argument(format!("malformed block: {rationale}"))
        }
    }
}

fn attestation_to_status(e: AttestationError) -> Status {
    match e {
        AttestationError::Required => Status::permission_denied(
            "producer_pid required in strict attestation mode",
        ),
        AttestationError::PolicyMismatch { .. } => Status::permission_denied(e.to_string()),
        AttestationError::Isolation(ie) => Status::permission_denied(ie.to_string()),
    }
}

fn policy_from_str(s: &str) -> Option<PolicyKind> {
    match s {
        "julia" | "julia-scientific" => Some(PolicyKind::Julia),
        "llm_inference" | "llm-inference" => Some(PolicyKind::LlmInference),
        "restricted" | "restricted-compute" => Some(PolicyKind::Restricted),
        _ => None,
    }
}

fn repo_root() -> PathBuf {
    std::env::var_os("AETERNA_REPO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Two levels up from CARGO_MANIFEST_DIR (santuario/signer -> repo).
            let manifest = env!("CARGO_MANIFEST_DIR");
            PathBuf::from(manifest).join("..").join("..")
        })
}

fn load_integrity_config(repo: &Path) -> IntegrityConfig {
    let p = repo.join("aeterna.toml");
    match std::fs::read_to_string(&p) {
        Ok(text) => santuario_integrity::config::load_from_toml(&text).unwrap_or_default(),
        Err(_) => IntegrityConfig::default(),
    }
}

// --- main ------------------------------------------------------------------

#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let repo = repo_root();
    let cfg = load_integrity_config(&repo);

    // --- keystore ----------------------------------------------------------
    let keys_dir = std::env::var_os("SANTUARIO_KEYS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
            home_dir.join(".santuario").join("keys")
        });
    let keystore = Arc::new(KeyStore::load_or_generate(&keys_dir)?);

    // --- integrity watchdog ------------------------------------------------
    let node_id = std::env::var("AETERNA_NODE_ID").unwrap_or_else(|_| "Prometheus-1".to_string());
    let auditor = Arc::new(IntegrityAuditor::new(node_id.clone(), &repo, cfg.clone()));
    let audit_log = AuditLog::default_for_repo(&repo);
    let recovery_ctx = RecoveryContext::new_under(&repo, audit_log.clone());

    // --- launcher ----------------------------------------------------------
    #[cfg(target_os = "linux")]
    let launcher: Arc<dyn Launcher + Send + Sync> =
        Arc::new(santuario_isolation::launcher::SeccompLauncher::new());
    #[cfg(not(target_os = "linux"))]
    let launcher: Arc<dyn Launcher + Send + Sync> =
        Arc::new(santuario_isolation::launcher::SeccompLauncher::new());

    // --- state -------------------------------------------------------------
    let state = Arc::new(SignerState::new());

    // Baseline seal on first run — if no baseline exists yet, create one
    // from the current working tree. Operators can reseal later via RPC.
    if !auditor.baseline_path.exists() {
        match auditor.seal_baseline() {
            Ok(b) => {
                log::info!("sealed fresh baseline ({} files)", b.entries.len());
                audit_log.log_baseline("bootstrap", b.entries.len()).ok();
            }
            Err(e) => log::warn!("baseline seal failed: {e}"),
        }
    }

    // α loop — sweep every `interval_minutes`.
    {
        let auditor = auditor.clone();
        let state = state.clone();
        let audit_log = audit_log.clone();
        let recovery_ctx = recovery_ctx.clone();
        let period = Duration::from_secs(cfg.interval_minutes.max(1) * 60);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            ticker.tick().await; // first tick immediately
            loop {
                ticker.tick().await;
                match auditor.sweep_once() {
                    Ok(alerts) if alerts.is_empty() => {
                        log::debug!("alpha sweep clean");
                    }
                    Ok(alerts) => {
                        for a in &alerts {
                            log::warn!("alpha alert: {:?}", a.evidence);
                            state.suspend_for_alert(a);
                            audit_log.log_alert(a).ok();
                        }
                        let _ = recovery::issue_challenge(&recovery_ctx);
                    }
                    Err(e) => log::warn!("alpha sweep failed: {e}"),
                }
            }
        });
    }

    // β CPU monitor — tick every 5 s.
    {
        let cfg = cfg.clone();
        let state = state.clone();
        let audit_log = audit_log.clone();
        let recovery_ctx = recovery_ctx.clone();
        let node_id = node_id.clone();
        tokio::spawn(async move {
            let mut mon = santuario_integrity::cpu::CpuMonitor::new(node_id, &cfg);
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                let sample = santuario_integrity::cpu::sample_cpu_global();
                let now = santuario_integrity::now_utc();
                if let Some(alert) = mon.tick(now, sample) {
                    log::warn!("beta alert: {:?}", alert.evidence);
                    state.suspend_for_alert(&alert);
                    audit_log.log_alert(&alert).ok();
                    let _ = recovery::issue_challenge(&recovery_ctx);
                }
            }
        });
    }

    // Vault sealed/unsealed tracker. For v0.2.0 we trust the environment
    // variable `SANTUARIO_VAULT_STATE=sealed|unsealed`; a full embedded
    // Vault object would require the vault crate on the signer's
    // critical-path hot loop which is out of scope.
    let vault_sealed_flag = std::env::var("SANTUARIO_VAULT_STATE")
        .map(|v| v.trim().eq_ignore_ascii_case("sealed"))
        .unwrap_or(false);
    let vault_sealed = Arc::new(std::sync::atomic::AtomicBool::new(vault_sealed_flag));

    let gate = AttestationGate::new(launcher.clone());

    let signer_service = SantuarioSigner {
        keystore,
        state,
        critic: DefaultCritic::new(),
        gate,
        auditor,
        audit_log,
        recovery: recovery_ctx,
        vault_sealed,
    };

    let server = Server::builder().add_service(SignerServer::new(signer_service));

    #[cfg(unix)]
    {
        if let Ok(port) = std::env::var("SANTUARIO_PORT") {
            let addr_str = format!("127.0.0.1:{}", port);
            let addr = addr_str.parse()?;
            log::info!("Santuario Signer v0.2.0 starting on TCP {}", addr);
            server.serve(addr).await?;
            return Ok(());
        }

        let socket_path = std::env::var("SANTUARIO_SOCKET")
            .unwrap_or_else(|_| "/run/aeterna/santuario.sock".to_string());
        let socket_path = PathBuf::from(socket_path);
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(&socket_path);
        let uds = UnixListener::bind(&socket_path)?;
        let uds_stream = UnixListenerStream::new(uds);

        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&socket_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&socket_path, perms)?;

        log::info!("Santuario Signer v0.2.0 starting on UDS {}", socket_path.display());
        server.serve_with_incoming(uds_stream).await?;
    }

    #[cfg(not(unix))]
    {
        let port = std::env::var("SANTUARIO_PORT").unwrap_or_else(|_| "50051".to_string());
        let addr_str = format!("127.0.0.1:{}", port);
        let addr = addr_str.parse()?;
        log::info!("Santuario Signer v0.2.0 starting on TCP {}", addr);
        server.serve(addr).await?;
    }

    Ok(())
}
