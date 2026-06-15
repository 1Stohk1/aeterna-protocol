//! santuario-signer — v0.3.0 "Oculus" gRPC server.
//!
//! Two services share one listener:
//!
//!   * `Signer` (v0.2.0 "Custos") — the write path. Every `Sign`
//!     request runs through a five-gate pipeline before a Dilithium-5
//!     signature is emitted:
//!
//!       1. Vault unsealed?             (vault::Vault::is_sealed == false)
//!       2. Signer state == Ready?      (integrity::SignerState::is_ready)
//!       3. Block parses as AGP-v1?     (critic::parse_block)
//!       4. Producer PID attested?      (isolation::Launcher::attest)
//!       5. Critic accepts block?       (critic::DefaultCritic::check)
//!
//!     If any gate refuses, the signer answers with the corresponding
//!     gRPC status code and does NOT emit a signature. The signer
//!     keeps sliding windows for α, β, γ thresholds and self-suspends
//!     on trip; recovery requires an operator-signed token per
//!     `recovery.rs`.
//!
//!   * `Admin` (v0.3.0 "Oculus") — the read path. `GetMetrics`,
//!     `TailAuditLog`, and `ListPeers` are callable from ANY signer
//!     verdict, including suspended and degraded. Observability must
//!     not depend on the sign path's health. See `admin.rs`.
//!
//! Every Sign outcome is also reflected in the metrics registry so
//! `GetMetrics` and the Prometheus exporter (Phase D) have something
//! real to show.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _};
use tonic::{transport::Server, Request, Response, Status};

// All internals live in the library (src/lib.rs) so integration tests
// in tests/ can construct them directly. The binary just wires them up.
use santuario_signer::santuario::signer::v1::signer_server::{Signer, SignerServer};
use santuario_signer::santuario::signer::v1::{
    GetPublicKeyRequest, GetPublicKeyResponse, GetStatusRequest, GetStatusResponse, ResumeRequest,
    ResumeResponse, SignRequest, SignResponse, TriggerAuditRequest, TriggerAuditResponse,
    VerifyRequest, VerifyResponse, ExecuteTaskRequest, ExecuteTaskResponse,
};

use santuario_signer::admin::{self, AdminService};
use santuario_signer::attestation::{AttestationError, AttestationGate};
use santuario_signer::keystore::KeyStore;
use santuario_signer::metrics::MetricsRegistry;
use santuario_signer::peers::PeerSnapshotReader;
use santuario_signer::recovery::{self, RecoveryContext};
use santuario_signer::sentinel_metrics::SentinelMetricsReader;

use santuario_cipher::MasterLogKey;
use santuario_ratchet::SignerIdentityKey;
use santuario_critic::{parse_block, Critic, DefaultCritic, Violation};
use santuario_integrity::{AuditLog, IntegrityAuditor, IntegrityConfig, SignerState};
use santuario_isolation::{Launcher, PolicyKind, LaunchSpec};

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
    /// v0.3.0 — every sign path increments counters and observes
    /// latency here so the Admin service's `GetMetrics` has something
    /// real to show.
    metrics: Arc<MetricsRegistry>,
    launcher: Arc<dyn Launcher + Send + Sync>,
    repo: PathBuf,
}

impl SantuarioSigner {
    fn is_vault_sealed(&self) -> bool {
        self.vault_sealed.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[tonic::async_trait]
impl Signer for SantuarioSigner {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let start = std::time::Instant::now();
        self.metrics.incr("santuario_sign_total");
        let res = self.sign_inner(request).await;
        self.metrics
            .observe_duration("santuario_sign_latency_seconds", start.elapsed());
        match &res {
            Ok(_) => self.metrics.incr("santuario_sign_accept_total"),
            Err(s) => {
                let bucket = classify_reject(s);
                self.metrics
                    .incr(&format!("santuario_sign_reject_{bucket}_total"));
            }
        }
        res
    }

    async fn verify(
        &self,
        request: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        self.verify_inner(request).await
    }

    async fn get_public_key(
        &self,
        request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        self.get_public_key_inner(request).await
    }

    async fn get_status(
        &self,
        request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        self.get_status_inner(request).await
    }

    async fn trigger_audit(
        &self,
        request: Request<TriggerAuditRequest>,
    ) -> Result<Response<TriggerAuditResponse>, Status> {
        self.trigger_audit_inner(request).await
    }

    async fn resume(
        &self,
        request: Request<ResumeRequest>,
    ) -> Result<Response<ResumeResponse>, Status> {
        self.resume_inner(request).await
    }

    async fn execute_task(
        &self,
        request: Request<ExecuteTaskRequest>,
    ) -> Result<Response<ExecuteTaskResponse>, Status> {
        self.execute_task_inner(request).await
    }
}

impl SantuarioSigner {
    async fn sign_inner(
        &self,
        request: Request<SignRequest>,
    ) -> Result<Response<SignResponse>, Status> {
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
        let (payload_hash, _producer_policy, producer_pid) = if !req.agp_block_json.is_empty() {
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

        // Terminate the container if producer_pid is provided and clean up the spool files
        if let Some(pid) = producer_pid {
            log::info!("Terminating sandbox container process with PID: {}", pid);
            #[cfg(unix)]
            {
                let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
            }
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(&["/F", "/PID", &pid.to_string()])
                    .spawn();
            }
            self.audit_log.append(&santuario_integrity::AuditRecord::WorkloadStop {
                ts_utc: santuario_integrity::now_utc(),
                pid,
                status: "killed".to_string(),
            }).ok();
            if !req.agp_block_json.is_empty() {
                if let Ok(block) = parse_block(std::str::from_utf8(&req.agp_block_json).unwrap_or("")) {
                    let outbound_file = self.repo.join("santuario/vault/outbound").join(format!("{}.json", block.payload.id_task));
                    let _ = std::fs::remove_file(&outbound_file);
                }
            }
        }

        Ok(Response::new(SignResponse {
            signature,
            payload_hash,
        }))
    }

    async fn verify_inner(
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

    async fn get_public_key_inner(
        &self,
        _request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        Ok(Response::new(GetPublicKeyResponse {
            public_key: self.keystore.public_key.as_bytes().to_vec(),
        }))
    }

    async fn get_status_inner(
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
            } => (
                "suspended".to_string(),
                kind.name().to_string(),
                reason,
                ts_utc,
            ),
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

    async fn trigger_audit_inner(
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

    async fn resume_inner(
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

    async fn execute_task_inner(
        &self,
        request: Request<ExecuteTaskRequest>,
    ) -> Result<Response<ExecuteTaskResponse>, Status> {
        let req = request.into_inner();

        // Gate 1: vault must be unsealed.
        if self.is_vault_sealed() {
            return Err(Status::failed_precondition(
                "vault sealed — call vaultctl unseal before executing tasks",
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

        // Parse id_task to make the spool file name unique but predictable
        let task_val: serde_json::Value = serde_json::from_str(&req.task_json)
            .map_err(|e| Status::invalid_argument(format!("invalid task_json: {}", e)))?;
        let id_task = task_val["id_task"].as_str()
            .ok_or_else(|| Status::invalid_argument("missing id_task in task_json"))?;

        // 1. Resolve paths for inbound and outbound spools
        let inbound_dir = self.repo.join("santuario/vault/inbound");
        let outbound_dir = self.repo.join("santuario/vault/outbound");

        let inbound_file = inbound_dir.join(format!("{}.json", id_task));
        let outbound_file = outbound_dir.join(format!("{}.json", id_task));

        // Ensure directories exist
        if let Err(e) = std::fs::create_dir_all(&inbound_dir) {
            return Ok(Response::new(ExecuteTaskResponse {
                result_json: String::new(),
                producer_pid: 0,
                error: format!("Failed to create inbound spool dir: {}", e),
            }));
        }
        if let Err(e) = std::fs::create_dir_all(&outbound_dir) {
            return Ok(Response::new(ExecuteTaskResponse {
                result_json: String::new(),
                producer_pid: 0,
                error: format!("Failed to create outbound spool dir: {}", e),
            }));
        }

        // Write the task json to the inbound spool
        if let Err(e) = std::fs::write(&inbound_file, &req.task_json) {
            return Ok(Response::new(ExecuteTaskResponse {
                result_json: String::new(),
                producer_pid: 0,
                error: format!("Failed to write inbound spool file: {}", e),
            }));
        }

        // 2. Setup LaunchSpec for Julia running task_run.jl
        let julia_bin = find_executable("julia").unwrap_or_else(|| PathBuf::from("julia"));
        let spec = LaunchSpec::new(julia_bin, PolicyKind::Julia)
            .with_arg("scientific/task_run.jl")
            .with_arg(inbound_file.to_string_lossy().to_string())
            .with_arg(outbound_file.to_string_lossy().to_string());

        log::info!("Executing task in sandbox: {:?}", spec);

        // 3. Launch using isolation launcher
        let mut child_handle = None;
        let pid = match self.launcher.launch(&spec) {
            Ok(c) => c.attestation.pid,
            Err(e) => {
                if self.launcher.is_enforcing() {
                    let _ = std::fs::remove_file(&inbound_file);
                    return Err(Status::internal(format!("Failed to launch task container under isolation: {}", e)));
                } else {
                    log::warn!("Workload isolation launcher failed on non-enforcing platform: {}. Falling back to host-space execution.", e);
                    let mut cmd = std::process::Command::new(&spec.program);
                    cmd.args(&spec.args);
                    if let Some(workdir) = &spec.workdir {
                        cmd.current_dir(workdir);
                    }
                    for (k, v) in &spec.env {
                        cmd.env(k, v);
                    }
                    match cmd.spawn() {
                        Ok(c) => {
                            let spawned_pid = c.id() as i32;
                            child_handle = Some(c);
                            spawned_pid
                        }
                        Err(spawn_err) => {
                            let _ = std::fs::remove_file(&inbound_file);
                            return Ok(Response::new(ExecuteTaskResponse {
                                result_json: String::new(),
                                producer_pid: 0,
                                error: format!("Host-space fallback spawn failed: {}", spawn_err),
                            }));
                        }
                    }
                }
            }
        };

        log::info!("Sandbox/Host process running with PID: {}", pid);

        self.audit_log.append(&santuario_integrity::AuditRecord::WorkloadStart {
            ts_utc: santuario_integrity::now_utc(),
            pid,
            policy: spec.policy.name().to_string(),
        }).ok();

        // 4. Poll for the output file to be written. Wait up to 30 seconds.
        let mut attempts = 0;
        let mut result_json = String::new();
        let mut err_msg = String::new();

        loop {
            if attempts >= 60 {
                err_msg = "Timeout waiting for task execution".to_string();
                break;
            }
            if outbound_file.exists() {
                match std::fs::read_to_string(&outbound_file) {
                    Ok(s) => {
                        result_json = s;
                        break;
                    }
                    Err(_e) => {
                        // Might be mid-write, wait a tiny bit
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        attempts += 1;
                        continue;
                    }
                }
            }
            if let Some(ref mut child) = child_handle {
                if let Ok(Some(exit_status)) = child.try_wait() {
                    if !outbound_file.exists() {
                        err_msg = format!("Host process exited unexpectedly with status: {}", exit_status);
                        break;
                    }
                }
            } else {
                // Check if process has died prematurely (only on unix/linux where /proc exists)
                #[cfg(unix)]
                {
                    if !Path::new(&format!("/proc/{}", pid)).exists() {
                        err_msg = "Sandbox container exited unexpectedly".to_string();
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            attempts += 1;
        }

        // Clean up input spool file
        let _ = std::fs::remove_file(&inbound_file);

        if !err_msg.is_empty() {
            // Kill the container or process if it's still running
            #[cfg(unix)]
            {
                let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
            }
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(&["/F", "/PID", &pid.to_string()])
                    .spawn();
            }
            self.audit_log.append(&santuario_integrity::AuditRecord::WorkloadStop {
                ts_utc: santuario_integrity::now_utc(),
                pid,
                status: format!("error: {}", err_msg),
            }).ok();
            let _ = std::fs::remove_file(&outbound_file);
            return Ok(Response::new(ExecuteTaskResponse {
                result_json: String::new(),
                producer_pid: 0,
                error: err_msg,
            }));
        }

        Ok(Response::new(ExecuteTaskResponse {
            result_json,
            producer_pid: pid,
            error: String::new(),
        }))
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
        AttestationError::Required => {
            Status::permission_denied("producer_pid required in strict attestation mode")
        }
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

/// Map a rejected-sign `Status` into the counter bucket name suffix
/// expected by the Admin metrics schema. Kept in sync with the error
/// table in signer.proto §Errors and with the SPRINT-v0.3.0 metrics
/// contract (Phase A, §7.2).
fn classify_reject(s: &Status) -> &'static str {
    use tonic::Code;
    let msg = s.message();
    match s.code() {
        Code::FailedPrecondition => {
            if msg.contains("vault sealed") {
                "vault_sealed"
            } else {
                "suspended"
            }
        }
        Code::InvalidArgument => "malformed",
        Code::PermissionDenied => "attestation",
        Code::Aborted => {
            if msg.contains("reflexive") {
                "reflexive"
            } else if msg.contains("symbolic") {
                "symbolic"
            } else if msg.contains("axiomatic") {
                "axiomatic"
            } else {
                "aborted_other"
            }
        }
        _ => "other",
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



fn find_executable(name: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let exe_path = dir.join(name);
            #[cfg(windows)]
            let exe_path = if exe_path.extension().is_none() {
                exe_path.with_extension("exe")
            } else {
                exe_path
            };
            if exe_path.exists() {
                return Some(exe_path);
            }
        }
    }
    None
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
    // v0.4 "Sigillum": provision the audit-log master key. First boot
    // generates a fresh 32-byte random key under <repo>/santuario/vault/
    // and persists it (chmod 0o600 on Unix). Subsequent boots load the
    // same key. Phase C will replace this random-on-first-boot path
    // with BIP-39 seed derivation; the file location stays stable.
    let log_master_key_path = repo.join("santuario/vault/log_master.key");
    let log_master = MasterLogKey::load_or_generate(&log_master_key_path)
        .map_err(|e| anyhow::anyhow!("provision audit master key at {}: {e}",
                                     log_master_key_path.display()))?;
    log::info!(
        "audit log master key id: {} ({})",
        log_master.id().to_hex(),
        log_master_key_path.display()
    );
    let audit_log = AuditLog::default_for_repo(&repo, log_master)
        .map_err(|e| anyhow::anyhow!("open encrypted audit log: {e}"))?;
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

    // --- v0.3.0 "Oculus" observability --------------------------------------
    // One shared metrics registry feeds the Admin `GetMetrics` RPC and is
    // incremented on every Sign outcome.
    let metrics = Arc::new(MetricsRegistry::default());

    // Gauge housekeeper — refreshes `santuario_*_state` gauges every 5s.
    // v0.4 Sigillum: also mirrors the AuditLog's internal monotonic counters
    // into the registry so `santuario_log_segments_total` and
    // `santuario_log_bytes_encrypted_total` are visible to the Admin RPC
    // and the Prometheus exporter (sprint v0.4 AC #8).
    {
        let metrics = metrics.clone();
        let state = state.clone();
        let vault_sealed = vault_sealed.clone();
        let audit_log = audit_log.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(5));
            loop {
                ticker.tick().await;
                let sealed = if vault_sealed.load(std::sync::atomic::Ordering::Relaxed) {
                    1.0
                } else {
                    0.0
                };
                let ready = if state.is_ready() { 1.0 } else { 0.0 };
                metrics.set_gauge("santuario_vault_sealed", sealed);
                metrics.set_gauge("santuario_signer_ready", ready);

                // Sigillum AC #8 — mirror atomic counters from AuditLog.
                metrics.set_counter(
                    "santuario_log_segments_total",
                    audit_log.segments_opened_total(),
                );
                metrics.set_counter(
                    "santuario_log_bytes_encrypted_total",
                    audit_log.bytes_encrypted_total(),
                );

                // Phase F: SPRINT-v0.5.0 criterion #8 metrics
                if let Ok(entries) = std::fs::read_dir(&audit_log.dir) {
                    let pushed_count = entries
                        .filter_map(|e| e.ok())
                        .filter(|e| e.path().extension().and_then(|s| s.to_str()).is_some_and(|ext| ext == "pushed"))
                        .count();
                    metrics.set_counter("santuario_shipper_segments_pushed_total", pushed_count as u64);
                }

                // Query Cosmos block height
                let mut height = 0.0;
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(1))
                    .build();
                if let Ok(client) = client {
                    if let Ok(resp) = client.get("http://127.0.0.1:1317/status").send().await {
                        if let Ok(json) = resp.json::<serde_json::Value>().await {
                            if let Some(height_str) = json["result"]["sync_info"]["latest_block_height"].as_str() {
                                if let Ok(h) = height_str.parse::<f64>() {
                                    height = h;
                                }
                            }
                        }
                    }
                }
                metrics.set_gauge("santuario_chain_block_height", height);
            }
        });
    }

    // --- remote log shipper companion thread (Phase F) --------------------
    let mut shipper_cfg = match std::fs::read_to_string(repo.join("aeterna.toml")) {
        Ok(text) => santuario_shipper::config::ShipperConfig::from_aeterna_toml(&text).unwrap_or_default(),
        Err(_) => santuario_shipper::config::ShipperConfig::default(),
    };
    if let Ok(endpoint_url) = std::env::var("AETERNA_SHIPPER_ENDPOINT") {
        if !endpoint_url.trim().is_empty() {
            shipper_cfg.endpoint_url = endpoint_url;
            shipper_cfg.enabled = true;
        }
    }
    if shipper_cfg.enabled {
        let audit_dir = audit_log.dir.clone();
        log::info!("Spawning remote log shipper companion thread (directory: {})...", audit_dir.display());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let shipper = santuario_shipper::state::Shipper::new(shipper_cfg, audit_dir);
        tokio::spawn(async move {
            let _keep_alive = shutdown_tx;
            if let Err(e) = shipper.run(shutdown_rx).await {
                log::error!("Shipper companion thread error: {:?}", e);
            }
        });
    }

    let signer_service = SantuarioSigner {
        keystore,
        state,
        critic: DefaultCritic::new(),
        gate,
        auditor,
        audit_log: audit_log.clone(),
        recovery: recovery_ctx,
        vault_sealed,
        metrics: metrics.clone(),
        launcher: launcher.clone(),
        repo: repo.clone(),
    };

    // v0.4 Phase C: signer's long-term X25519 identity for the
    // operator-endpoint ratchet. Loaded from vault; generated on first boot.
    let signer_identity_path = repo.join("santuario/vault/signer_identity.x25519");
    let signer_identity = Arc::new(
        SignerIdentityKey::load_or_generate(&signer_identity_path)
            .map_err(|e| anyhow::anyhow!("provision signer identity key at {}: {e}",
                                         signer_identity_path.display()))?,
    );
    log::info!(
        "ratchet signer identity id: {} ({})",
        signer_identity.id_hex(),
        signer_identity_path.display()
    );

    // Admin service — same listener as Signer; see SPRINT-v0.3.0 §7.1.
    let admin_service = AdminService {
        node_id: node_id.clone(),
        metrics: metrics.clone(),
        audit_log: audit_log.clone(),
        peers: PeerSnapshotReader::default_for_repo(&repo),
        sentinel_metrics: SentinelMetricsReader::default_for_repo(&repo),
        signer_identity,
        ratchet_session: Arc::new(std::sync::Mutex::new(None)),
        ratchet_last_handshake_utc: Arc::new(
            std::sync::atomic::AtomicI64::new(0),
        ),
    };

    let server = Server::builder()
        .add_service(SignerServer::new(signer_service))
        .add_service(admin::server(admin_service));

    #[cfg(unix)]
    {
        if let Ok(port) = std::env::var("SANTUARIO_PORT") {
            let addr_str = format!("127.0.0.1:{}", port);
            let addr = addr_str.parse()?;
            log::info!(
                "Santuario Signer v0.3.0 (Signer+Admin) starting on TCP {}",
                addr
            );
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

        log::info!(
            "Santuario Signer v0.3.0 (Signer+Admin) starting on UDS {}",
            socket_path.display()
        );
        server.serve_with_incoming(uds_stream).await?;
    }

    #[cfg(not(unix))]
    {
        let port = std::env::var("SANTUARIO_PORT").unwrap_or_else(|_| "50051".to_string());
        let addr_str = format!("127.0.0.1:{}", port);
        let addr = addr_str.parse()?;
        log::info!(
            "Santuario Signer v0.3.0 (Signer+Admin) starting on TCP {}",
            addr
        );
        server.serve(addr).await?;
    }

    Ok(())
}
