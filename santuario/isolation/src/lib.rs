//! Process isolation layer for the Santuario.
//!
//! The Santuario enforces that **every** subprocess whose output will be
//! signed was launched under a strict `seccomp-bpf` syscall allowlist, and
//! it refuses to sign a result whose producer PID is not attested against
//! the active policy. This crate provides:
//!
//! 1. A [`Launcher`] trait with a Linux seccomp-bpf implementation and a
//!    stub for non-Linux targets that refuses to start any workload (the
//!    node degrades to `osservatore` trust tier).
//! 2. A [`PolicyKind`] catalogue enumerating the syscall allowlists
//!    shipped as text files under `santuario/isolation/policies/`.
//! 3. A [`Attestation`] record — the signed-in-memory promise the
//!    launcher gives the signer about a PID's provenance.
//!
//! See `docs/sprint-v0.2.0.md §3 Phase B` for the acceptance contract.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod policy;

#[cfg(target_os = "linux")]
pub mod launcher;

#[cfg(not(target_os = "linux"))]
pub mod launcher_stub;

#[cfg(not(target_os = "linux"))]
pub use launcher_stub as launcher;

/// Categorical kinds of workload the Santuario launches. Each maps to a
/// fixed-shape seccomp-bpf policy loaded from `policies/*.bpf` (text
/// allowlists, one syscall per line).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    /// The Julia scientific engine (`scientific/zmq_server.jl`). Needs
    /// read/write to ZMQ socket, mmap/munmap for GC, clock_gettime, and
    /// a narrow set of filesystem ops.
    Julia,
    /// Any in-process LLM inference child. Allowlist is tighter than
    /// Julia: no `execve`, no `socket`, no `connect` — the model runs
    /// fully local with stdio only.
    LlmInference,
    /// Minimal "compute-only" profile. Suitable for small deterministic
    /// subprograms that must not touch the network or the filesystem.
    Restricted,
}

impl PolicyKind {
    /// Canonical lowercase name — used as the stem of the policy file
    /// under `santuario/isolation/policies/`.
    pub fn name(self) -> &'static str {
        match self {
            PolicyKind::Julia => "julia",
            PolicyKind::LlmInference => "llm_inference",
            PolicyKind::Restricted => "restricted",
        }
    }

    /// Short human-readable label for audit logs.
    pub fn label(self) -> &'static str {
        match self {
            PolicyKind::Julia => "julia-scientific",
            PolicyKind::LlmInference => "llm-inference",
            PolicyKind::Restricted => "restricted-compute",
        }
    }
}

/// Specification handed to [`Launcher::launch`].
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    /// Absolute path to the executable. Must exist and be readable.
    pub program: PathBuf,
    /// Command-line arguments, not including argv[0] (the launcher sets
    /// that to `program`).
    pub args: Vec<String>,
    /// Environment variables to export to the child. The launcher does
    /// NOT inherit the parent's environment.
    pub env: Vec<(String, String)>,
    /// Which seccomp profile to install before `execve`.
    pub policy: PolicyKind,
    /// Optional working directory for the child. `None` = inherit.
    pub workdir: Option<PathBuf>,
}

impl LaunchSpec {
    pub fn new(program: impl Into<PathBuf>, policy: PolicyKind) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            policy,
            workdir: None,
        }
    }

    pub fn with_arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn with_env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.push((k.into(), v.into()));
        self
    }

    pub fn with_workdir(mut self, p: impl Into<PathBuf>) -> Self {
        self.workdir = Some(p.into());
        self
    }
}

/// Evidence returned by the launcher at launch time. The signer stores
/// one of these per live PID and refuses to sign any result whose
/// `producer_pid` does not attest to an entry in the live table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attestation {
    /// The PID of the attested child. Valid until the process exits.
    pub pid: i32,
    /// The policy the child was launched under.
    pub policy: PolicyKind,
    /// Hex SHA-256 of the on-disk binary at launch time. Detects a
    /// mid-flight replacement of the executable on disk even if the PID
    /// survives.
    pub exe_hash_hex: String,
    /// UTC seconds since epoch at launch.
    pub started_utc: i64,
    /// Full path to the launched binary, for log context.
    pub program: PathBuf,
}

impl Attestation {
    /// Short `pid=NNNN policy=X exe_hash=01ab..` line for audit logs.
    pub fn summary(&self) -> String {
        let short = self.exe_hash_hex.get(..16).unwrap_or(&self.exe_hash_hex);
        format!(
            "pid={} policy={} exe_hash={} started_utc={}",
            self.pid,
            self.policy.label(),
            short,
            self.started_utc
        )
    }
}

/// Handle returned by [`Launcher::launch`]. Drop does NOT kill the child —
/// the signer owns the lifecycle; the launcher only mints the
/// attestation at spawn time.
#[derive(Debug, Clone)]
pub struct LaunchedChild {
    pub attestation: Attestation,
}

#[derive(Debug, Error)]
pub enum IsolationError {
    #[error("unsupported platform for signing workloads: seccomp-bpf requires Linux")]
    UnsupportedPlatform,
    #[error("policy '{0}' not found under santuario/isolation/policies/")]
    PolicyMissing(String),
    #[error("policy '{0}' empty or unparseable")]
    PolicyInvalid(String),
    #[error("program '{0}' does not exist or is not readable")]
    ProgramMissing(PathBuf),
    #[error("program '{0}' is not executable")]
    ProgramNotExecutable(PathBuf),
    #[error("fork/clone failed: {0}")]
    Fork(String),
    #[error("seccomp filter install failed: {0}")]
    Seccomp(String),
    #[error("execve failed: {0}")]
    Execve(String),
    #[error("pid {0} is unknown to the attestation table")]
    UnknownPid(i32),
    #[error("pid {0} is no longer alive")]
    Dead(i32),
    #[error("pid {expected} was attested under policy '{expected_policy}' but submitted result under '{got_policy}'")]
    PolicyMismatch {
        expected: i32,
        expected_policy: String,
        got_policy: String,
    },
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// Platform-agnostic launcher interface. The default constructor on
/// Linux is [`launcher::SeccompLauncher::new`]; on other platforms the
/// stub is a non-functional sentinel that refuses every launch.
pub trait Launcher {
    fn launch(&self, spec: &LaunchSpec) -> Result<LaunchedChild, IsolationError>;

    /// Re-hash the executable by PID and compare against the stored
    /// attestation. Returns `Ok(())` iff the PID is still alive, still
    /// runs the attested binary, and still has the expected policy.
    fn attest(&self, pid: i32) -> Result<Attestation, IsolationError>;

    /// Whether real enforcement is active on this host. The non-Linux
    /// stub returns `false`; the Linux launcher returns `true`.
    fn is_enforcing(&self) -> bool;
}

/// SHA-256 of the on-disk bytes at `path`, returned as lowercase hex.
pub fn hash_file(path: &std::path::Path) -> Result<String, IsolationError> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).map_err(IsolationError::Io)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

/// Current UTC seconds since epoch. Used only for audit logging, not
/// for security decisions.
pub fn now_utc() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_kind_name_matches_file_stem() {
        assert_eq!(PolicyKind::Julia.name(), "julia");
        assert_eq!(PolicyKind::LlmInference.name(), "llm_inference");
        assert_eq!(PolicyKind::Restricted.name(), "restricted");
    }

    #[test]
    fn launch_spec_builder_roundtrips() {
        let s = LaunchSpec::new("/bin/ls", PolicyKind::Restricted)
            .with_arg("-la")
            .with_env("LANG", "C")
            .with_workdir("/tmp");
        assert_eq!(s.args, vec!["-la".to_string()]);
        assert_eq!(s.env, vec![("LANG".to_string(), "C".to_string())]);
        assert_eq!(s.workdir.as_deref(), Some(std::path::Path::new("/tmp")));
        assert_eq!(s.policy, PolicyKind::Restricted);
    }

    #[test]
    fn attestation_summary_is_parseable() {
        let a = Attestation {
            pid: 4242,
            policy: PolicyKind::Julia,
            exe_hash_hex: "0123456789abcdef".repeat(4),
            started_utc: 1_713_542_400,
            program: PathBuf::from("/opt/aeterna/julia"),
        };
        let s = a.summary();
        assert!(s.contains("pid=4242"));
        assert!(s.contains("policy=julia-scientific"));
        assert!(s.contains("exe_hash=0123456789abcdef"));
    }
}
