//! PID attestation shim between the signer and the isolation launcher.
//!
//! The signer keeps an `Arc<AttestationGate>` and consults it before
//! every Dilithium-5 signature. A `SignRequest` carries an optional
//! `producer_pid`; the gate:
//!
//! 1. Looks up `pid` in the launcher's [`Launcher::attest`] result.
//! 2. Checks the attestation's [`PolicyKind`] matches the kind declared
//!    by the request (callers must agree on the policy out of band —
//!    the Sentinel knows which workload class produced the block).
//! 3. On mismatch, returns `AttestationError::PolicyMismatch` and the
//!    signer answers the gRPC with `PermissionDenied`.
//!
//! With `--feature strict-attestation` disabled, a signing request that
//! omits `producer_pid` is permitted (dev mode). With the feature on,
//! every signable request MUST carry a valid, attested PID.

use std::sync::Arc;

use santuario_isolation::{Attestation, IsolationError, Launcher, PolicyKind};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("attestation required but request omitted producer_pid")]
    Required,
    #[error("isolation layer: {0}")]
    Isolation(#[from] IsolationError),
    #[error("pid {pid} attested under {attested:?} but sign request claims {claimed:?}")]
    PolicyMismatch {
        pid: i32,
        attested: PolicyKind,
        claimed: PolicyKind,
    },
}

/// Gate wrapper around a launcher. Cheap to clone — internally just
/// holds an `Arc<dyn Launcher>`.
#[derive(Clone)]
pub struct AttestationGate {
    launcher: Arc<dyn Launcher + Send + Sync>,
    /// Strict mode: when true, every sign request MUST carry a PID.
    strict: bool,
}

impl AttestationGate {
    pub fn new(launcher: Arc<dyn Launcher + Send + Sync>) -> Self {
        Self {
            launcher,
            strict: cfg!(feature = "strict-attestation"),
        }
    }

    /// Override the strict bit — useful for tests and for the
    /// bootstrap-driven toggle.
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Whether this gate is currently enforcing. Off in dev, on in prod.
    pub fn is_strict(&self) -> bool {
        self.strict
    }

    /// Check that `producer_pid` (if any) matches `claimed_policy`.
    /// Returns the full attestation on success so the signer can log it.
    pub fn verify(
        &self,
        producer_pid: Option<i32>,
        claimed_policy: PolicyKind,
    ) -> Result<Option<Attestation>, AttestationError> {
        match producer_pid {
            None => {
                if self.strict {
                    return Err(AttestationError::Required);
                }
                Ok(None)
            }
            Some(pid) => {
                let att = self.launcher.attest(pid)?;
                if att.policy != claimed_policy {
                    return Err(AttestationError::PolicyMismatch {
                        pid,
                        attested: att.policy,
                        claimed: claimed_policy,
                    });
                }
                Ok(Some(att))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use santuario_isolation::{IsolationError, LaunchSpec, LaunchedChild};
    use std::sync::Mutex;

    struct FakeLauncher {
        by_pid: Mutex<std::collections::HashMap<i32, Attestation>>,
    }

    impl FakeLauncher {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                by_pid: Mutex::new(std::collections::HashMap::new()),
            })
        }

        fn record(&self, att: Attestation) {
            self.by_pid.lock().unwrap().insert(att.pid, att);
        }
    }

    impl Launcher for FakeLauncher {
        fn launch(&self, _spec: &LaunchSpec) -> Result<LaunchedChild, IsolationError> {
            Err(IsolationError::UnsupportedPlatform)
        }

        fn attest(&self, pid: i32) -> Result<Attestation, IsolationError> {
            self.by_pid
                .lock()
                .unwrap()
                .get(&pid)
                .cloned()
                .ok_or(IsolationError::UnknownPid(pid))
        }

        fn is_enforcing(&self) -> bool {
            true
        }
    }

    fn fixture(pid: i32, policy: PolicyKind) -> Attestation {
        Attestation {
            pid,
            policy,
            exe_hash_hex: "a".repeat(64),
            started_utc: 1,
            program: std::path::PathBuf::from("/opt/aeterna/x"),
        }
    }

    #[test]
    fn attested_pid_same_policy_passes() {
        let l = FakeLauncher::new();
        l.record(fixture(77, PolicyKind::Julia));
        let gate = AttestationGate::new(l.clone());
        let out = gate.verify(Some(77), PolicyKind::Julia).unwrap();
        assert_eq!(out.unwrap().pid, 77);
    }

    #[test]
    fn policy_mismatch_rejected() {
        let l = FakeLauncher::new();
        l.record(fixture(77, PolicyKind::Julia));
        let gate = AttestationGate::new(l.clone());
        let err = gate
            .verify(Some(77), PolicyKind::LlmInference)
            .unwrap_err();
        matches!(err, AttestationError::PolicyMismatch { .. });
    }

    #[test]
    fn unknown_pid_rejected() {
        let l = FakeLauncher::new();
        let gate = AttestationGate::new(l.clone());
        let err = gate.verify(Some(99), PolicyKind::Julia).unwrap_err();
        matches!(err, AttestationError::Isolation(IsolationError::UnknownPid(99)));
    }

    #[test]
    fn missing_pid_allowed_in_dev_mode() {
        let l = FakeLauncher::new();
        let gate = AttestationGate::new(l.clone()).with_strict(false);
        assert!(gate.verify(None, PolicyKind::Julia).unwrap().is_none());
    }

    #[test]
    fn missing_pid_refused_in_strict_mode() {
        let l = FakeLauncher::new();
        let gate = AttestationGate::new(l.clone()).with_strict(true);
        let err = gate.verify(None, PolicyKind::Julia).unwrap_err();
        matches!(err, AttestationError::Required);
    }
}
