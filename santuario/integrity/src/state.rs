//! Shared mutable state between the integrity watchdog and the signer.
//!
//! The signer holds an `Arc<SignerState>` and consults it on every
//! `SignRequest`. The watchdog tasks (α audit loop, β CPU monitor, γ
//! port-scan monitor) write into the same `SignerState` when a
//! threshold trips. A suspended signer refuses every sign request with
//! `Err(PermissionDenied)`.
//!
//! Resumption requires an operator-signed **recovery token** — a
//! Dilithium-5-signed challenge; the signer re-verifies it through the
//! [`recovery`](crate::recovery) module. Until resumed, the node stays
//! degraded: verification and gossip still work, signing does not.

use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::{AlertKind, IntegrityAlert};

/// The signer's mutable verdict as seen by every sign request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// Ready to sign.
    Ready,
    /// Suspended due to a threshold trip. Carries the greek letter and
    /// a short reason string for the error response.
    Suspended {
        kind: AlertKind,
        reason: String,
        ts_utc: i64,
    },
}

impl Verdict {
    pub fn is_ready(&self) -> bool {
        matches!(self, Verdict::Ready)
    }

    pub fn as_error_reason(&self) -> Option<String> {
        match self {
            Verdict::Ready => None,
            Verdict::Suspended { kind, reason, .. } => Some(format!(
                "signer suspended under {} threshold: {reason}",
                kind.greek()
            )),
        }
    }
}

/// Thread-safe state cell. Cheap to share across tasks via `Arc`.
#[derive(Debug)]
pub struct SignerState {
    inner: RwLock<Verdict>,
}

impl Default for SignerState {
    fn default() -> Self {
        Self {
            inner: RwLock::new(Verdict::Ready),
        }
    }
}

impl SignerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn verdict(&self) -> Verdict {
        self.inner.read().unwrap().clone()
    }

    pub fn is_ready(&self) -> bool {
        self.verdict().is_ready()
    }

    pub fn suspend(&self, kind: AlertKind, reason: impl Into<String>) {
        *self.inner.write().unwrap() = Verdict::Suspended {
            kind,
            reason: reason.into(),
            ts_utc: crate::now_utc(),
        };
    }

    pub fn suspend_for_alert(&self, alert: &IntegrityAlert) {
        let reason = match &alert.evidence {
            crate::AlertEvidence::AlphaMismatch { path, .. } => {
                format!("file mismatch: {}", path.display())
            }
            crate::AlertEvidence::AlphaMissing { path, .. } => {
                format!("file missing: {}", path.display())
            }
            crate::AlertEvidence::BetaCpuStress { mean_pct, .. } => {
                format!("cpu {:.1}% sustained", mean_pct)
            }
            crate::AlertEvidence::GammaPortScan { peer, .. } => {
                format!("port-scan peer {peer}")
            }
        };
        self.suspend(alert.kind, reason);
    }

    pub fn resume(&self) {
        *self.inner.write().unwrap() = Verdict::Ready;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlertEvidence, IntegrityAlert};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn new_state_is_ready() {
        let s = SignerState::new();
        assert!(s.is_ready());
        assert!(s.verdict().as_error_reason().is_none());
    }

    #[test]
    fn suspend_sets_verdict_and_reason() {
        let s = SignerState::new();
        s.suspend(AlertKind::Alpha, "manifesto mutated");
        assert!(!s.is_ready());
        let r = s.verdict().as_error_reason().unwrap();
        assert!(r.contains("manifesto mutated"));
        assert!(r.contains('α'));
    }

    #[test]
    fn suspend_for_alert_maps_evidence() {
        let s = SignerState::new();
        let a = IntegrityAlert {
            kind: AlertKind::Alpha,
            ts_utc: 1,
            node_id: "n".to_string(),
            evidence: AlertEvidence::AlphaMissing {
                path: PathBuf::from("aeterna.toml"),
                expected_sha256: "aa".repeat(32),
            },
        };
        s.suspend_for_alert(&a);
        assert!(s.verdict().as_error_reason().unwrap().contains("missing"));
    }

    #[test]
    fn concurrent_readers_and_writers() {
        let s = Arc::new(SignerState::new());
        let s1 = s.clone();
        let h = thread::spawn(move || {
            for i in 0..100 {
                s1.suspend(AlertKind::Beta, format!("cpu i={i}"));
                s1.resume();
            }
        });
        for _ in 0..100 {
            let _ = s.verdict();
        }
        h.join().unwrap();
    }
}
