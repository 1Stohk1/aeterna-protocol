//! α/β/γ threshold watchdog for the Santuario.
//!
//! - **α** — hourly SHA-256 sweep across the critical file set declared in
//!   `aeterna.toml [integrity].files`. A mismatch fires an
//!   [`IntegrityAlert`], which (a) is gossipped to the network as a
//!   signed message, (b) causes the signer to self-suspend until an
//!   operator unseals with a recovery token, (c) is appended to the
//!   audit log. See [`audit`].
//! - **β** — 10-minute CPU-usage window; ≥90% average for the window
//!   trips the threshold and puts the node in degraded mode (signer
//!   refuses new work, verification still live). See [`cpu`].
//! - **γ** — three unsolicited port scans trip the γ threshold; same
//!   degraded-mode shift plus a mandatory recovery-token reboot. See
//!   [`portscan`].
//!
//! The three detectors share an [`AlertSink`] — an append-only log and
//! the in-memory [`SignerState`] flag the signer polls on every sign
//! request.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod audit;
pub mod config;
pub mod cpu;
pub mod log;
pub mod portscan;
pub mod state;

pub use audit::{FileDigest, IntegrityAuditor};
pub use config::IntegrityConfig;
pub use log::AuditLog;
pub use state::{SignerState, Verdict};

/// Kinds of degraded-mode trigger. Maps 1:1 to the Greek-letter
/// thresholds described in `docs/sprint-v0.2.0.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// File-system integrity mismatch (α).
    Alpha,
    /// CPU stress threshold crossed (β).
    Beta,
    /// Port-scan quota exceeded (γ).
    Gamma,
}

impl AlertKind {
    pub fn greek(self) -> char {
        match self {
            AlertKind::Alpha => 'α',
            AlertKind::Beta => 'β',
            AlertKind::Gamma => 'γ',
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            AlertKind::Alpha => "alpha",
            AlertKind::Beta => "beta",
            AlertKind::Gamma => "gamma",
        }
    }
}

/// Single alert record — the union of all three threshold kinds. Each
/// alert carries enough evidence for an operator to pinpoint the cause
/// without having to query the live node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntegrityAlert {
    pub kind: AlertKind,
    pub ts_utc: i64,
    pub node_id: String,
    pub evidence: AlertEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AlertEvidence {
    AlphaMismatch {
        path: PathBuf,
        expected_sha256: String,
        observed_sha256: String,
    },
    AlphaMissing {
        path: PathBuf,
        expected_sha256: String,
    },
    BetaCpuStress {
        window_seconds: u64,
        mean_pct: f32,
        threshold_pct: f32,
    },
    GammaPortScan {
        peer: String,
        count_in_window: u32,
        window_seconds: u64,
    },
}

impl IntegrityAlert {
    /// Serialize the alert as canonical JSON for the gossip payload.
    /// The Python gossip layer signs this exact byte-string with the
    /// node's Dilithium-5 key.
    pub fn to_canonical_json(&self) -> serde_json::Result<String> {
        // serde_json with no pretty indent and BTreeMap-backed objects
        // (our structs all use insertion order → we rely on the
        // top-level `tag=` discriminant to keep ordering stable).
        serde_json::to_string(self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse: {0}")]
    Toml(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("audit log is closed")]
    LogClosed,
    #[error("unknown file key '{0}' in integrity sweep")]
    UnknownKey(String),
}

impl From<toml::de::Error> for IntegrityError {
    fn from(e: toml::de::Error) -> Self {
        IntegrityError::Toml(e.to_string())
    }
}

/// Current UTC seconds since the epoch.
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
    fn alert_kind_names() {
        assert_eq!(AlertKind::Alpha.greek(), 'α');
        assert_eq!(AlertKind::Beta.name(), "beta");
        assert_eq!(AlertKind::Gamma.name(), "gamma");
    }

    #[test]
    fn alert_roundtrips_json() {
        let a = IntegrityAlert {
            kind: AlertKind::Alpha,
            ts_utc: 1_713_542_400,
            node_id: "Prometheus-1".to_string(),
            evidence: AlertEvidence::AlphaMismatch {
                path: PathBuf::from("MANIFESTO.md"),
                expected_sha256: "aa".repeat(32),
                observed_sha256: "bb".repeat(32),
            },
        };
        let j = a.to_canonical_json().unwrap();
        let back: IntegrityAlert = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }
}
