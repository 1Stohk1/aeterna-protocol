//! Append-only audit log.
//!
//! Every integrity alert, every signer self-suspend, every recovery
//! unseal lands here as a JSON-Lines record. The file is `chmod 0o600`
//! and never rewritten in place — operators can `tail -f` it.
//!
//! The log is NOT the gossip channel. The gossip layer (Python
//! `core/gossip.py`) broadcasts alerts to peers; this file is the local
//! forensic trail.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{now_utc, IntegrityAlert, IntegrityError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum AuditRecord {
    /// An α/β/γ alert fired.
    Alert(IntegrityAlert),
    /// The signer voluntarily suspended (e.g. on receiving an alert).
    SignerSuspend { ts_utc: i64, reason: String },
    /// An operator produced a recovery token and cleared the suspension.
    SignerResume { ts_utc: i64, operator: String },
    /// An operator accepted a new baseline for the α sweep.
    BaselineSealed {
        ts_utc: i64,
        operator: String,
        n_entries: usize,
    },
}

/// Append-only JSON-Lines log at a fixed path.
#[derive(Debug, Clone)]
pub struct AuditLog {
    pub path: PathBuf,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Default location under the repo root.
    pub fn default_for_repo(repo_root: &Path) -> Self {
        Self::new(repo_root.join("santuario/integrity/audit.log.jsonl"))
    }

    pub fn append(&self, rec: &AuditRecord) -> Result<(), IntegrityError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let line = serde_json::to_string(rec)?;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{line}")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = f.metadata()?.permissions();
            perms.set_mode(0o600);
            f.set_permissions(perms)?;
        }
        Ok(())
    }

    pub fn log_alert(&self, alert: &IntegrityAlert) -> Result<(), IntegrityError> {
        self.append(&AuditRecord::Alert(alert.clone()))
    }

    pub fn log_suspend(&self, reason: impl Into<String>) -> Result<(), IntegrityError> {
        self.append(&AuditRecord::SignerSuspend {
            ts_utc: now_utc(),
            reason: reason.into(),
        })
    }

    pub fn log_resume(&self, operator: impl Into<String>) -> Result<(), IntegrityError> {
        self.append(&AuditRecord::SignerResume {
            ts_utc: now_utc(),
            operator: operator.into(),
        })
    }

    pub fn log_baseline(
        &self,
        operator: impl Into<String>,
        n_entries: usize,
    ) -> Result<(), IntegrityError> {
        self.append(&AuditRecord::BaselineSealed {
            ts_utc: now_utc(),
            operator: operator.into(),
            n_entries,
        })
    }

    /// Read the log back into memory. Bounded by `limit` records from
    /// the tail; useful for `santuarioctl status --tail 20`.
    pub fn tail(&self, limit: usize) -> Result<Vec<AuditRecord>, IntegrityError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&self.path)?;
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(limit);
        let mut out = Vec::with_capacity(lines.len() - start);
        for l in &lines[start..] {
            if l.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(l)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlertEvidence, AlertKind};
    use std::path::PathBuf;

    fn sample_alert() -> IntegrityAlert {
        IntegrityAlert {
            kind: AlertKind::Alpha,
            ts_utc: 1_713_542_400,
            node_id: "Prometheus-test".to_string(),
            evidence: AlertEvidence::AlphaMismatch {
                path: PathBuf::from("MANIFESTO.md"),
                expected_sha256: "aa".repeat(32),
                observed_sha256: "bb".repeat(32),
            },
        }
    }

    #[test]
    fn append_and_tail_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit.jsonl"));
        log.log_alert(&sample_alert()).unwrap();
        log.log_suspend("alpha fired").unwrap();
        log.log_resume("christian").unwrap();
        let records = log.tail(10).unwrap();
        assert_eq!(records.len(), 3);
        assert!(matches!(records[0], AuditRecord::Alert(_)));
        assert!(matches!(records[1], AuditRecord::SignerSuspend { .. }));
        assert!(matches!(records[2], AuditRecord::SignerResume { .. }));
    }

    #[test]
    fn tail_of_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("nope.jsonl"));
        assert!(log.tail(10).unwrap().is_empty());
    }

    #[test]
    fn records_are_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::new(dir.path().join("audit.jsonl"));
        for _ in 0..3 {
            log.log_alert(&sample_alert()).unwrap();
        }
        let raw = std::fs::read_to_string(&log.path).unwrap();
        assert_eq!(raw.trim().lines().count(), 3);
        for l in raw.lines() {
            let _: AuditRecord = serde_json::from_str(l).unwrap();
        }
    }
}
