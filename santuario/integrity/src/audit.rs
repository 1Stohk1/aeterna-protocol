//! α sweep — hashes the critical file set and flags mismatches.
//!
//! On first run the auditor records the observed SHA-256 for every
//! declared path as the *expected* baseline. Every subsequent sweep
//! re-hashes each file and compares against the baseline; any delta
//! produces an [`IntegrityAlert`] with kind [`AlertKind::Alpha`].
//!
//! The baseline lives in `santuario/integrity/baseline.json` — an
//! operator rotates it after a legitimate file change (e.g. software
//! update) by running `santuarioctl audit --accept-new`.
//!
//! The auditor is a *pure data* component: it doesn't spawn threads,
//! sleep, or poll. The signer's own Tokio runtime drives it via
//! `sweep_once()`; the hourly cadence is enforced by a `tokio::time::sleep`
//! loop in `main.rs`. This keeps the crate easy to unit-test.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{now_utc, AlertEvidence, AlertKind, IntegrityAlert, IntegrityConfig, IntegrityError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileDigest {
    pub path: PathBuf,
    pub sha256_hex: String,
}

/// Baseline — the trusted, signed-off hashes of the integrity file set.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Baseline {
    pub recorded_utc: i64,
    pub entries: BTreeMap<String, String>, // path -> sha256 hex
}

impl Baseline {
    pub fn load(path: &Path) -> Result<Self, IntegrityError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn save(&self, path: &Path) -> Result<(), IntegrityError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let j = serde_json::to_string_pretty(self)?;
        std::fs::write(path, j)?;
        Ok(())
    }
}

/// The α sweep engine.
#[derive(Debug, Clone)]
pub struct IntegrityAuditor {
    pub node_id: String,
    pub repo_root: PathBuf,
    pub cfg: IntegrityConfig,
    pub baseline_path: PathBuf,
}

impl IntegrityAuditor {
    pub fn new(
        node_id: impl Into<String>,
        repo_root: impl Into<PathBuf>,
        cfg: IntegrityConfig,
    ) -> Self {
        let repo_root = repo_root.into();
        let baseline_path = repo_root.join("santuario/integrity/baseline.json");
        Self {
            node_id: node_id.into(),
            repo_root,
            cfg,
            baseline_path,
        }
    }

    /// Re-hash every file in the config, returning a list of
    /// `FileDigest`. Missing files are silently omitted; the caller
    /// must compare against the baseline to detect *expected-but-
    /// missing* entries.
    pub fn sweep(&self) -> Result<Vec<FileDigest>, IntegrityError> {
        let mut out = Vec::with_capacity(self.cfg.files.len());
        for rel in &self.cfg.files {
            let p = self.repo_root.join(rel);
            if !p.exists() {
                continue;
            }
            let bytes = std::fs::read(&p)?;
            let mut h = Sha256::new();
            h.update(&bytes);
            out.push(FileDigest {
                path: rel.clone(),
                sha256_hex: hex::encode(h.finalize()),
            });
        }
        Ok(out)
    }

    /// Take the first sweep as the signed-off baseline. Writes
    /// `baseline.json`. Call this during `bootstrap.sh` once, or after
    /// an operator accepts a legitimate file change.
    pub fn seal_baseline(&self) -> Result<Baseline, IntegrityError> {
        let digests = self.sweep()?;
        let mut entries = BTreeMap::new();
        for d in digests {
            entries.insert(d.path.display().to_string(), d.sha256_hex);
        }
        let b = Baseline {
            recorded_utc: now_utc(),
            entries,
        };
        b.save(&self.baseline_path)?;
        Ok(b)
    }

    /// Sweep once and compare against the baseline. Returns the list of
    /// alerts to fire. An empty vector means "all clean".
    pub fn sweep_once(&self) -> Result<Vec<IntegrityAlert>, IntegrityError> {
        let baseline = Baseline::load(&self.baseline_path)?;
        if baseline.entries.is_empty() {
            // No baseline → behave as if we sealed one right now. This
            // keeps first-boot from spuriously alerting, at the cost of
            // requiring a manual `santuarioctl audit --seal` in prod.
            return Ok(Vec::new());
        }
        let observed: BTreeMap<String, String> = self
            .sweep()?
            .into_iter()
            .map(|d| (d.path.display().to_string(), d.sha256_hex))
            .collect();

        let mut alerts = Vec::new();
        for (key, expected) in &baseline.entries {
            match observed.get(key) {
                Some(obs) if obs == expected => {}
                Some(obs) => alerts.push(self.alert(AlertEvidence::AlphaMismatch {
                    path: PathBuf::from(key),
                    expected_sha256: expected.clone(),
                    observed_sha256: obs.clone(),
                })),
                None => alerts.push(self.alert(AlertEvidence::AlphaMissing {
                    path: PathBuf::from(key),
                    expected_sha256: expected.clone(),
                })),
            }
        }
        Ok(alerts)
    }

    fn alert(&self, evidence: AlertEvidence) -> IntegrityAlert {
        IntegrityAlert {
            kind: AlertKind::Alpha,
            ts_utc: now_utc(),
            node_id: self.node_id.clone(),
            evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn repo() -> (tempfile::TempDir, IntegrityAuditor) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let mf = root.join("MANIFESTO.md");
        std::fs::write(&mf, b"first principle: life is sacred\n").unwrap();
        let cfg = IntegrityConfig {
            files: vec![PathBuf::from("MANIFESTO.md")],
            ..IntegrityConfig::default()
        };
        let a = IntegrityAuditor::new("Prometheus-test", &root, cfg);
        (dir, a)
    }

    #[test]
    fn sweep_records_all_files() {
        let (_dir, a) = repo();
        let d = a.sweep().unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].path, PathBuf::from("MANIFESTO.md"));
        assert_eq!(d[0].sha256_hex.len(), 64);
    }

    #[test]
    fn baseline_seal_is_idempotent() {
        let (_dir, a) = repo();
        let b1 = a.seal_baseline().unwrap();
        let b2 = Baseline::load(&a.baseline_path).unwrap();
        assert_eq!(b1.entries, b2.entries);
    }

    #[test]
    fn no_baseline_means_no_alerts() {
        let (_dir, a) = repo();
        assert!(a.sweep_once().unwrap().is_empty());
    }

    #[test]
    fn mutation_is_caught() {
        let (dir, a) = repo();
        a.seal_baseline().unwrap();
        // mutate MANIFESTO
        let mf = dir.path().join("MANIFESTO.md");
        let mut f = std::fs::OpenOptions::new().append(true).open(&mf).unwrap();
        writeln!(f, "attacker-added line").unwrap();
        let alerts = a.sweep_once().unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::Alpha);
        match &alerts[0].evidence {
            AlertEvidence::AlphaMismatch { path, .. } => {
                assert_eq!(path, &PathBuf::from("MANIFESTO.md"))
            }
            other => panic!("expected AlphaMismatch, got {other:?}"),
        }
    }

    #[test]
    fn deletion_is_caught() {
        let (dir, a) = repo();
        a.seal_baseline().unwrap();
        std::fs::remove_file(dir.path().join("MANIFESTO.md")).unwrap();
        let alerts = a.sweep_once().unwrap();
        assert_eq!(alerts.len(), 1);
        match &alerts[0].evidence {
            AlertEvidence::AlphaMissing { path, .. } => {
                assert_eq!(path, &PathBuf::from("MANIFESTO.md"))
            }
            other => panic!("expected AlphaMissing, got {other:?}"),
        }
    }
}
