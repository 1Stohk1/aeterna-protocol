//! Append-only audit log. **Encrypted at rest from v0.4 "Sigillum"**.
//!
//! Every integrity alert, every signer self-suspend, every recovery
//! unseal lands here. Records are JSON-serialized and sealed under
//! ChaCha20-Poly1305 segments via the `santuario-cipher` crate. The
//! plaintext JSON-Lines path of v0.3 is gone -- a v0.3 file lying on
//! disk is simply ignored by the new reader (cesura netta per
//! SPRINT-v0.4.0 §7.1).
//!
//! ## On-disk layout (v0.4)
//!
//! ```text
//! <repo>/santuario/integrity/audit/
//!   0000000000.sigillum    <- header (40 B) + records, capped at 10 MiB
//!   0000000001.sigillum    <- next segment, opened on rotation
//!   ...
//!   0000000NNN.sigillum    <- active segment (still being appended to)
//! ```
//!
//! Each file is a self-authenticated unit. Reading the audit tail with
//! the wrong master key fails immediately on the first segment -- the
//! reader never silently degrades.
//!
//! ## Concurrency
//!
//! `AuditLog::append` takes `&self` to keep the existing call-site
//! ergonomics intact across the signer, the recovery flow, and the
//! integrity loop. Internal mutability is protected by a `Mutex`
//! around the active `LogSegmentWriter`. Contention is negligible
//! because audit emissions are rare (event-driven, not per-sign-call)
//! and each emission holds the mutex for ~tens of microseconds.
//!
//! ## Master key provisioning (Phase A)
//!
//! For v0.4.0 the master log key is generated on first boot via OsRng
//! and persisted at `<vault>/log_master.key` (chmod 0o600 on Unix).
//! Phase C will replace the random-on-first-boot path with BIP-39 seed
//! derivation; the on-disk layout and the `MasterLogKey` type stay
//! stable so the migration is a one-line swap.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use santuario_cipher::{
    LogSegmentReader, LogSegmentWriter, MasterLogKey, DEFAULT_MAX_PLAINTEXT_BYTES,
};
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

/// Encrypted append-only audit log backed by Sigillum-v1 segments.
///
/// `Clone` is intentionally cheap (Arc bump + PathBuf copy) so callers
/// like the signer's `RecoveryContext` can hold their own handle that
/// shares the same underlying segment manager and master key. All
/// clones write to the same active segment; no key material is
/// duplicated in memory.
#[derive(Clone)]
pub struct AuditLog {
    pub dir: PathBuf,
    inner: Arc<AuditLogInner>,
}

/// Owned by the Arc inside `AuditLog`. Holding the master key here
/// (instead of inline in AuditLog) means a single MasterLogKey lives
/// in the process even when the AuditLog is cloned to many sites.
struct AuditLogInner {
    master: MasterLogKey,
    seg: Mutex<SegmentManager>,
}

struct SegmentManager {
    /// Currently-open writer. Lazily created on first append.
    active: Option<LogSegmentWriter>,
    /// Next segment id to mint when the current writer fills up OR
    /// when no active writer exists yet.
    next_segment_id: u64,
    /// Plaintext-equivalent rotation cap, in bytes. Defaults to
    /// `DEFAULT_MAX_PLAINTEXT_BYTES` (10 MiB).
    max_plaintext_bytes: u64,
}

impl AuditLog {
    /// Production constructor. Scans `dir` for any pre-existing
    /// `*.sigillum` segments and resumes from `max(segment_id) + 1`
    /// so segment ids are unique across restarts.
    ///
    /// `master` is the `MasterLogKey` obtained via
    /// `MasterLogKey::load_or_generate(<vault>/log_master.key)`.
    pub fn new(
        dir: impl Into<PathBuf>,
        master: MasterLogKey,
    ) -> Result<Self, IntegrityError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let next = scan_next_segment_id(&dir)?;
        Ok(Self {
            dir,
            inner: Arc::new(AuditLogInner {
                master,
                seg: Mutex::new(SegmentManager {
                    active: None,
                    next_segment_id: next,
                    max_plaintext_bytes: DEFAULT_MAX_PLAINTEXT_BYTES,
                }),
            }),
        })
    }

    /// Default location: `<repo_root>/santuario/integrity/audit/`.
    pub fn default_for_repo(
        repo_root: &Path,
        master: MasterLogKey,
    ) -> Result<Self, IntegrityError> {
        Self::new(repo_root.join("santuario/integrity/audit"), master)
    }

    /// Test helper: random per-process master key, log directory under
    /// `dir`. Useful for unit tests where persistence across runs is
    /// not desired.
    pub fn ephemeral(dir: impl Into<PathBuf>) -> Result<Self, IntegrityError> {
        Self::new(dir, MasterLogKey::generate())
    }

    /// Test helper: like `new` but with a custom segment-rotation cap
    /// so tests can exercise rotation without writing 10 MiB.
    #[doc(hidden)]
    pub fn new_with_cap(
        dir: impl Into<PathBuf>,
        master: MasterLogKey,
        max_plaintext_bytes: u64,
    ) -> Result<Self, IntegrityError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let next = scan_next_segment_id(&dir)?;
        Ok(Self {
            dir,
            inner: Arc::new(AuditLogInner {
                master,
                seg: Mutex::new(SegmentManager {
                    active: None,
                    next_segment_id: next,
                    max_plaintext_bytes,
                }),
            }),
        })
    }

    pub fn append(&self, rec: &AuditRecord) -> Result<(), IntegrityError> {
        let json = serde_json::to_vec(rec)?;
        let mut mgr = self.inner.seg.lock().expect("audit log mutex poisoned");

        // Open active writer lazily so an AuditLog that is constructed
        // but never written to leaves no segment file behind.
        if mgr.active.is_none() {
            let id = mgr.next_segment_id;
            let writer = LogSegmentWriter::new_with_cap(
                &self.dir,
                &self.inner.master,
                id,
                mgr.max_plaintext_bytes,
            )?;
            mgr.active = Some(writer);
        }

        // The unwrap is safe because we just ensured `active` is Some.
        let writer = mgr.active.as_mut().expect("active writer just initialized");
        writer.append(&json)?;

        // If the segment just crossed the rotation threshold, finalize
        // it and bump the segment id. The next append() opens a fresh
        // writer at id+1.
        if writer.should_rotate() {
            // take() leaves None; we drop into finalize() which flushes.
            let old = mgr.active.take().expect("just-checked active writer");
            old.finalize()?;
            mgr.next_segment_id = mgr
                .next_segment_id
                .checked_add(1)
                .ok_or_else(|| IntegrityError::Io(std::io::Error::other(
                    "segment_id overflow -- node has been running far longer than v0.4 supports",
                )))?;
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
    /// the tail; useful for `santuarioctl status --tail 20` and for
    /// the `Admin.TailAuditLog` gRPC response.
    ///
    /// Iterates segments in segment_id order (oldest first), collects
    /// every decrypted record, then keeps the last `limit`. Slow for
    /// very deep histories; the typical "tail 50" stays well under
    /// 100 ms even with hundreds of segments.
    pub fn tail(&self, limit: usize) -> Result<Vec<AuditRecord>, IntegrityError> {
        // Flush the active writer to disk so its records are visible
        // to the reader. Without this, a record just appended is
        // buffered inside the BufWriter and tail() would miss it.
        {
            let mut mgr = self.inner.seg.lock().expect("audit log mutex poisoned");
            if let Some(writer) = mgr.active.take() {
                let id = writer.segment_id();
                writer.finalize()?;
                // Advance next_segment_id past the just-closed one so
                // the next append doesn't try to re-create the same file.
                if mgr.next_segment_id == id {
                    mgr.next_segment_id = id.checked_add(1).ok_or_else(|| {
                        IntegrityError::Io(std::io::Error::other(
                            "segment_id overflow on tail flush",
                        ))
                    })?;
                }
            }
        }

        let mut segments = list_segments(&self.dir)?;
        segments.sort_by_key(|(id, _)| *id);

        let mut all: Vec<AuditRecord> = Vec::new();
        for (_, path) in &segments {
            let mut reader = match LogSegmentReader::open(path, &self.inner.master) {
                Ok(r) => r,
                Err(santuario_cipher::Error::InvalidMagic) => {
                    // A non-Sigillum file landed in the dir (e.g., a
                    // v0.3 plaintext leftover). Skip it silently --
                    // the cesura-netta contract says we ignore.
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            for record_bytes in reader.records() {
                let bytes = record_bytes?;
                let rec: AuditRecord = serde_json::from_slice(&bytes)?;
                all.push(rec);
            }
        }

        let start = all.len().saturating_sub(limit);
        Ok(all.split_off(start))
    }
}

// Avoid #[derive(Debug)] -- MasterLogKey's Debug is hand-redacted, and
// the Mutex<SegmentManager> inside the Arc doesn't impl Debug uniformly.
impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("dir", &self.dir)
            .field("master", &self.inner.master)
            .finish()
    }
}

/// Scan `dir` for `<id>.sigillum` files, return `max(id) + 1`. If the
/// directory is empty, return 0. A non-conforming file name is skipped
/// silently (the magic/header check happens at read time).
fn scan_next_segment_id(dir: &Path) -> Result<u64, IntegrityError> {
    let mut max_id: Option<u64> = None;
    if !dir.exists() {
        return Ok(0);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        if let Some(stem) = name.strip_suffix(".sigillum") {
            if let Ok(id) = stem.parse::<u64>() {
                max_id = Some(max_id.map_or(id, |m| m.max(id)));
            }
        }
    }
    Ok(max_id.map_or(0, |m| m + 1))
}

/// Return all `<id>.sigillum` files in `dir`, paired with their parsed
/// segment id. Order is filesystem-dependent; the caller is expected
/// to sort.
fn list_segments(dir: &Path) -> Result<Vec<(u64, PathBuf)>, IntegrityError> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(s) => s,
            None => continue,
        };
        if let Some(stem) = name.strip_suffix(".sigillum") {
            if let Ok(id) = stem.parse::<u64>() {
                out.push((id, path));
            }
        }
    }
    Ok(out)
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
        let log = AuditLog::ephemeral(dir.path().join("audit")).unwrap();
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
    fn tail_of_missing_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::ephemeral(dir.path().join("nope")).unwrap();
        assert!(log.tail(10).unwrap().is_empty());
    }

    #[test]
    fn records_are_encrypted_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::ephemeral(dir.path().join("audit")).unwrap();
        log.log_suspend("secret reason that should not appear in plaintext")
            .unwrap();
        // Force a flush by tailing once.
        let _ = log.tail(10).unwrap();

        // Locate the segment file and assert the secret string is NOT
        // present anywhere in its bytes -- the log directory is meant
        // to be opaque to anyone without the master key.
        let segment_files: Vec<_> = std::fs::read_dir(&log.dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sigillum"))
            .collect();
        assert_eq!(segment_files.len(), 1, "exactly one segment expected");
        let bytes = std::fs::read(segment_files[0].path()).unwrap();
        assert!(
            !bytes.windows(b"secret reason".len()).any(|w| w == b"secret reason"),
            "plaintext leak: 'secret reason' substring found in {:?}",
            segment_files[0].path()
        );
        // The magic header MUST be present though.
        assert_eq!(&bytes[..16], b"SIGILLUM-v1\0\0\0\0\0");
    }

    #[test]
    fn rotation_creates_new_segments() {
        let dir = tempfile::tempdir().unwrap();
        // Tiny cap so a few records trigger rotation.
        let log = AuditLog::new_with_cap(
            dir.path().join("audit"),
            MasterLogKey::generate(),
            200, // ~200 plaintext bytes per segment
        )
        .unwrap();
        for _ in 0..20 {
            // Each suspend record serializes to ~80 bytes of JSON.
            log.log_suspend("rotate me please").unwrap();
        }
        let _ = log.tail(usize::MAX).unwrap();

        let n_segments = std::fs::read_dir(log.dir.clone())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "sigillum"))
            .count();
        assert!(
            n_segments >= 2,
            "rotation should have produced at least 2 segments, got {}",
            n_segments
        );
    }

    #[test]
    fn second_open_resumes_from_next_segment_id() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("master.key");
        let master1 = MasterLogKey::load_or_generate(&key_path).unwrap();
        let log_dir = dir.path().join("audit");

        {
            let log = AuditLog::new(&log_dir, master1.clone()).unwrap();
            log.log_suspend("first run").unwrap();
            // Force flush by reading.
            let _ = log.tail(10).unwrap();
        } // log dropped here -- segment 0 is finalized on disk

        let master2 = MasterLogKey::load_or_generate(&key_path).unwrap();
        let log2 = AuditLog::new(&log_dir, master2).unwrap();
        log2.log_suspend("second run").unwrap();
        let records = log2.tail(10).unwrap();
        assert_eq!(records.len(), 2, "both runs' records must be readable");
    }

    #[test]
    fn tail_skips_v0_3_plaintext_leftover() {
        let dir = tempfile::tempdir().unwrap();
        let log_dir = dir.path().join("audit");
        std::fs::create_dir_all(&log_dir).unwrap();
        // Drop a v0.3 plaintext file in the dir. It does NOT have the
        // .sigillum extension so list_segments() ignores it. Even if it
        // had the extension, the magic check would skip it.
        std::fs::write(
            log_dir.join("audit.log.jsonl"),
            b"{\"record\":\"alert\",\"severity\":\"alpha\"}\n",
        )
        .unwrap();
        let log = AuditLog::ephemeral(&log_dir).unwrap();
        log.log_suspend("v0.4 era").unwrap();
        let records = log.tail(10).unwrap();
        assert_eq!(records.len(), 1, "v0.3 file must be invisible to v0.4 reader");
    }

    #[test]
    fn append_holds_mutex_briefly() {
        // Smoke test: 100 appends across a single AuditLog complete in
        // less than a second on any reasonable hardware. We don't measure
        // latency precisely, just confirm the API doesn't deadlock.
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::ephemeral(dir.path().join("audit")).unwrap();
        for i in 0..100 {
            log.log_suspend(format!("burst {}", i)).unwrap();
        }
        let records = log.tail(usize::MAX).unwrap();
        assert_eq!(records.len(), 100);
    }
}
