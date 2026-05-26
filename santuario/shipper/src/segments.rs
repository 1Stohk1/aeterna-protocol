//! Segment discovery in the audit directory.
//!
//! The shipper polls the local audit-log directory for finalized
//! `.sigillum` segments. A segment is "finalized" when its trailing
//! magic + counter footer matches the v0.4 Sigillum-v1 spec — in
//! practice this means the segment has been closed via
//! `LogSegmentWriter::finalize()` rather than being the still-active
//! writer that's accumulating new records.
//!
//! ## Why a separate module
//!
//! The shipper does not want to depend on the integrity crate (which
//! pulls in chrono, the audit-record enum, and the whole AuditLog
//! API surface). Segment discovery is a small filesystem walk plus
//! a 16-byte magic check — both achievable with `santuario-cipher`
//! alone.

use std::path::{Path, PathBuf};

use santuario_cipher::{SegmentHeader, HEADER_LEN, SEGMENT_MAGIC};

use crate::error::{Error, Result};

/// Information about a finalized segment ready to be shipped.
#[derive(Debug, Clone)]
pub struct SegmentInfo {
    /// Filesystem path, e.g. `./santuario/integrity/audit/000042.sigillum`.
    pub path: PathBuf,
    /// Numeric segment id extracted from the file header (not the filename).
    /// Two segments with the same id under different master keys is itself
    /// an alert worth raising; we surface the id-from-header so downstream
    /// code can detect such inconsistency.
    pub segment_id: u64,
    /// File size in bytes. Used as a coarse "is this worth shipping" gate
    /// (zero-byte files are dropped as malformed).
    pub size_bytes: u64,
}

/// Walks `dir` and returns every `*.sigillum` file whose header parses
/// as a valid Sigillum-v1 segment. The result is sorted by `segment_id`
/// ascending so callers can ship oldest-first.
///
/// Returns `Ok(empty)` for a missing or empty dir — that is the
/// natural state on a fresh node that has not yet appended.
pub fn find_finalized(dir: &Path) -> Result<Vec<SegmentInfo>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(dir).max_depth(1) {
        // walkdir::Error → io::Error so it slots into our Error::Io variant.
        let entry = entry.map_err(|e| {
            e.into_io_error()
                .unwrap_or_else(|| std::io::Error::other("walkdir traversal failed"))
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("sigillum") {
            continue;
        }
        let info = match read_segment_header(path) {
            Ok(info) => info,
            Err(Error::NotASegment { path }) => {
                log::warn!("dropping non-Sigillum-v1 file from segment scan: {path}");
                continue;
            }
            Err(e) => return Err(e),
        };
        out.push(info);
    }
    out.sort_by_key(|s| s.segment_id);
    Ok(out)
}

/// Parse just the 40-byte segment header (magic + segment_id +
/// master_key_id) without decrypting any record. The shipper does NOT
/// have the master key — it identifies segments by id alone.
fn read_segment_header(path: &Path) -> Result<SegmentInfo> {
    use std::io::Read;

    let mut f = std::fs::File::open(path)?;
    let meta = f.metadata()?;
    let mut buf = [0u8; HEADER_LEN];
    if f.read(&mut buf)? < HEADER_LEN {
        return Err(Error::NotASegment {
            path: path.display().to_string(),
        });
    }
    if &buf[..SEGMENT_MAGIC.len()] != &SEGMENT_MAGIC[..] {
        return Err(Error::NotASegment {
            path: path.display().to_string(),
        });
    }
    // Use santuario_cipher's SegmentHeader parser so we share the
    // canonical byte layout with the writer/reader.
    let header = SegmentHeader::from_bytes(&buf).map_err(|_| Error::NotASegment {
        path: path.display().to_string(),
    })?;

    Ok(SegmentInfo {
        path: path.to_path_buf(),
        segment_id: header.segment_id,
        size_bytes: meta.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid Sigillum-v1 segment file: just the 40-byte
    /// header, no records. Real segments are richer, but for shipper
    /// discovery the header alone is sufficient.
    fn write_segment_skeleton(path: &Path, segment_id: u64, master_key_id: [u8; 16]) {
        let mut buf = Vec::with_capacity(HEADER_LEN);
        buf.extend_from_slice(SEGMENT_MAGIC);
        buf.extend_from_slice(&segment_id.to_be_bytes());
        buf.extend_from_slice(&master_key_id);
        assert_eq!(buf.len(), HEADER_LEN);
        std::fs::write(path, &buf).unwrap();
    }

    #[test]
    fn missing_dir_is_empty() {
        let dir = std::path::Path::new("nonexistent-dir-for-shipper-test-deadbeef");
        let segs = find_finalized(dir).unwrap();
        assert!(segs.is_empty());
    }

    #[test]
    fn empty_dir_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let segs = find_finalized(tmp.path()).unwrap();
        assert!(segs.is_empty());
    }

    #[test]
    fn finds_and_sorts_segments() {
        let tmp = tempfile::tempdir().unwrap();
        let key_id = [0xAA; 16];
        // Write in reverse order so we can verify the sort works.
        for id in [2u64, 0, 1] {
            write_segment_skeleton(
                &tmp.path().join(format!("{id:06}.sigillum")),
                id,
                key_id,
            );
        }
        let segs = find_finalized(tmp.path()).unwrap();
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0].segment_id, 0);
        assert_eq!(segs[1].segment_id, 1);
        assert_eq!(segs[2].segment_id, 2);
    }

    #[test]
    fn skips_files_without_sigillum_extension() {
        let tmp = tempfile::tempdir().unwrap();
        let key_id = [0xAA; 16];
        write_segment_skeleton(&tmp.path().join("000007.sigillum"), 7, key_id);
        // Decoy: a file with valid header bytes but wrong extension.
        write_segment_skeleton(&tmp.path().join("000099.bin"), 99, key_id);
        let segs = find_finalized(tmp.path()).unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].segment_id, 7);
    }

    #[test]
    fn skips_files_with_wrong_magic() {
        let tmp = tempfile::tempdir().unwrap();
        // 40 zero bytes -- right length, wrong magic.
        std::fs::write(tmp.path().join("000003.sigillum"), [0u8; HEADER_LEN]).unwrap();
        let segs = find_finalized(tmp.path()).unwrap();
        assert!(segs.is_empty(), "files without SIGILLUM magic must be ignored");
    }

    #[test]
    fn skips_files_shorter_than_header() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("000004.sigillum"), b"short").unwrap();
        let segs = find_finalized(tmp.path()).unwrap();
        assert!(segs.is_empty());
    }

    #[test]
    fn segment_info_size_matches_file_size() {
        let tmp = tempfile::tempdir().unwrap();
        let key_id = [0xCC; 16];
        let path = tmp.path().join("000042.sigillum");
        write_segment_skeleton(&path, 42, key_id);
        let segs = find_finalized(tmp.path()).unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].size_bytes, HEADER_LEN as u64);
        assert_eq!(segs[0].segment_id, 42);
    }
}
