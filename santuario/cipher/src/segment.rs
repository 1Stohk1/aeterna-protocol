//! Encrypted audit-log segments.
//!
//! ## File layout
//!
//! ```text
//! HEADER (40 bytes, plaintext, integrity-bound by the per-record AD)
//!   [0..16]    magic = "SIGILLUM-v1\0\0\0\0\0"
//!   [16..24]   segment_id (u64 BE)
//!   [24..40]   master_key_id (16 bytes -- truncated SHA-256 of the
//!              master key; reveals nothing about the key itself)
//!
//! RECORDS (one or more, until rotation cap):
//!   for each record:
//!     [0..4]   length (u32 BE) -- size of ciphertext+tag (= plaintext_len + 16)
//!     [4..8]   counter (u32 LE) -- monotonic within segment, drives the nonce
//!     [8..]    payload = ChaCha20Poly1305_seal(subkey, nonce, ad, plaintext)
//!
//!   where:
//!     nonce = nonce_prefix(8 bytes) || counter (4 bytes LE)        -- 12 bytes total
//!     ad    = segment_id (8 bytes LE) || counter (4 bytes LE)      -- 12 bytes
//! ```
//!
//! Including `(segment_id, counter)` as the AEAD associated data binds
//! every record to its position in the segment AND to the segment
//! identity. An attacker who swaps two records inside the same segment
//! gets `Error::AuthFailed` on the second one; an attacker who copies
//! a record from segment N to segment M gets `Error::AuthFailed` even
//! if N and M share a master key.
//!
//! ## Rotation
//!
//! `LogSegmentWriter::should_rotate()` returns true once the cumulative
//! plaintext bytes written exceeds `max_plaintext_bytes` (configured at
//! construction; default 10 MiB per SPRINT-v0.4.0 §3 Phase A). The
//! segment manager (in `santuario-integrity`, not here) is expected to
//! poll this after each append and call `finalize()` + open a fresh
//! writer with `segment_id + 1` when true.
//!
//! ## Hard nonce-reuse guard
//!
//! `append()` panics if the per-record counter would wrap around u32.
//! At 10 MiB cap with realistic ~250-byte audit records, the counter
//! tops out around 2^16 -- four orders of magnitude below the limit.
//! The panic exists for the future case where someone misconfigures
//! the cap to absurd values.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::error::{Error, Result};
use crate::keys::{MasterKeyId, MasterLogKey, SegmentSubKey};

/// Magic marker at the start of every Sigillum-v1 segment file. Exactly
/// 16 bytes so it aligns the segment header to 16-byte boundaries.
pub const SEGMENT_MAGIC: &[u8; 16] = b"SIGILLUM-v1\0\0\0\0\0";

/// Total segment header size in bytes: magic + segment_id + master_key_id.
pub const HEADER_LEN: usize = 16 + 8 + 16;

/// Default rotation cap. SPRINT-v0.4.0 §3 Phase A.
pub const DEFAULT_MAX_PLAINTEXT_BYTES: u64 = 10 * 1024 * 1024;

/// Per-record overhead on disk: 4 (length) + 4 (counter) + 16 (Poly1305 tag).
pub const RECORD_OVERHEAD: usize = 4 + 4 + 16;

/// Hard upper bound on counter to refuse anywhere close to nonce-reuse.
/// `2^32 - 1024` leaves a safety margin for the 1024 records the runbook
/// might emit during a panic-driven incident burst.
const COUNTER_HARD_LIMIT: u32 = u32::MAX - 1024;

/// Strongly-typed view of a parsed segment header. Public so callers can
/// inspect a segment without fully decrypting it (operator forensics).
#[derive(Debug, Clone, Copy)]
pub struct SegmentHeader {
    pub segment_id: u64,
    pub master_key_id: MasterKeyId,
}

// =============================================================================
// Writer
// =============================================================================

pub struct LogSegmentWriter {
    file: BufWriter<File>,
    subkey: SegmentSubKey,
    cipher: ChaCha20Poly1305,
    counter: u32,
    plaintext_bytes_written: u64,
    max_plaintext_bytes: u64,
    path: PathBuf,
}

impl LogSegmentWriter {
    /// Create a new segment file at `dir/<segment_id:010>.sigillum` and
    /// write the magic header. Fails if the file already exists -- by
    /// design, segment IDs are unique-per-run and the manager is expected
    /// to pick the next free one.
    pub fn new(dir: &Path, master: &MasterLogKey, segment_id: u64) -> Result<Self> {
        Self::new_with_cap(dir, master, segment_id, DEFAULT_MAX_PLAINTEXT_BYTES)
    }

    pub fn new_with_cap(
        dir: &Path,
        master: &MasterLogKey,
        segment_id: u64,
        max_plaintext_bytes: u64,
    ) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{:010}.sigillum", segment_id));

        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        let mut file = BufWriter::new(file);

        // Header: magic || segment_id_be(8) || master_key_id(16).
        let master_id = master.id();
        file.write_all(SEGMENT_MAGIC)?;
        file.write_all(&segment_id.to_be_bytes())?;
        file.write_all(master_id.as_bytes())?;
        file.flush()?;

        let subkey = master.derive_segment_subkey(segment_id)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(subkey.subkey()));

        Ok(Self {
            file,
            subkey,
            cipher,
            counter: 0,
            plaintext_bytes_written: 0,
            max_plaintext_bytes,
            path,
        })
    }

    /// Append one record. The plaintext bytes are sealed with a fresh
    /// `(nonce, ad)` pair derived from the segment + counter, then
    /// length-prefixed and written.
    pub fn append(&mut self, plaintext: &[u8]) -> Result<()> {
        if self.counter >= COUNTER_HARD_LIMIT {
            return Err(Error::Invariant(
                "segment record counter near u32::MAX -- rotation overdue",
            ));
        }
        let counter_le = self.counter.to_le_bytes();
        let nonce_bytes = self.subkey.nonce_for_record(self.counter);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // AD binds (segment_id, counter) so cross-record / cross-segment
        // splice attacks fail authentication.
        let mut ad = [0u8; 12];
        ad[..8].copy_from_slice(&self.subkey.segment_id().to_le_bytes());
        ad[8..].copy_from_slice(&counter_le);

        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &ad,
                },
            )
            .map_err(|_| Error::Invariant("ChaCha20Poly1305 encrypt failed"))?;

        // Disk format: length(4 BE) || counter(4 LE) || ciphertext+tag.
        let length: u32 = ciphertext.len().try_into().map_err(|_| {
            Error::Invariant("record ciphertext exceeds u32 -- record too large")
        })?;
        self.file.write_all(&length.to_be_bytes())?;
        self.file.write_all(&counter_le)?;
        self.file.write_all(&ciphertext)?;

        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(Error::Invariant("counter overflow"))?;
        self.plaintext_bytes_written += plaintext.len() as u64;

        Ok(())
    }

    /// Returns true if the segment has reached its rotation cap. The
    /// caller (segment manager in santuario-integrity) is expected to
    /// poll this after each append and rotate when true.
    pub fn should_rotate(&self) -> bool {
        self.plaintext_bytes_written >= self.max_plaintext_bytes
    }

    /// Flush and close. Consumes self because no further writes are
    /// permitted after finalization.
    pub fn finalize(mut self) -> Result<()> {
        self.file.flush()?;
        Ok(())
    }

    /// Inspect-only accessors -- handy for tests and for the segment
    /// manager's metric instrumentation.
    pub fn segment_id(&self) -> u64 {
        self.subkey.segment_id()
    }
    pub fn record_count(&self) -> u32 {
        self.counter
    }
    pub fn plaintext_bytes(&self) -> u64 {
        self.plaintext_bytes_written
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// =============================================================================
// Reader
// =============================================================================

pub struct LogSegmentReader {
    file: BufReader<File>,
    header: SegmentHeader,
    subkey: SegmentSubKey,
    cipher: ChaCha20Poly1305,
    /// Position the reader expects the next record to claim. Starts at
    /// 0 and increments after each successful decrypt. Mismatch with
    /// the on-disk counter field returns `Error::OutOfOrder`, catching
    /// physical reordering attacks that the AEAD alone cannot see.
    expected_counter: u32,
}

// Manual Debug impl: ChaCha20Poly1305 deliberately does NOT implement Debug
// (it would risk leaking the key bytes), and SegmentSubKey's Debug is
// hand-redacted. We propagate that discipline at the Reader level so callers
// can `unwrap_err` / `expect` without leaking secrets into panic messages.
impl std::fmt::Debug for LogSegmentReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogSegmentReader")
            .field("header", &self.header)
            .field("subkey", &self.subkey)
            .field("cipher", &"<ChaCha20Poly1305 redacted>")
            .finish()
    }
}

impl LogSegmentReader {
    /// Open and authenticate a segment. Reads the magic header, parses
    /// the segment_id and master_key_id, derives the subkey, and
    /// positions the file cursor at the first record.
    ///
    /// Failure modes (in order of precedence):
    /// * file too short to hold the 40-byte header -> `InvalidMagic`
    ///   (a stub file is, by definition, not a Sigillum segment)
    /// * 16-byte magic does not match SEGMENT_MAGIC -> `InvalidMagic`
    /// * master_key_id in the header doesn't match the supplied master
    ///   -> `KeyIdMismatch`
    pub fn open(path: &Path, master: &MasterLogKey) -> Result<Self> {
        let file = OpenOptions::new().read(true).open(path)?;
        let mut file = BufReader::new(file);

        // Read the magic separately and tolerate a short read: any file
        // smaller than 16 bytes that doesn't already match the magic is
        // categorically not a Sigillum segment.
        let mut magic_buf = [0u8; 16];
        let n = file.read(&mut magic_buf)?;
        if n < 16 || &magic_buf != SEGMENT_MAGIC {
            return Err(Error::InvalidMagic);
        }

        // Now read the rest of the header. At this point we know the file
        // claimed to be Sigillum-v1, so a truncation here is a real
        // truncation (genuinely corrupted segment), not a category error.
        let mut rest = [0u8; HEADER_LEN - 16];
        file.read_exact(&mut rest)?;

        let mut sid_bytes = [0u8; 8];
        sid_bytes.copy_from_slice(&rest[..8]);
        let segment_id = u64::from_be_bytes(sid_bytes);

        let mut mki_bytes = [0u8; 16];
        mki_bytes.copy_from_slice(&rest[8..24]);
        let stored_id = MasterKeyId(mki_bytes);

        let actual_id = master.id();
        if stored_id != actual_id {
            return Err(Error::KeyIdMismatch {
                expected: stored_id.0,
                actual: actual_id.0,
            });
        }

        let header = SegmentHeader {
            segment_id,
            master_key_id: stored_id,
        };
        let subkey = master.derive_segment_subkey(segment_id)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(subkey.subkey()));

        Ok(Self {
            file,
            header,
            subkey,
            cipher,
            expected_counter: 0,
        })
    }

    pub fn header(&self) -> SegmentHeader {
        self.header
    }

    /// Iterate over decrypted plaintext records. Each iteration item is
    /// a `Result<Vec<u8>>` so the caller can decide whether to halt or
    /// continue on a per-record error (e.g., truncation at end of a
    /// crashed segment).
    pub fn records(&mut self) -> RecordIter<'_> {
        RecordIter { reader: self }
    }

    /// Internal: decrypt one record at the current file position, or
    /// return Ok(None) at clean EOF.
    fn read_one(&mut self) -> Result<Option<Vec<u8>>> {
        // Length prefix. We use a hand-rolled "read exact OR clean EOF"
        // helper because `Read::read()` is permitted to return fewer
        // bytes than requested even when the stream is not at EOF
        // (e.g., when a `BufReader` exhausts its internal buffer
        // mid-call). The naive `match read(buf) { 0, 4, n }` pattern
        // wrongly classifies a 3-byte short-read as a truncated
        // segment, which a proptest run with many records reliably
        // triggers around the 8 KiB BufReader boundary.
        let mut length_bytes = [0u8; 4];
        if !read_exact_or_eof(&mut self.file, &mut length_bytes)? {
            return Ok(None); // clean EOF, no more records
        }
        let length = u32::from_be_bytes(length_bytes) as usize;

        // Counter.
        let mut counter_le = [0u8; 4];
        self.file.read_exact(&mut counter_le)?;
        let counter = u32::from_le_bytes(counter_le);

        // Framing-level monotonicity check. The AEAD alone cannot catch a
        // record-swap attack that preserves each record's own counter
        // field (the AD remains internally consistent with the
        // ciphertext). This invariant catches it: if the on-disk counter
        // doesn't match the position the reader expects to be reading,
        // the segment has been re-shuffled.
        if counter != self.expected_counter {
            return Err(Error::OutOfOrder {
                expected: self.expected_counter,
                got: counter,
            });
        }

        // Payload (ciphertext + 16-byte tag).
        let mut payload = vec![0u8; length];
        self.file.read_exact(&mut payload).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Truncated {
                    declared: length as u64,
                    available: 0,
                }
            } else {
                Error::Io(e)
            }
        })?;

        // Reconstruct nonce + AD.
        let nonce_bytes = self.subkey.nonce_for_record(counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ad = [0u8; 12];
        ad[..8].copy_from_slice(&self.subkey.segment_id().to_le_bytes());
        ad[8..].copy_from_slice(&counter_le);

        let plaintext = self
            .cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &payload,
                    aad: &ad,
                },
            )
            .map_err(|_| Error::AuthFailed)?;

        // Advance the expected position only after a successful read.
        // On any error path (Truncated, OutOfOrder, AuthFailed) we leave
        // expected_counter untouched so the iterator can be inspected
        // post-mortem to know exactly where the corruption began.
        self.expected_counter = self
            .expected_counter
            .checked_add(1)
            .ok_or(Error::Invariant("reader expected_counter overflow"))?;

        Ok(Some(plaintext))
    }
}

/// Fill `buf` exactly, OR return `Ok(false)` if the stream is at EOF
/// before any byte has been read. Returns `Err(Truncated)` if the
/// stream ends mid-buffer (i.e., a partial record).
///
/// This is the right primitive for "is there another record, and if
/// so, decode it" loops: vanilla `read_exact` collapses both cases
/// into `UnexpectedEof`, and vanilla `read` may return fewer bytes
/// than requested even outside EOF (BufReader buffer boundary).
fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 if total == 0 => return Ok(false), // clean EOF
            0 => {
                return Err(Error::Truncated {
                    declared: buf.len() as u64,
                    available: total as u64,
                })
            }
            n => total += n,
        }
    }
    Ok(true)
}

pub struct RecordIter<'a> {
    reader: &'a mut LogSegmentReader,
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_one() {
            Ok(Some(record)) => Some(Ok(record)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn dummy_master() -> MasterLogKey {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        MasterLogKey::from_bytes(k)
    }

    #[test]
    fn roundtrip_single_record() {
        let dir = TempDir::new().unwrap();
        let master = dummy_master();

        let mut w = LogSegmentWriter::new(dir.path(), &master, 0).unwrap();
        w.append(b"hello, sigillum").unwrap();
        let path = w.path().to_path_buf();
        w.finalize().unwrap();

        let mut r = LogSegmentReader::open(&path, &master).unwrap();
        let recs: Vec<_> = r.records().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0], b"hello, sigillum");
    }

    #[test]
    fn roundtrip_many_records() {
        let dir = TempDir::new().unwrap();
        let master = dummy_master();
        let mut w = LogSegmentWriter::new(dir.path(), &master, 1).unwrap();
        for i in 0..256 {
            w.append(format!("record-{}", i).as_bytes()).unwrap();
        }
        let path = w.path().to_path_buf();
        w.finalize().unwrap();

        let mut r = LogSegmentReader::open(&path, &master).unwrap();
        let recs: Vec<_> = r.records().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(recs.len(), 256);
        for (i, rec) in recs.iter().enumerate() {
            assert_eq!(rec, format!("record-{}", i).as_bytes());
        }
    }

    #[test]
    fn rejects_plaintext_v0_3_log() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, b"{\"record\":\"alert\",\"severity\":\"alpha\"}\n").unwrap();
        let master = dummy_master();
        let err = LogSegmentReader::open(&path, &master).unwrap_err();
        assert!(matches!(err, Error::InvalidMagic), "got {:?}", err);
    }

    #[test]
    fn rejects_wrong_master_key() {
        let dir = TempDir::new().unwrap();
        let master_a = dummy_master();
        let mut w = LogSegmentWriter::new(dir.path(), &master_a, 0).unwrap();
        w.append(b"sealed by A").unwrap();
        let path = w.path().to_path_buf();
        w.finalize().unwrap();

        let mut bytes = [0u8; 32];
        bytes[31] = 0xFF;
        let master_b = MasterLogKey::from_bytes(bytes);
        let err = LogSegmentReader::open(&path, &master_b).unwrap_err();
        assert!(matches!(err, Error::KeyIdMismatch { .. }), "got {:?}", err);
    }

    #[test]
    fn detects_record_tamper() {
        let dir = TempDir::new().unwrap();
        let master = dummy_master();
        let mut w = LogSegmentWriter::new(dir.path(), &master, 0).unwrap();
        w.append(b"alpha alert original").unwrap();
        let path = w.path().to_path_buf();
        w.finalize().unwrap();

        // Flip a byte deep inside the record area (past header, past
        // length+counter prefix). HEADER_LEN=40, RECORD_OVERHEAD=24,
        // so byte 64 is mid-ciphertext.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[64] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        let mut r = LogSegmentReader::open(&path, &master).unwrap();
        let res: Result<Vec<_>> = r.records().collect();
        assert!(matches!(res, Err(Error::AuthFailed)), "got {:?}", res);
    }

    #[test]
    fn detects_record_swap() {
        // Sealing two different records and then physically swapping
        // them in the file MUST fail. The defense is the framing-level
        // monotonicity check on the on-disk counter -- the AEAD alone
        // would happily decrypt a swapped record, because the swap
        // preserves each record's internal (counter, nonce, AD)
        // consistency. The reader's `expected_counter` invariant is
        // what catches the reordering.
        let dir = TempDir::new().unwrap();
        let master = dummy_master();
        let mut w = LogSegmentWriter::new(dir.path(), &master, 0).unwrap();
        w.append(b"AAAAAAAAAAAAAAAA").unwrap();
        w.append(b"BBBBBBBBBBBBBBBB").unwrap();
        let path = w.path().to_path_buf();
        w.finalize().unwrap();

        let bytes = std::fs::read(&path).unwrap();
        // Each record on disk: 4 (length) + 4 (counter) + 32 (16 ciphertext + 16 tag) = 40 bytes.
        let r1_start = HEADER_LEN;
        let r2_start = r1_start + 40;
        let mut swapped = bytes.clone();
        swapped[r1_start..r1_start + 40].copy_from_slice(&bytes[r2_start..r2_start + 40]);
        swapped[r2_start..r2_start + 40].copy_from_slice(&bytes[r1_start..r1_start + 40]);
        std::fs::write(&path, &swapped).unwrap();

        let mut r = LogSegmentReader::open(&path, &master).unwrap();
        let res: Result<Vec<_>> = r.records().collect();
        assert!(
            matches!(res, Err(Error::OutOfOrder { expected: 0, got: 1 })),
            "got {:?}",
            res
        );
    }

    #[test]
    fn rotation_threshold_triggers() {
        let dir = TempDir::new().unwrap();
        let master = dummy_master();
        // Tiny cap to test rotation logic without writing a real 10 MiB.
        let mut w = LogSegmentWriter::new_with_cap(dir.path(), &master, 0, 100).unwrap();
        for _ in 0..5 {
            w.append(b"some twenty-five bytes...").unwrap();  // 25 bytes each
        }
        assert!(w.should_rotate(), "should rotate after 125 plaintext bytes (cap=100)");
        assert_eq!(w.record_count(), 5);
        assert_eq!(w.plaintext_bytes(), 125);
        w.finalize().unwrap();
    }

    #[test]
    fn rotation_threshold_inactive_below_cap() {
        let dir = TempDir::new().unwrap();
        let master = dummy_master();
        let mut w = LogSegmentWriter::new_with_cap(dir.path(), &master, 0, 1000).unwrap();
        w.append(b"only-fifty-bytes-ish-of-text-to-stay-under-cap-OK").unwrap();
        assert!(!w.should_rotate());
        w.finalize().unwrap();
    }

    #[test]
    fn segment_header_parses_correctly() {
        let dir = TempDir::new().unwrap();
        let master = dummy_master();
        let w = LogSegmentWriter::new(dir.path(), &master, 0xCAFEBABE).unwrap();
        let path = w.path().to_path_buf();
        w.finalize().unwrap();

        let r = LogSegmentReader::open(&path, &master).unwrap();
        let h = r.header();
        assert_eq!(h.segment_id, 0xCAFEBABE);
        assert_eq!(h.master_key_id, master.id());
    }

    #[test]
    fn refuses_to_overwrite_existing_segment() {
        let dir = TempDir::new().unwrap();
        let master = dummy_master();
        let _w1 = LogSegmentWriter::new(dir.path(), &master, 0).unwrap();
        // Drop _w1 without finalize -- the file is still on disk with magic.
        let res = LogSegmentWriter::new(dir.path(), &master, 0);
        assert!(res.is_err(), "should refuse to overwrite existing segment file");
    }
}
