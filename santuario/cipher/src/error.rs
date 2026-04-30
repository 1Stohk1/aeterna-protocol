//! Error types for the Sigillum cipher layer.
//!
//! Every variant is callable-meaningful: callers (santuario-integrity,
//! santuario-signer admin, santuarioctl tail) match on the variant to
//! decide between "operator misconfiguration" (retry with different
//! input), "key compromise" (escalate to recovery), and "data
//! corruption" (alert + halt).

use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem or stream IO. Usually transient (disk full, broken
    /// pipe). Caller may retry.
    #[error("io: {0}")]
    Io(#[from] io::Error),

    /// File does not start with the SIGILLUM-v1 magic header. The
    /// "cesura netta" boundary: plaintext logs from v0.3.0 hit this.
    /// Caller should NOT retry; operator should archive or delete the
    /// file out-of-band.
    #[error("not a Sigillum-v1 segment (magic header missing or wrong)")]
    InvalidMagic,

    /// Header parsed but the master_key_id_hash inside it does not
    /// match the master key currently held. Either the operator
    /// imported the wrong seed, or the segment was sealed with a key
    /// that has since been rotated and is no longer in the active
    /// keyring.
    #[error("segment was sealed with key id {expected:?}, current key id is {actual:?}")]
    KeyIdMismatch {
        expected: [u8; 16],
        actual: [u8; 16],
    },

    /// AEAD authentication failed. EITHER the ciphertext was tampered
    /// with on disk OR the wrong key is being used. The cipher layer
    /// cannot distinguish; santuarioctl tail surfaces a "wrong key?"
    /// hint to the operator.
    #[error("authentication tag invalid -- ciphertext corrupted or wrong key")]
    AuthFailed,

    /// Internal invariant violation. Indicates a bug in the segment
    /// manager (nonce counter overflow, malformed length-prefix). The
    /// caller should HALT immediately and the operator should
    /// snapshot the segment for forensic analysis.
    #[error("internal Sigillum invariant violated: {0}")]
    Invariant(&'static str),

    /// Record length prefix declares more bytes than the segment file
    /// contains. Either truncation (mid-write crash) or deliberate
    /// tampering. Treated as fatal for the segment.
    #[error("truncated segment: declared {declared} bytes but only {available} available")]
    Truncated { declared: u64, available: u64 },

    /// The on-disk record counter does not match the reader's expected
    /// position. Catches whole-record reordering attacks that the AEAD
    /// alone would not detect (a swapped record still decrypts cleanly
    /// because its counter field remains consistent with its
    /// ciphertext). The reader treats this as a fatal segment-level
    /// integrity violation -- iteration halts.
    #[error("record counter out of order: expected {expected}, got {got}")]
    OutOfOrder { expected: u32, got: u32 },

    /// HKDF expansion or other key-derivation primitive failed.
    /// Typically only happens if the requested OKM length is absurd
    /// (>255 hash blocks); the segment manager never asks for that
    /// much, so seeing this in the wild means a build-config bug.
    #[error("key derivation failed: {0}")]
    Kdf(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
