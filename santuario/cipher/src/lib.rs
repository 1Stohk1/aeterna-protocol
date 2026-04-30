//! AETERNA v0.4.0 "Sigillum" -- authenticated-encryption layer.
//!
//! This crate is the cryptographic envelope for two surfaces:
//!
//! * **Audit log** (Phase A): every record is a ChaCha20-Poly1305
//!   sealed payload, written to segmented files capped at 10 MiB
//!   plaintext. Per-segment subkeys are HKDF-derived from a single
//!   master log key so a key-rotation operation only requires
//!   re-derivation, not re-encryption of historical segments.
//! * **Gossip channel** (Phase B, separate API in this crate): each
//!   frame carries a session_id + monotonic nonce, decryptable with a
//!   session key HKDF-derived from a long-lived gossip root key.
//!
//! ## Threat model
//!
//! * Attacker with read-only filesystem access: defeated for both
//!   audit log on disk and operator-endpoint config (key envelope).
//! * Attacker with full network capture: defeated for gossip frames
//!   (forward-secret per session) and for the operator-endpoint
//!   gRPC stream (Phase C, separate crate `santuario-ratchet`).
//! * Attacker with concurrent process on the same host: NOT defeated
//!   here. That is the seccomp/Firecracker layer's responsibility.
//! * Attacker with the operator's BIP-39 seed: defeated only by the
//!   operator's physical security of their seed backup.
//!
//! ## Hard invariants
//!
//! 1. A `(key, nonce)` pair is NEVER reused across two distinct
//!    plaintexts. The segment manager enforces this with a runtime
//!    counter and a property-based test in `tests/`.
//! 2. The magic header `SIGILLUM-v1\0\0\0\0\0` is mandatory at every
//!    segment start. Files without it are rejected
//!    (`Error::InvalidMagic`) -- "cesura netta" per
//!    SPRINT-v0.4.0 §7.1.
//! 3. The master key never leaves the process address space in
//!    plaintext. `MasterLogKey` is `Zeroize` and refuses to be
//!    `Debug`-printed without redaction.

pub mod error;
pub mod keys;
pub mod segment;

pub use error::{Error, Result};
pub use keys::{MasterKeyId, MasterLogKey, SegmentSubKey};
pub use segment::{
    LogSegmentReader, LogSegmentWriter, SegmentHeader, DEFAULT_MAX_PLAINTEXT_BYTES, SEGMENT_MAGIC,
};
