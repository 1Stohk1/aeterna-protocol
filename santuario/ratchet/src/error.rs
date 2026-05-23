//! Error types for the operator-endpoint ratchet (Phase C).
//!
//! Every variant is callable-meaningful: santuarioctl, the War Room,
//! and the Telegram bot all match on the variant to decide whether to
//! retry, re-handshake, or escalate.

use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem or stream IO. Usually transient (disk full, broken
    /// pipe). Caller may retry.
    #[error("io: {0}")]
    Io(#[from] io::Error),

    /// Wire frame is shorter than the fixed header for its kind
    /// (handshake or sealed message). Likely a truncated UDP/gRPC
    /// payload. Drop, log, retry on next message.
    #[error("frame too short: got {got} bytes, need >= {need}")]
    FrameTooShort { got: usize, need: usize },

    /// First byte of the wire frame is not a known Sigillum-ratchet
    /// version. Either a stale operator binary or someone fuzzing
    /// the gRPC port. Refuse silently.
    #[error("unsupported wire version: 0x{0:02x}")]
    UnsupportedVersion(u8),

    /// HKDF expand or other KDF primitive failed. Indicates a build
    /// misconfig (absurd OKM length); never user-actionable.
    #[error("key derivation failed: {0}")]
    Kdf(&'static str),

    /// AEAD authentication failed. The frame was tampered with, or
    /// the session_key is wrong (typically: counterparty in a
    /// different ratchet step, or replay across a session boundary).
    /// Triggers the tombstone counter on the receiver.
    #[error("authentication tag invalid -- ciphertext corrupted, replay, or step desync")]
    AuthFailed,

    /// On-disk counter on a sealed message does not match the
    /// receiver's expected position. Catches whole-message reordering
    /// attacks that the AEAD alone would not detect.
    #[error("message out of order: expected counter {expected}, got {got}")]
    OutOfOrder { expected: u32, got: u32 },

    /// The session has tombstoned (3 consecutive AuthFailed events).
    /// Caller MUST trigger a fresh handshake to recover; no in-place
    /// continuation is possible.
    #[error("session is tombstoned -- a fresh handshake is required")]
    SessionTombstoned,

    /// Counter neared u32::MAX before the natural ratchet step caught
    /// up. This is an internal sanity check; in normal operation the
    /// step trigger fires long before counter saturation.
    #[error("session counter saturated -- caller failed to invoke step()")]
    CounterSaturated,

    /// SignerIdentityKey on disk is the wrong length. Same semantics
    /// as the audit log master key: refuse to silently regenerate;
    /// the operator must reconcile manually.
    #[error("signer identity key file at {path} has wrong length: {got} bytes (expected 32)")]
    InvalidIdentityKeyFile { path: String, got: usize },

    /// Handshake response carries an unexpected schema version. Same
    /// vector as `UnsupportedVersion` but at the handshake layer
    /// specifically -- distinguished so the operator-side can surface
    /// "your signer is too old / too new" with precision.
    #[error("handshake version mismatch: peer sent 0x{got:02x}, expected 0x{expected:02x}")]
    HandshakeVersionMismatch { got: u8, expected: u8 },

    /// X25519 public key bytes failed to deserialize (wrong length,
    /// or otherwise malformed). x25519-dalek validates points on
    /// construction; this surface lets us propagate that.
    #[error("malformed X25519 public key (32 bytes expected)")]
    MalformedPublicKey,

    /// BIP-39 mnemonic parsing failed. Typically: unknown word, wrong
    /// checksum, wrong word count. Operator must re-check their phrase.
    #[error("bip39 mnemonic invalid: {0}")]
    Bip39(String),

    /// Internal invariant violation. Indicates a bug in this crate;
    /// caller should HALT immediately.
    #[error("internal Sigillum-ratchet invariant violated: {0}")]
    Invariant(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;
