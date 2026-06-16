//! AETERNA v0.4.0 "Sigillum" — operator-endpoint ratchet (Phase C).
//!
//! This crate carries the cryptographic envelope for the channel
//! between the **operator client** (santuarioctl, the War Room
//! sidebar, the Telegram bot) and the **signer** (santuario-signer's
//! Admin gRPC). Phase A protects the audit log on disk; Phase B
//! protects gossip on the wire; Phase C protects the gRPC stream the
//! operator personally rides.
//!
//! ## Threat model
//!
//! * Read-only network capture (LAN sniff, on-path proxy): defeated.
//!   ChaCha20-Poly1305 over X25519-derived session keys.
//! * Active network capture that replays past frames: defeated by the
//!   per-message counter inside the AEAD AAD plus the
//!   `expected_counter` framing-level guard the receiver applies.
//! * Compromise of one ratchet step's session key: prior steps remain
//!   opaque (HKDF one-wayness). Future steps remain opaque so long as
//!   the previous step's session_key was zeroized on schedule -- which
//!   we do, via `ZeroizeOnDrop`.
//! * Compromise of the signer's long-term X25519 identity key: total
//!   loss of forward secrecy for any future session opened against
//!   that identity. Operator must rotate the identity (file replace
//!   + redistribute pubkey out-of-band).
//! * Operator's ephemeral key is single-use (per-handshake) and
//!   `ZeroizeOnDrop`. A compromise of one operator session does NOT
//!   reveal the long-term identity nor any prior session.
//!
//! ## Hard invariants
//!
//! 1. The same `(session_key, nonce)` pair is NEVER used to seal two
//!    distinct messages. Counter is asserted-monotonic per session and
//!    saturates at u32::MAX - 1024.
//! 2. A `Session` in the `Tombstone` state refuses every encrypt /
//!    decrypt call; the only legal transition out is a fresh
//!    handshake (which constructs a brand-new `Session`).
//! 3. The signer's long-term X25519 identity NEVER appears in
//!    `Debug`-printed output -- both the secret and the wrapper type
//!    have hand-redacted impls.
//! 4. After a rekey via `Session::step`, the previous step's
//!    `session_key` is `zeroize`d before the next encrypt is allowed.
//!
//! ## State machine
//!
//! ```text
//!     OperatorEndpoint::handshake_request()
//!                     │
//!                     ▼
//!         ┌──────────────────────┐
//!         │ Initial / waiting on │
//!         │ signer response      │
//!         └──────────────────────┘
//!                     │ finalize(signer_response)
//!                     ▼
//!         ┌──────────────────────────┐
//!         │ Established              │ ◀────── encrypt / decrypt
//!         │   session_key            │           (counter-bound)
//!         │   counter, started_at    │
//!         │   msgs_in_session        │
//!         └──────────────────────────┘
//!                     │
//!                     │ step()  (every 600s OR 1024 msgs)
//!                     ▼
//!         ┌──────────────────────────┐
//!         │ Established (next step)  │
//!         │   new session_key        │
//!         │   counter = 0            │
//!         └──────────────────────────┘
//!
//!         ANY decrypt path that fails authentication 3x consecutive
//!                     │
//!                     ▼
//!         ┌──────────────────────────┐
//!         │ Tombstone                │
//!         │   refuses all ops        │
//!         │   only escape: fresh     │
//!         │   handshake from caller  │
//!         └──────────────────────────┘
//! ```
//!
//! ## Wire format
//!
//! ### Handshake messages
//! ```text
//! Request:  [ver=0x01][operator_eph_pub: 32 bytes]            (33 bytes)
//! Response: [ver=0x01][signer_eph_pub: 32 bytes]              (33 bytes)
//! ```
//!
//! ### Sealed messages
//! ```text
//! [ver=0x10][step_counter: 4 bytes BE][nonce_seq: 4 bytes BE][ciphertext+tag]
//! ```
//! Header (10 bytes) is the AEAD AAD.

pub mod bip39_derive;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod session;
pub mod p2p_handshake;

pub use bip39_derive::{derive_from_mnemonic, parse_mnemonic, SigillumKeys};
pub use error::{Error, Result};
pub use handshake::{HandshakeRequest, HandshakeResponse, OperatorEndpoint, SignerEndpoint};
pub use identity::{SignerIdentityKey, SignerIdentityPublic};
pub use session::{Session, SessionOptions, SessionStatus, Side};
pub use p2p_handshake::{
    P2PHandshakeRequest, P2PHandshakeResponse, P2PInitiator, P2PResponder,
    KYBER_PUB_LEN, KYBER_CT_LEN,
};


/// Wire-format version for handshake messages. Bumping this is a
/// coordinated upgrade across operator + signer.
pub const HANDSHAKE_VERSION: u8 = 0x01;

/// Wire-format version for sealed messages. Distinct from the gossip
/// `0x04` (Phase B) so a multiplexer at the gRPC boundary can
/// fast-reject misrouted frames without allocating decryption state.
pub const SEALED_VERSION: u8 = 0x10;

/// Default ratchet step thresholds. Confirmed in SPRINT-v0.4.0 §3
/// Phase C: 600s of wall-clock OR 1024 sealed messages, whichever
/// trips first.
pub const DEFAULT_STEP_MAX_SECONDS: f64 = 600.0;
pub const DEFAULT_STEP_MAX_MESSAGES: u32 = 1024;

/// Tombstone trigger: this many consecutive AuthFailed before the
/// session refuses further operation. Confirmed at 3 — tolerant of
/// a single corrupted/dup'd packet on a noisy LAN, but unambiguous
/// when an active replay attack is in progress.
pub const TOMBSTONE_AUTHFAIL_THRESHOLD: u32 = 3;
