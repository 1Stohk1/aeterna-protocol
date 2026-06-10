//! AETERNA v0.5.0 "Consensus" Phase D — remote shipper for encrypted
//! `.sigillum` audit-log segments.
//!
//! ## Purpose
//!
//! Sigillum Phase A (v0.4) makes the audit log unreadable to anyone
//! without the BIP-39 master seed. That is the *confidentiality*
//! guarantee. It says nothing about *durability*: a host that loses
//! its disk loses its audit trail.
//!
//! This crate adds durability without weakening confidentiality.
//! Finalized `.sigillum` segments are pushed off-host to an
//! operator-controlled HTTP(S) endpoint. The local file remains the
//! source of truth; the remote copy is a best-effort backup the
//! operator can read back later via a separate decryption pass with
//! the same BIP-39 seed.
//!
//! ## What this crate is
//!
//! * **Configuration types** ([`config::ShipperConfig`]) for the
//!   `[shipper]` section of `aeterna.toml` — endpoint URL, cert pin,
//!   poll cadence, back-off thresholds.
//! * **Segment discovery** ([`segments::find_finalized`]) — walks the
//!   audit dir and lists `.sigillum` files in segment-id order.
//! * **Push state machine** ([`state`] — TODO, next commit) tracking
//!   per-segment push status (pending / pushed / failed) via a
//!   sidecar `.pushed` marker file.
//! * **HTTP client** ([`client`] — TODO, next commit) doing the
//!   actual `POST <endpoint>/<segment_id>.sigillum` with cert pin
//!   verification.
//!
//! ## What this crate is NOT
//!
//! * **Not a re-encryption layer.** The segment bytes already carry
//!   ChaCha20-Poly1305 sealing. The shipper passes them through.
//!   TLS provides transport-level confidentiality on top.
//! * **Not a gossip relay.** Segments do NOT travel through the v0.4
//!   UDP gossip mesh. The shipper talks to a single operator endpoint.
//! * **Not coupled to the signer.** A shipper failure does NOT
//!   suspend the signer or block signing (sprint AC #6). The signer
//!   does not even know whether the shipper is running.
//!
//! ## Hard invariants
//!
//! 1. The shipper NEVER deletes a local segment. Operator-controlled
//!    rotation is a separate concern (manual `Remove-Item`, log
//!    rotation tool, etc).
//! 2. The shipper NEVER reads the segment plaintext. It opens the
//!    file as raw bytes, validates the Sigillum-v1 header (so we
//!    don't ship random files that happened to land in the dir),
//!    and POSTs the unchanged content.
//! 3. A cert pin mismatch is a HARD STOP. The shipper refuses to
//!    speak to an endpoint whose TLS leaf cert SHA-256 does not
//!    match `aeterna.toml [shipper] endpoint_pin_sha256`. Operator
//!    must explicitly rotate the pin via `santuarioctl ship deploy
//!    --pin <new-sha256>` after verifying out-of-band.

pub mod config;
pub mod error;
pub mod segments;
pub mod client;
pub mod state;

#[cfg(test)]
mod mock_cert_data;

pub use config::ShipperConfig;
pub use error::{Error, Result};
pub use segments::{find_finalized, SegmentInfo};
pub use client::build_pinned_client;
pub use state::Shipper;

