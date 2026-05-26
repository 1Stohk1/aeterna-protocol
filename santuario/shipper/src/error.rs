//! Error types for the shipper.
//!
//! Every variant is callable-meaningful — santuarioctl's `ship`
//! subcommand matches on the variant to decide whether to retry,
//! escalate to alpha, or surface a config-fix prompt to the operator.

use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem IO. Usually transient (file just rotated, permission
    /// hiccup). Caller may retry the segment scan.
    #[error("io: {0}")]
    Io(#[from] io::Error),

    /// `[shipper]` section of `aeterna.toml` is malformed or missing a
    /// required field (`endpoint_url`, `endpoint_pin_sha256` when
    /// `enabled = true`). Operator must edit the toml; no retry.
    #[error("shipper config invalid: {0}")]
    Config(String),

    /// A file in the segment dir looked like `.sigillum` but did not
    /// carry the Sigillum-v1 magic header. The shipper refuses to
    /// push it — that is not our data.
    #[error("segment {path} is not a Sigillum-v1 file (bad header)")]
    NotASegment { path: String },

    /// The endpoint URL in `aeterna.toml` is syntactically invalid
    /// (not parseable as a URL). Operator must edit the toml.
    #[error("endpoint url invalid: {0}")]
    InvalidEndpointUrl(String),

    /// The endpoint cert pin is not a 64-char hex string (i.e. not a
    /// 32-byte SHA-256). Operator must re-fetch the pin and update
    /// `aeterna.toml [shipper] endpoint_pin_sha256`.
    #[error("endpoint cert pin must be 64 hex chars (32-byte SHA-256), got: {0}")]
    InvalidCertPin(String),

    /// The cert pin negotiated during the TLS handshake does not match
    /// the configured pin. Hard stop — the shipper refuses to push.
    /// Operator must verify the endpoint identity out-of-band before
    /// rotating the pin.
    #[error("cert pin mismatch: expected {expected}, observed {observed}")]
    CertPinMismatch { expected: String, observed: String },

    /// HTTP transport failure (DNS, connect, TLS, 5xx). Retryable
    /// per the configured back-off policy.
    #[error("transport: {0}")]
    Transport(String),

    /// HTTP 4xx from the remote endpoint. Caller should NOT retry —
    /// the endpoint is rejecting the request (bad auth, payload too
    /// large, etc). Operator must reconcile manually.
    #[error("remote rejected push: HTTP {status} -- {body}")]
    RemoteRejected { status: u16, body: String },

    /// `santuarioctl ship verify` HEAD'ed the remote URL and the
    /// reported SHA-256 did not match the local file's SHA-256.
    /// Indicates either a partial upload or remote-side corruption.
    #[error(
        "remote segment {segment_id} digest mismatch: local={local_sha256} remote={remote_sha256}"
    )]
    VerifyMismatch {
        segment_id: u64,
        local_sha256: String,
        remote_sha256: String,
    },
}

pub type Result<T> = std::result::Result<T, Error>;
