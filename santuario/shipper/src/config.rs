//! Parsing for the `[shipper]` section of `aeterna.toml`.
//!
//! The shipper is opt-in: a fresh v0.5.0 install has `enabled = false`
//! and the operator must explicitly point at a remote endpoint before
//! any bytes leave the host. This mirrors the v0.3 Telegram-bot
//! zero-trust-default: a node that does not know who to ship to ships
//! to nobody.

use serde::Deserialize;

use crate::error::{Error, Result};

/// Default poll cadence: every 30 s scan the audit dir for new segments.
pub const DEFAULT_POLL_INTERVAL_SECONDS: u64 = 30;

/// Default exponential back-off floor when a push fails.
pub const DEFAULT_BACK_OFF_SECONDS: u64 = 60;

/// Default number of retries before a segment is marked `.failed`.
pub const DEFAULT_MAX_RETRIES_PER_SEGMENT: u32 = 5;

/// Cert pin length in raw bytes (SHA-256 = 32 bytes = 64 hex chars).
pub const CERT_PIN_HEX_LEN: usize = 64;

/// Parsed `[shipper]` section. See `aeterna.toml` Phase F additions
/// for the operator-facing field documentation.
#[derive(Debug, Clone, Deserialize)]
pub struct ShipperConfig {
    /// Master enable switch. False means the shipper thread is not
    /// spawned at all — the audit log lives entirely on the local disk.
    #[serde(default)]
    pub enabled: bool,

    /// URL like `https://archive.example.com/segments`. The shipper
    /// POSTs each segment to `<endpoint_url>/<segment_id>.sigillum`.
    #[serde(default)]
    pub endpoint_url: String,

    /// SHA-256 of the endpoint's TLS leaf cert, 64 hex chars. The
    /// shipper aborts the TLS handshake if the observed cert hash
    /// differs. Operator gets the initial pin out-of-band (e.g. via
    /// `openssl s_client | openssl x509 -fingerprint -sha256`).
    #[serde(default)]
    pub endpoint_pin_sha256: String,

    #[serde(default = "default_poll_interval_seconds")]
    pub poll_interval_seconds: u64,

    #[serde(default = "default_back_off_seconds")]
    pub back_off_seconds: u64,

    #[serde(default = "default_max_retries_per_segment")]
    pub max_retries_per_segment: u32,
}

fn default_poll_interval_seconds() -> u64 {
    DEFAULT_POLL_INTERVAL_SECONDS
}
fn default_back_off_seconds() -> u64 {
    DEFAULT_BACK_OFF_SECONDS
}
fn default_max_retries_per_segment() -> u32 {
    DEFAULT_MAX_RETRIES_PER_SEGMENT
}

impl Default for ShipperConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint_url: String::new(),
            endpoint_pin_sha256: String::new(),
            poll_interval_seconds: DEFAULT_POLL_INTERVAL_SECONDS,
            back_off_seconds: DEFAULT_BACK_OFF_SECONDS,
            max_retries_per_segment: DEFAULT_MAX_RETRIES_PER_SEGMENT,
        }
    }
}

impl ShipperConfig {
    /// Parse the `[shipper]` table out of a full `aeterna.toml` body.
    /// Returns `Ok(default)` when the section is missing — that is the
    /// natural "shipper disabled" path for nodes that have not yet
    /// opted in.
    pub fn from_aeterna_toml(text: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct Outer {
            #[serde(default)]
            shipper: Option<ShipperConfig>,
        }
        let outer: Outer = toml::from_str(text)
            .map_err(|e| Error::Config(format!("toml parse: {e}")))?;
        Ok(outer.shipper.unwrap_or_default())
    }

    /// Stronger validation pass applied only when `enabled = true`.
    /// Catches blank URLs, malformed pins, absurd cadences before the
    /// shipper thread starts. Disabled-config never reaches this path.
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.endpoint_url.trim().is_empty() {
            return Err(Error::Config(
                "endpoint_url is required when enabled = true".into(),
            ));
        }
        if !self.endpoint_url.starts_with("https://") {
            return Err(Error::Config(format!(
                "endpoint_url must be https:// (got {}). Sigillum forbids \
                 plaintext shipper transport.",
                self.endpoint_url
            )));
        }
        if self.endpoint_pin_sha256.len() != CERT_PIN_HEX_LEN {
            return Err(Error::InvalidCertPin(format!(
                "expected {} hex chars, got {}",
                CERT_PIN_HEX_LEN,
                self.endpoint_pin_sha256.len()
            )));
        }
        if hex::decode(&self.endpoint_pin_sha256).is_err() {
            return Err(Error::InvalidCertPin(format!(
                "not valid hex: {}",
                self.endpoint_pin_sha256
            )));
        }
        if self.poll_interval_seconds == 0 {
            return Err(Error::Config(
                "poll_interval_seconds must be > 0".into(),
            ));
        }
        if self.max_retries_per_segment == 0 {
            return Err(Error::Config(
                "max_retries_per_segment must be > 0".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_section_is_default_disabled() {
        let cfg = ShipperConfig::from_aeterna_toml("[other]\nx = 1\n").unwrap();
        assert!(!cfg.enabled);
        assert!(cfg.endpoint_url.is_empty());
        // Default cadence still populated.
        assert_eq!(cfg.poll_interval_seconds, DEFAULT_POLL_INTERVAL_SECONDS);
    }

    #[test]
    fn parses_minimal_enabled_config() {
        let toml = r#"
            [shipper]
            enabled = true
            endpoint_url = "https://archive.example.com/segments"
            endpoint_pin_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        "#;
        let cfg = ShipperConfig::from_aeterna_toml(toml).unwrap();
        assert!(cfg.enabled);
        cfg.validate().expect("minimal config must validate");
    }

    #[test]
    fn validate_rejects_blank_url_when_enabled() {
        let cfg = ShipperConfig {
            enabled: true,
            endpoint_url: String::new(),
            endpoint_pin_sha256: "ab".repeat(32),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, Error::Config(msg) if msg.contains("endpoint_url")));
    }

    #[test]
    fn validate_rejects_http_url() {
        let cfg = ShipperConfig {
            enabled: true,
            endpoint_url: "http://archive.example.com".into(),
            endpoint_pin_sha256: "ab".repeat(32),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, Error::Config(msg) if msg.contains("https://")));
    }

    #[test]
    fn validate_rejects_short_pin() {
        let cfg = ShipperConfig {
            enabled: true,
            endpoint_url: "https://archive.example.com".into(),
            endpoint_pin_sha256: "abcd".into(),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, Error::InvalidCertPin(_)));
    }

    #[test]
    fn validate_rejects_non_hex_pin() {
        let cfg = ShipperConfig {
            enabled: true,
            endpoint_url: "https://archive.example.com".into(),
            // 64 chars but the 'z' makes it non-hex.
            endpoint_pin_sha256: "z".repeat(64),
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, Error::InvalidCertPin(_)));
    }

    #[test]
    fn disabled_config_skips_validation() {
        // Even with garbage url/pin, validation is a no-op when disabled.
        let cfg = ShipperConfig {
            enabled: false,
            endpoint_url: "ftp://nope".into(),
            endpoint_pin_sha256: "not-hex-not-64-chars".into(),
            ..Default::default()
        };
        cfg.validate().expect("disabled config bypasses validation");
    }

    #[test]
    fn validate_rejects_zero_poll_interval() {
        let cfg = ShipperConfig {
            enabled: true,
            endpoint_url: "https://archive.example.com".into(),
            endpoint_pin_sha256: "ab".repeat(32),
            poll_interval_seconds: 0,
            ..Default::default()
        };
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, Error::Config(msg) if msg.contains("poll_interval_seconds")));
    }
}
