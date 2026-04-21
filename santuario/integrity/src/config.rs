//! Parse the `[integrity]` section of `aeterna.toml`.
//!
//! The section enumerates the file set the α sweep hashes and publishes
//! operational parameters for β and γ. Example:
//!
//! ```toml
//! [integrity]
//! # α — hourly file set
//! interval_minutes       = 60
//! files = [
//!   "MANIFESTO.md",
//!   "aeterna.toml",
//!   "santuario/vault/manifest.json",
//!   "scientific/Manifest.toml",
//! ]
//!
//! # β — CPU stress window
//! cpu_threshold_pct      = 90.0
//! cpu_window_seconds     = 600
//!
//! # γ — port-scan detection
//! portscan_abort_count   = 3
//! portscan_window_seconds = 3600
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::IntegrityError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntegrityConfig {
    /// α — sweep interval in minutes. Must be ≥ 1.
    #[serde(default = "default_interval_minutes")]
    pub interval_minutes: u64,

    /// α — paths that MUST exist and MUST not change in-flight.
    #[serde(default)]
    pub files: Vec<PathBuf>,

    /// β — average CPU% over the window above which the β alert fires.
    #[serde(default = "default_cpu_threshold")]
    pub cpu_threshold_pct: f32,

    /// β — sliding window in seconds over which CPU% is averaged.
    #[serde(default = "default_cpu_window")]
    pub cpu_window_seconds: u64,

    /// γ — number of distinct unsolicited port scans within the window
    /// that will trip the γ alert.
    #[serde(default = "default_portscan_count")]
    pub portscan_abort_count: u32,

    /// γ — window length in seconds.
    #[serde(default = "default_portscan_window")]
    pub portscan_window_seconds: u64,
}

fn default_interval_minutes() -> u64 {
    60
}
fn default_cpu_threshold() -> f32 {
    90.0
}
fn default_cpu_window() -> u64 {
    600
}
fn default_portscan_count() -> u32 {
    3
}
fn default_portscan_window() -> u64 {
    3600
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            interval_minutes: default_interval_minutes(),
            files: Vec::new(),
            cpu_threshold_pct: default_cpu_threshold(),
            cpu_window_seconds: default_cpu_window(),
            portscan_abort_count: default_portscan_count(),
            portscan_window_seconds: default_portscan_window(),
        }
    }
}

/// Parse just the `[integrity]` table out of an aeterna.toml. Missing
/// table yields [`IntegrityConfig::default`].
pub fn load_from_toml(text: &str) -> Result<IntegrityConfig, IntegrityError> {
    #[derive(Deserialize)]
    struct Wrap {
        integrity: Option<IntegrityConfig>,
    }
    let wrap: Wrap = toml::from_str(text)?;
    let mut cfg = wrap.integrity.unwrap_or_default();
    if cfg.interval_minutes == 0 {
        cfg.interval_minutes = 1;
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_section() {
        let t = r#"
[integrity]
interval_minutes = 30
files = ["MANIFESTO.md", "aeterna.toml"]
cpu_threshold_pct = 85.5
cpu_window_seconds = 300
portscan_abort_count = 5
portscan_window_seconds = 1800
"#;
        let c = load_from_toml(t).unwrap();
        assert_eq!(c.interval_minutes, 30);
        assert_eq!(c.files.len(), 2);
        assert_eq!(c.cpu_threshold_pct, 85.5);
        assert_eq!(c.portscan_abort_count, 5);
    }

    #[test]
    fn applies_defaults() {
        let c = load_from_toml("").unwrap();
        assert_eq!(c.interval_minutes, 60);
        assert_eq!(c.cpu_threshold_pct, 90.0);
        assert_eq!(c.cpu_window_seconds, 600);
    }

    #[test]
    fn clamps_zero_interval() {
        let c = load_from_toml("[integrity]\ninterval_minutes = 0").unwrap();
        assert_eq!(c.interval_minutes, 1);
    }
}
