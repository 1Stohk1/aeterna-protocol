//! v0.3.0 "Oculus" — reader for the Sentinel-side metrics snapshot.
//!
//! The Python Sentinel owns half the telemetry surface —
//! gossip rx/tx, task queue depth, heartbeat cadence, mission state.
//! It atomically publishes that data to
//!   `<repo>/santuario/integrity/sentinel_metrics.json`
//! and the Admin service merges those `aeterna_*` counters/gauges into
//! its `GetMetrics` response. The Rust-side `MetricsRegistry` owns the
//! disjoint `santuario_*` namespace, so there is no key collision by
//! construction (see admin.proto).
//!
//! Missing or malformed files yield an EMPTY snapshot, never an error.
//! Observability must be callable from any Sentinel state — per
//! SPRINT-v0.3.0 §2.3.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SentinelMetricsFile {
    #[serde(default)]
    pub snapshot_utc: i64,
    #[serde(default)]
    pub counters: HashMap<String, u64>,
    #[serde(default)]
    pub gauges: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
pub struct SentinelMetricsReader {
    pub path: PathBuf,
}

impl SentinelMetricsReader {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn default_for_repo(repo_root: &Path) -> Self {
        Self::new(repo_root.join("santuario/integrity/sentinel_metrics.json"))
    }

    /// Never fails — missing / malformed files yield an empty snapshot.
    pub fn read(&self) -> SentinelMetricsFile {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => SentinelMetricsFile::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let r = SentinelMetricsReader::new(dir.path().join("nope.json"));
        let snap = r.read();
        assert_eq!(snap.snapshot_utc, 0);
        assert!(snap.counters.is_empty());
        assert!(snap.gauges.is_empty());
    }

    #[test]
    fn malformed_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sentinel_metrics.json");
        std::fs::write(&path, "not json").unwrap();
        let snap = SentinelMetricsReader::new(&path).read();
        assert!(snap.counters.is_empty());
    }

    #[test]
    fn valid_file_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sentinel_metrics.json");
        let sample = SentinelMetricsFile {
            snapshot_utc: 1_713_542_400,
            counters: HashMap::from([
                ("aeterna_gossip_rx_total".to_string(), 42_u64),
                ("aeterna_block_tx_total".to_string(), 3_u64),
            ]),
            gauges: HashMap::from([("aeterna_task_queue_depth".to_string(), 7.0_f64)]),
        };
        std::fs::write(&path, serde_json::to_string(&sample).unwrap()).unwrap();
        let snap = SentinelMetricsReader::new(&path).read();
        assert_eq!(snap.counters["aeterna_gossip_rx_total"], 42);
        assert_eq!(snap.counters["aeterna_block_tx_total"], 3);
        assert_eq!(snap.gauges["aeterna_task_queue_depth"], 7.0);
    }
}
