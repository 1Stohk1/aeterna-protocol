//! v0.3.0 "Oculus" — peer snapshot reader.
//!
//! The Rust Santuario does NOT run the gossip loop — that lives in the
//! Python Sentinel (`core/gossip.py`). On every heartbeat the Sentinel
//! writes a snapshot of its peer table atomically to
//!   `<repo>/santuario/integrity/peers.json`
//! and the Admin service reads that file whenever a `ListPeers` RPC
//! arrives.
//!
//! Contract from SPRINT-v0.3.0 §2.3: observability MUST be callable
//! regardless of the gossip subsystem's health. A missing or malformed
//! snapshot file therefore yields an EMPTY snapshot, never an error —
//! a suspended-and-gossip-degraded node must still report to its
//! operator.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerSnapshotFile {
    #[serde(default)]
    pub snapshot_utc: i64,
    #[serde(default)]
    pub peers: Vec<PeerEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerEntry {
    pub address: String,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub last_seen_utc: i64,
    #[serde(default)]
    pub rx_count: u64,
    #[serde(default)]
    pub tx_count: u64,
    #[serde(default)]
    pub is_bootstrap: bool,
}

#[derive(Debug, Clone)]
pub struct PeerSnapshotReader {
    pub path: PathBuf,
}

impl PeerSnapshotReader {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn default_for_repo(repo_root: &Path) -> Self {
        Self::new(repo_root.join("santuario/integrity/peers.json"))
    }

    /// Never fails — missing / malformed files yield an empty snapshot.
    pub fn read(&self) -> PeerSnapshotFile {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => PeerSnapshotFile::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_file_yields_empty() {
        let dir = tempfile::tempdir().unwrap();
        let r = PeerSnapshotReader::new(dir.path().join("nope.json"));
        let snap = r.read();
        assert_eq!(snap.snapshot_utc, 0);
        assert!(snap.peers.is_empty());
    }

    #[test]
    fn malformed_file_yields_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        std::fs::write(&path, "this is not JSON").unwrap();
        let r = PeerSnapshotReader::new(&path);
        let snap = r.read();
        assert!(snap.peers.is_empty());
    }

    #[test]
    fn well_formed_file_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let sample = PeerSnapshotFile {
            snapshot_utc: 1_713_542_400,
            peers: vec![PeerEntry {
                address: "udp://192.168.1.19:4444".to_string(),
                node_id: "Prometheus-2".to_string(),
                last_seen_utc: 1_713_542_350,
                rx_count: 42,
                tx_count: 17,
                is_bootstrap: true,
            }],
        };
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(serde_json::to_string(&sample).unwrap().as_bytes())
            .unwrap();
        let snap = PeerSnapshotReader::new(&path).read();
        assert_eq!(snap.peers.len(), 1);
        assert_eq!(snap.peers[0].node_id, "Prometheus-2");
        assert!(snap.peers[0].is_bootstrap);
    }
}
