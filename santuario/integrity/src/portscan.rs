//! γ threshold — port-scan detector.
//!
//! This module is intentionally minimal: it counts distinct
//! "unsolicited connection" events per peer IP within a sliding window
//! and fires [`AlertKind::Gamma`] when a peer crosses
//! `portscan_abort_count` within `portscan_window_seconds`.
//!
//! The Sentinel (Python) feeds events into this detector via an IPC
//! boundary not implemented in this crate — that glue belongs to
//! `santuario/signer/src/main.rs`. The detector itself is pure data.

use std::collections::HashMap;

use crate::{now_utc, AlertEvidence, AlertKind, IntegrityAlert, IntegrityConfig};

/// Single unsolicited-connection event.
#[derive(Debug, Clone)]
pub struct ScanEvent {
    pub peer: String,
    pub ts_utc: i64,
}

#[derive(Debug, Clone)]
pub struct PortScanMonitor {
    pub node_id: String,
    pub abort_count: u32,
    pub window_seconds: u64,
    per_peer: HashMap<String, Vec<i64>>,
    latched: HashMap<String, i64>,
}

impl PortScanMonitor {
    pub fn new(node_id: impl Into<String>, cfg: &IntegrityConfig) -> Self {
        Self {
            node_id: node_id.into(),
            abort_count: cfg.portscan_abort_count,
            window_seconds: cfg.portscan_window_seconds,
            per_peer: HashMap::new(),
            latched: HashMap::new(),
        }
    }

    pub fn observe(&mut self, event: ScanEvent) -> Option<IntegrityAlert> {
        let now = event.ts_utc;
        let window = self.window_seconds as i64;
        let entry = self.per_peer.entry(event.peer.clone()).or_default();
        entry.retain(|&t| now - t <= window);
        entry.push(now);
        let count_in_window = entry.len() as u32;

        // Re-arm after a full window with no hits.
        if let Some(&last) = self.latched.get(&event.peer) {
            if now - last > window {
                self.latched.remove(&event.peer);
            }
        }

        if count_in_window >= self.abort_count && !self.latched.contains_key(&event.peer) {
            self.latched.insert(event.peer.clone(), now);
            return Some(IntegrityAlert {
                kind: AlertKind::Gamma,
                ts_utc: now_utc(),
                node_id: self.node_id.clone(),
                evidence: AlertEvidence::GammaPortScan {
                    peer: event.peer,
                    count_in_window,
                    window_seconds: self.window_seconds,
                },
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(window: u64, count: u32) -> IntegrityConfig {
        IntegrityConfig {
            portscan_abort_count: count,
            portscan_window_seconds: window,
            ..IntegrityConfig::default()
        }
    }

    #[test]
    fn below_count_does_not_fire() {
        let mut m = PortScanMonitor::new("n", &cfg(60, 3));
        assert!(m
            .observe(ScanEvent {
                peer: "10.0.0.1".into(),
                ts_utc: 1
            })
            .is_none());
        assert!(m
            .observe(ScanEvent {
                peer: "10.0.0.1".into(),
                ts_utc: 2
            })
            .is_none());
    }

    #[test]
    fn threshold_fires_once_then_latches() {
        let mut m = PortScanMonitor::new("n", &cfg(60, 3));
        for i in 0..3 {
            let out = m.observe(ScanEvent {
                peer: "10.0.0.1".into(),
                ts_utc: i,
            });
            if i == 2 {
                assert!(out.is_some(), "third event must fire");
            } else {
                assert!(out.is_none());
            }
        }
        // Additional events don't re-fire.
        for i in 3..8 {
            assert!(m
                .observe(ScanEvent {
                    peer: "10.0.0.1".into(),
                    ts_utc: i
                })
                .is_none());
        }
    }

    #[test]
    fn distinct_peers_do_not_combine() {
        let mut m = PortScanMonitor::new("n", &cfg(60, 3));
        m.observe(ScanEvent {
            peer: "10.0.0.1".into(),
            ts_utc: 1,
        });
        m.observe(ScanEvent {
            peer: "10.0.0.2".into(),
            ts_utc: 1,
        });
        assert!(m
            .observe(ScanEvent {
                peer: "10.0.0.1".into(),
                ts_utc: 2
            })
            .is_none());
    }

    #[test]
    fn rearms_after_window() {
        let mut m = PortScanMonitor::new("n", &cfg(5, 3));
        for i in 0..3 {
            m.observe(ScanEvent {
                peer: "10.0.0.1".into(),
                ts_utc: i,
            });
        }
        // long gap
        for i in 3..12 {
            m.observe(ScanEvent {
                peer: "10.0.0.9".into(),
                ts_utc: i,
            });
        }
        // new burst from same peer, after the latch's window expired
        let mut re_fire = false;
        for i in 20..25 {
            if m
                .observe(ScanEvent {
                    peer: "10.0.0.1".into(),
                    ts_utc: i,
                })
                .is_some()
            {
                re_fire = true;
            }
        }
        assert!(re_fire, "should re-fire after window elapsed");
    }
}
