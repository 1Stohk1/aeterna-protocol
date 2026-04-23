//! β threshold — CPU stress monitor.
//!
//! Pulls aggregate CPU% from [`sysinfo`] once per tick and averages it
//! over a sliding window; if the average stays ≥ `cpu_threshold_pct`
//! for the entire window the detector fires [`AlertKind::Beta`]. The
//! threshold and window duration come from `aeterna.toml [integrity]`.
//!
//! The detector is synchronous and tick-driven: callers (the main
//! Tokio runtime) invoke [`CpuMonitor::tick`] on a schedule and the
//! detector returns `Some(alert)` when the threshold is crossed. This
//! keeps the crate test-friendly — no real `sysinfo` probe in unit
//! tests, just pushed samples.

use std::collections::VecDeque;

use crate::{now_utc, AlertEvidence, AlertKind, IntegrityAlert, IntegrityConfig};

/// Sliding CPU-stress window. The monitor holds at most
/// `window / tick` samples; a full window above threshold trips the
/// alarm. On trip, the internal state resets so we don't emit twice for
/// the same sustained event.
#[derive(Debug, Clone)]
pub struct CpuMonitor {
    pub node_id: String,
    pub threshold_pct: f32,
    pub window_seconds: u64,
    samples: VecDeque<(i64, f32)>,
    latched: bool,
}

impl CpuMonitor {
    pub fn new(node_id: impl Into<String>, cfg: &IntegrityConfig) -> Self {
        Self {
            node_id: node_id.into(),
            threshold_pct: cfg.cpu_threshold_pct,
            window_seconds: cfg.cpu_window_seconds,
            samples: VecDeque::new(),
            latched: false,
        }
    }

    /// Feed one CPU% sample. `now` is the current UTC second. Returns an
    /// alert when the window is full AND its average crosses the
    /// threshold AND we haven't already latched one for the current
    /// sustained event.
    pub fn tick(&mut self, now: i64, cpu_pct: f32) -> Option<IntegrityAlert> {
        self.samples.push_back((now, cpu_pct));
        // Evict samples older than the window.
        while let Some(&(t, _)) = self.samples.front() {
            if now - t > self.window_seconds as i64 {
                self.samples.pop_front();
            } else {
                break;
            }
        }
        // Only arm once we've seen a full window's worth. Assume samples
        // are roughly regular so ~= window seconds of history.
        if self.samples.is_empty() {
            return None;
        }
        let span = now - self.samples.front().unwrap().0;
        if (span as u64) + 1 < self.window_seconds {
            return None;
        }

        let mean: f32 =
            self.samples.iter().map(|&(_, v)| v).sum::<f32>() / (self.samples.len() as f32);

        if mean >= self.threshold_pct && !self.latched {
            self.latched = true;
            return Some(IntegrityAlert {
                kind: AlertKind::Beta,
                ts_utc: now_utc(),
                node_id: self.node_id.clone(),
                evidence: AlertEvidence::BetaCpuStress {
                    window_seconds: self.window_seconds,
                    mean_pct: mean,
                    threshold_pct: self.threshold_pct,
                },
            });
        }
        if mean < self.threshold_pct {
            // Re-arm once the stress subsides.
            self.latched = false;
        }
        None
    }
}

/// Sample current global CPU% via `sysinfo`. Intended to be called once
/// per tick on Linux; on other platforms returns 0.0 (the β detector
/// will never fire, which is the intended behaviour — non-Linux nodes
/// run as osservatore anyway).
pub fn sample_cpu_global() -> f32 {
    use sysinfo::{CpuRefreshKind, RefreshKind, System};
    let mut sys =
        System::new_with_specifics(RefreshKind::new().with_cpu(CpuRefreshKind::everything()));
    sys.refresh_cpu();
    // sysinfo API needs two samples separated by MINIMUM_CPU_UPDATE_INTERVAL;
    // callers on a periodic tick naturally satisfy this.
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_cpu();
    sys.global_cpu_info().cpu_usage()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(window: u64, threshold: f32) -> IntegrityConfig {
        IntegrityConfig {
            cpu_threshold_pct: threshold,
            cpu_window_seconds: window,
            ..IntegrityConfig::default()
        }
    }

    #[test]
    fn below_threshold_does_not_fire() {
        let mut m = CpuMonitor::new("n", &cfg(10, 90.0));
        for i in 0..20 {
            assert!(m.tick(i as i64, 50.0).is_none());
        }
    }

    #[test]
    fn sustained_above_threshold_fires_once() {
        let mut m = CpuMonitor::new("n", &cfg(10, 90.0));
        let mut fires = 0;
        for i in 0..30 {
            if m.tick(i as i64, 95.0).is_some() {
                fires += 1;
            }
        }
        assert_eq!(fires, 1, "should latch after first trip");
    }

    #[test]
    fn rearms_after_recovery() {
        let mut m = CpuMonitor::new("n", &cfg(5, 90.0));
        for i in 0..20 {
            m.tick(i as i64, 95.0);
        }
        for i in 20..40 {
            m.tick(i as i64, 50.0);
        }
        let mut re_fires = 0;
        for i in 40..60 {
            if m.tick(i as i64, 95.0).is_some() {
                re_fires += 1;
            }
        }
        assert_eq!(re_fires, 1);
    }

    #[test]
    fn partial_window_does_not_fire() {
        let mut m = CpuMonitor::new("n", &cfg(1000, 90.0));
        for i in 0..5 {
            assert!(m.tick(i as i64, 99.0).is_none());
        }
    }
}
