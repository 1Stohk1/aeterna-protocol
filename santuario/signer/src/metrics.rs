//! v0.3.0 "Oculus" — in-memory metrics registry.
//!
//! The Admin service snapshots this registry on every `GetMetrics`
//! call. The registry is thread-safe (`Mutex` everywhere) because the
//! sign-path critical section holds it for only a few microseconds —
//! contention is negligible against a Dilithium-5 sign (~ms).
//!
//! Key namespaces (stable, per admin.proto):
//!   `santuario_*` — Rust-side signals (this crate)
//!   `aeterna_*`   — Sentinel-side signals (reserved; not populated here)
//!
//! Counters only ever go up. Gauges are last-write-wins. Quantiles are
//! sliding windows over the last `Quantiles::CAP` samples.
//!
//! The registry is deliberately minimal: no dependency on `prometheus`,
//! no labels, no histogram buckets. The exporter crate (Phase D) is
//! responsible for re-shaping these into Prometheus text format.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

/// Fixed-capacity ring buffer of f64 samples. p50/p90/p99 are computed
/// on demand by cloning + sorting; this is fine because the buffer is
/// bounded and `GetMetrics` is called at most every few seconds.
#[derive(Debug)]
pub struct QuantileWindow {
    buf: Vec<f64>,
    cursor: usize,
    filled: bool,
}

impl QuantileWindow {
    /// Cap is intentionally small — 512 samples covers 5 min at ~1.7 Hz
    /// which is well above the expected sign rate.
    pub const CAP: usize = 512;

    pub fn new(cap: usize) -> Self {
        Self {
            buf: vec![0.0; cap.max(1)],
            cursor: 0,
            filled: false,
        }
    }

    pub fn observe(&mut self, v: f64) {
        self.buf[self.cursor] = v;
        self.cursor = (self.cursor + 1) % self.buf.len();
        if self.cursor == 0 {
            self.filled = true;
        }
    }

    /// Returns (p50, p90, p99). All three are 0.0 if no samples yet.
    pub fn snapshot(&self) -> (f64, f64, f64) {
        let live = if self.filled {
            self.buf.len()
        } else {
            self.cursor
        };
        if live == 0 {
            return (0.0, 0.0, 0.0);
        }
        let mut v: Vec<f64> = self.buf[..live].to_vec();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let pick = |q: f64| -> f64 {
            let idx = ((v.len() as f64 - 1.0) * q).round() as usize;
            v[idx.min(v.len() - 1)]
        };
        (pick(0.5), pick(0.9), pick(0.99))
    }
}

#[derive(Debug)]
pub struct MetricsRegistry {
    counters: Mutex<HashMap<String, u64>>,
    gauges: Mutex<HashMap<String, f64>>,
    quantiles: Mutex<HashMap<String, QuantileWindow>>,
    pub window_seconds: u32,
}

impl MetricsRegistry {
    pub fn new(window_seconds: u32) -> Self {
        Self {
            counters: Mutex::new(HashMap::new()),
            gauges: Mutex::new(HashMap::new()),
            quantiles: Mutex::new(HashMap::new()),
            window_seconds,
        }
    }

    pub fn incr(&self, name: &str) {
        self.incr_by(name, 1);
    }

    pub fn incr_by(&self, name: &str, by: u64) {
        let mut m = self.counters.lock().expect("counters mutex poisoned");
        *m.entry(name.to_string()).or_insert(0) += by;
    }

    pub fn set_gauge(&self, name: &str, v: f64) {
        let mut m = self.gauges.lock().expect("gauges mutex poisoned");
        m.insert(name.to_string(), v);
    }

    pub fn observe(&self, name: &str, v: f64) {
        let mut m = self.quantiles.lock().expect("quantiles mutex poisoned");
        m.entry(name.to_string())
            .or_insert_with(|| QuantileWindow::new(QuantileWindow::CAP))
            .observe(v);
    }

    pub fn observe_duration(&self, name: &str, d: Duration) {
        self.observe(name, d.as_secs_f64());
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let counters = self.counters.lock().expect("counters").clone();
        let gauges = self.gauges.lock().expect("gauges").clone();
        let quantiles = {
            let q = self.quantiles.lock().expect("quantiles");
            q.iter()
                .map(|(k, v)| (k.clone(), v.snapshot()))
                .collect::<HashMap<String, (f64, f64, f64)>>()
        };
        MetricsSnapshot {
            counters,
            gauges,
            quantiles,
            window_seconds: self.window_seconds,
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        // 300 s == War Room refresh budget per SPRINT-v0.3.0.
        Self::new(300)
    }
}

#[derive(Debug)]
pub struct MetricsSnapshot {
    pub counters: HashMap<String, u64>,
    pub gauges: HashMap<String, f64>,
    pub quantiles: HashMap<String, (f64, f64, f64)>,
    pub window_seconds: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let r = MetricsRegistry::default();
        r.incr("santuario_sign_total");
        r.incr("santuario_sign_total");
        r.incr_by("santuario_sign_total", 3);
        let s = r.snapshot();
        assert_eq!(s.counters["santuario_sign_total"], 5);
    }

    #[test]
    fn gauges_overwrite() {
        let r = MetricsRegistry::default();
        r.set_gauge("santuario_vault_sealed", 1.0);
        r.set_gauge("santuario_vault_sealed", 0.0);
        let s = r.snapshot();
        assert_eq!(s.gauges["santuario_vault_sealed"], 0.0);
    }

    #[test]
    fn quantiles_monotone_input() {
        let r = MetricsRegistry::default();
        for i in 1..=100 {
            r.observe("latency", i as f64 / 1000.0);
        }
        let s = r.snapshot();
        let (p50, p90, p99) = s.quantiles["latency"];
        assert!(p50 < p90 && p90 < p99);
        assert!((p50 - 0.050).abs() < 0.005);
    }

    #[test]
    fn quantiles_empty_is_zero() {
        let w = QuantileWindow::new(16);
        assert_eq!(w.snapshot(), (0.0, 0.0, 0.0));
    }

    #[test]
    fn quantile_window_wraps() {
        let mut w = QuantileWindow::new(4);
        for i in 0..10 {
            w.observe(i as f64);
        }
        // Only the last 4 samples (6,7,8,9) survive.
        let (p50, _p90, p99) = w.snapshot();
        assert!(p50 >= 6.0);
        assert!(p99 >= 8.0);
    }
}
