//! Curated catalog of well-known registry keys.
//!
//! The `MetricsRegistry` (santuario/signer/src/metrics.rs) and the
//! Sentinel `MetricsContributor` (core/metrics_contributor.py) both store
//! a flat keyspace by design — see admin.proto. The exporter is the layer
//! that gives those keys a human-readable `# HELP` line and the right
//! Prometheus `# TYPE`.
//!
//! Behaviour for unknown keys (Phase D contract):
//!   - Counters from `GetMetricsResponse.counters` -> emitted as `# TYPE … counter`
//!   - Gauges   from `GetMetricsResponse.gauges`   -> emitted as `# TYPE … gauge`
//!   - HELP defaults to "Auto-discovered AETERNA metric (no curated description)."
//!
//! This means a new metric added to the contributor TODAY shows up at the
//! Prometheus scrape immediately, without recompiling the exporter. The
//! catalog is purely a documentation/typing assist.

/// Prometheus metric type. We deliberately do not model histograms /
/// summaries here — Phase D contract says the exporter ignores the
/// `quantiles` map (it would need bucket boundaries + label generation,
/// out of scope per SPRINT-v0.3.0 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    Counter,
    Gauge,
}

impl MetricKind {
    pub fn as_prom_str(self) -> &'static str {
        match self {
            MetricKind::Counter => "counter",
            MetricKind::Gauge => "gauge",
        }
    }
}

/// One curated catalog entry.
pub struct CatalogEntry {
    /// Registry key as it appears in `GetMetricsResponse.{counters,gauges}`.
    pub key: &'static str,
    /// Prometheus type — see MetricKind. Drives the `# TYPE` line.
    pub kind: MetricKind,
    /// HELP text. Should describe the metric in <80 chars on a single line.
    pub help: &'static str,
}

/// The catalog itself. Order is irrelevant; lookup is linear (N≈12, faster
/// than a HashMap and zero alloc).
///
/// Maintenance rule: every entry here MUST correspond to a key that is
/// actually emitted somewhere in the codebase. Do not add aspirational
/// entries — if the key isn't present in the snapshot, the exporter will
/// just not emit a sample, which is the right behavior. Adding a phantom
/// entry would mislead operators reading the `# HELP` lines.
pub const CATALOG: &[CatalogEntry] = &[
    // --- Consenso ---------------------------------------------------------
    CatalogEntry {
        key: "aeterna_trust_score",
        kind: MetricKind::Gauge,
        help: "Current local Trust Score of this Guardian (CONSENSUS.md formula).",
    },
    CatalogEntry {
        key: "aeterna_blocks_emitted_total",
        kind: MetricKind::Counter,
        help: "Blocks broadcast by this Guardian since startup.",
    },
    CatalogEntry {
        key: "aeterna_blocks_validated_total",
        kind: MetricKind::Counter,
        help: "Peer blocks accepted as valid via PoC scientific_hash replay.",
    },
    CatalogEntry {
        key: "aeterna_blocks_rejected_total",
        kind: MetricKind::Counter,
        help: "Peer blocks rejected by PoC replay or local checks.",
    },
    // --- P2P --------------------------------------------------------------
    CatalogEntry {
        key: "aeterna_gossip_peers_active",
        kind: MetricKind::Gauge,
        help: "Peers heard from in the last gossip window.",
    },
    CatalogEntry {
        key: "aeterna_gossip_rx_total",
        kind: MetricKind::Counter,
        help: "Gossip datagrams received since startup.",
    },
    CatalogEntry {
        key: "aeterna_block_tx_total",
        kind: MetricKind::Counter,
        help: "Block messages emitted to the gossip layer since startup.",
    },
    CatalogEntry {
        key: "aeterna_task_queue_depth",
        kind: MetricKind::Gauge,
        help: "Tasks queued for the Julia engine but not yet dispatched.",
    },
    // --- Cripto / firme PQ ------------------------------------------------
    CatalogEntry {
        key: "santuario_sign_total",
        kind: MetricKind::Counter,
        help: "Post-quantum (Dilithium-5) signatures issued by the signer.",
    },
    // --- Sicurezza / Custos ----------------------------------------------
    CatalogEntry {
        key: "santuario_integrity_alerts_total",
        kind: MetricKind::Counter,
        help: "Integrity alerts raised by the Custos loop (alpha+beta+gamma combined).",
    },
    CatalogEntry {
        key: "santuario_vault_sealed",
        kind: MetricKind::Gauge,
        help: "Vault state: 1 = sealed (signer cannot sign), 0 = unsealed.",
    },
    CatalogEntry {
        key: "santuario_signer_uptime_seconds",
        kind: MetricKind::Gauge,
        help: "Seconds since the signer process bound its gRPC port.",
    },
    // --- Admin surface (Phase A self-instrumentation) --------------------
    CatalogEntry {
        key: "santuario_admin_requests_total",
        kind: MetricKind::Counter,
        help: "Admin gRPC requests served (GetMetrics + ListPeers + TailAuditLog combined).",
    },
];

/// Lookup. Returns `None` for keys not in the catalog (which is the
/// pass-through trigger in render.rs).
pub fn lookup(key: &str) -> Option<&'static CatalogEntry> {
    CATALOG.iter().find(|e| e.key == key)
}

/// HELP text used for keys not in the catalog. Single line, <80 chars.
pub const FALLBACK_HELP: &str = "Auto-discovered AETERNA metric (no curated description).";

/// The three boolean flat metrics that mirror the `santuario_signer_state`
/// enum gauge. These are NOT in the main catalog because they are
/// SYNTHESIZED at render time from a single source key — see render.rs
/// `synthesize_signer_state_booleans`.
pub const SIGNER_STATE_SOURCE_KEY: &str = "santuario_signer_state";

/// (output_metric_name, expected enum value, HELP text)
pub const SIGNER_STATE_BOOLEANS: &[(&str, f64, &str)] = &[
    (
        "santuario_signer_state_normal",
        0.0,
        "Signer is in normal operation (1) or not (0). Derived from santuario_signer_state.",
    ),
    (
        "santuario_signer_state_degraded",
        1.0,
        "Signer is in degraded mode (1) or not (0). Derived from santuario_signer_state.",
    ),
    (
        "santuario_signer_state_suspended",
        2.0,
        "Signer is suspended (1) or not (0). Derived from santuario_signer_state.",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_keys_unique() {
        let mut seen = std::collections::HashSet::new();
        for e in CATALOG {
            assert!(seen.insert(e.key), "duplicate catalog key: {}", e.key);
        }
    }

    #[test]
    fn lookup_hit_and_miss() {
        assert!(lookup("aeterna_trust_score").is_some());
        assert!(lookup("definitely_not_a_real_metric").is_none());
    }

    #[test]
    fn signer_state_booleans_cover_three_values() {
        let vals: Vec<f64> = SIGNER_STATE_BOOLEANS.iter().map(|(_, v, _)| *v).collect();
        assert_eq!(vals, vec![0.0, 1.0, 2.0]);
    }
}
