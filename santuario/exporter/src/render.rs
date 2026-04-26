//! Pure render layer: AdminMetrics snapshot -> Prometheus text format.
//!
//! No I/O, no async, no globals. The render takes a fully-resolved
//! `MetricsSnapshot` plus a `NodeIdentity` and returns a `String` that
//! conforms to the Prometheus 0.0.4 text exposition format.
//!
//! Why a separate `MetricsSnapshot` type instead of consuming the tonic
//! `GetMetricsResponse` directly: the proto is a wire contract and tests
//! that build it require the full prost runtime + a generated client.
//! A plain Rust struct with HashMap<String, T> is trivial to construct
//! in tests and is the right abstraction boundary.
//!
//! The proto -> snapshot conversion happens in admin_client.rs, which
//! is the only place that touches tonic types.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write;

use crate::catalog::{
    self, CatalogEntry, MetricKind, FALLBACK_HELP, SIGNER_STATE_BOOLEANS, SIGNER_STATE_SOURCE_KEY,
};

/// Decoupled-from-proto input for the renderer.
#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub node_id: String,
    pub schema_version: u32,
    pub ts_utc: i64,
    pub counters: HashMap<String, u64>,
    pub gauges: HashMap<String, f64>,
}

/// Identity labels that decorate `aeterna_node_info`. Resolved once at
/// exporter startup from env / aeterna.toml / build constants.
#[derive(Debug, Clone)]
pub struct NodeIdentity {
    pub network: String,
    pub version: String,
    pub julia_version: String,
    pub pq_sig: String,
    pub pq_kem: String,
}

impl Default for NodeIdentity {
    fn default() -> Self {
        Self {
            network: "aeterna-testnet-0".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            julia_version: "unknown".to_string(),
            pq_sig: "Dilithium-5".to_string(),
            pq_kem: "Kyber-1024".to_string(),
        }
    }
}

/// Render a snapshot into Prometheus text format. Output ends with `\n`.
pub fn render(snap: &MetricsSnapshot, ident: &NodeIdentity) -> String {
    let mut out = String::with_capacity(4096);

    // 1. aeterna_node_info -- single time-series, value 1, identity carrier.
    write_node_info(&mut out, snap, ident);

    // 2. Curated entries first, in catalog declaration order. This makes
    //    the /metrics output stable across scrapes regardless of HashMap
    //    iteration order, which keeps Prometheus's text-format diff
    //    detection sane.
    let mut emitted: BTreeSet<String> = BTreeSet::new();
    for entry in catalog::CATALOG {
        if let Some(line) = render_curated(snap, entry) {
            out.push_str(&line);
            emitted.insert(entry.key.to_string());
        }
    }

    // 3. Synthesize the three signer-state booleans from the enum source,
    //    UNLESS the operator's contributor already publishes them as flat
    //    gauges (defensive: pass-through wins, no double-reporting).
    let synthesized = synthesize_signer_state_booleans(snap, &emitted);
    out.push_str(&synthesized.text);
    for k in synthesized.emitted_keys {
        emitted.insert(k);
    }

    // 4. Pass-through for everything else. Sort by key for stable output.
    write_passthrough(&mut out, snap, &emitted);

    out
}

// ---------------------------------------------------------------------------
// node_info
// ---------------------------------------------------------------------------

fn write_node_info(out: &mut String, snap: &MetricsSnapshot, ident: &NodeIdentity) {
    out.push_str("# HELP aeterna_node_info Static identity of this Guardian node. Always 1.\n");
    out.push_str("# TYPE aeterna_node_info gauge\n");
    let _ = writeln!(
        out,
        "aeterna_node_info{{guardian_id=\"{}\",network=\"{}\",version=\"{}\",julia_version=\"{}\",pq_sig=\"{}\",pq_kem=\"{}\"}} 1",
        escape_label(&snap.node_id),
        escape_label(&ident.network),
        escape_label(&ident.version),
        escape_label(&ident.julia_version),
        escape_label(&ident.pq_sig),
        escape_label(&ident.pq_kem),
    );
}

// ---------------------------------------------------------------------------
// curated
// ---------------------------------------------------------------------------

fn render_curated(snap: &MetricsSnapshot, entry: &CatalogEntry) -> Option<String> {
    let value = match entry.kind {
        MetricKind::Counter => snap.counters.get(entry.key).map(|v| *v as f64),
        MetricKind::Gauge => snap.gauges.get(entry.key).copied(),
    }?;
    let mut s = String::with_capacity(128);
    let _ = writeln!(s, "# HELP {} {}", entry.key, escape_help(entry.help));
    let _ = writeln!(s, "# TYPE {} {}", entry.key, entry.kind.as_prom_str());
    let _ = writeln!(s, "{} {}", entry.key, format_value(value));
    Some(s)
}

// ---------------------------------------------------------------------------
// signer state synthesis
// ---------------------------------------------------------------------------

struct SynthOutcome {
    text: String,
    emitted_keys: Vec<String>,
}

fn synthesize_signer_state_booleans(
    snap: &MetricsSnapshot,
    already_emitted: &BTreeSet<String>,
) -> SynthOutcome {
    let mut out = SynthOutcome {
        text: String::new(),
        emitted_keys: Vec::new(),
    };

    // Defensive pass-through guard: if the contributor evolves to publish
    // the three booleans directly, we yield. Detected by ANY of the three
    // boolean keys already being in gauges -- the synthesis is all-or-none,
    // we do not partially supplement.
    let any_boolean_already_present = SIGNER_STATE_BOOLEANS
        .iter()
        .any(|(name, _, _)| snap.gauges.contains_key(*name));
    if any_boolean_already_present {
        return out;
    }

    let Some(state_value) = snap.gauges.get(SIGNER_STATE_SOURCE_KEY).copied() else {
        // Source enum absent -> nothing to synthesize. The operator will
        // see no signer_state_* time-series, which is the honest signal
        // (the contributor isn't publishing the state yet).
        return out;
    };

    for (name, expected, help) in SIGNER_STATE_BOOLEANS {
        if already_emitted.contains(*name) {
            continue;
        }
        let v = if (state_value - expected).abs() < f64::EPSILON {
            1
        } else {
            0
        };
        let _ = writeln!(out.text, "# HELP {} {}", name, escape_help(help));
        let _ = writeln!(out.text, "# TYPE {} gauge", name);
        let _ = writeln!(out.text, "{} {}", name, v);
        out.emitted_keys.push((*name).to_string());
    }

    out
}

// ---------------------------------------------------------------------------
// pass-through
// ---------------------------------------------------------------------------

fn write_passthrough(out: &mut String, snap: &MetricsSnapshot, already_emitted: &BTreeSet<String>) {
    // BTreeMap-ify so iteration order is deterministic (key-sorted).
    let counters: BTreeMap<&String, &u64> = snap.counters.iter().collect();
    let gauges: BTreeMap<&String, &f64> = snap.gauges.iter().collect();

    for (key, value) in counters {
        if already_emitted.contains(key.as_str()) || catalog::lookup(key).is_some() {
            continue;
        }
        let _ = writeln!(out, "# HELP {} {}", key, FALLBACK_HELP);
        let _ = writeln!(out, "# TYPE {} counter", key);
        let _ = writeln!(out, "{} {}", key, value);
    }

    for (key, value) in gauges {
        if already_emitted.contains(key.as_str()) || catalog::lookup(key).is_some() {
            continue;
        }
        let _ = writeln!(out, "# HELP {} {}", key, FALLBACK_HELP);
        let _ = writeln!(out, "# TYPE {} gauge", key);
        let _ = writeln!(out, "{} {}", key, format_value(*value));
    }
}

// ---------------------------------------------------------------------------
// formatting helpers
// ---------------------------------------------------------------------------

/// Format a float for the Prometheus text format. Integers are rendered
/// without a decimal point; non-integer floats use Rust's Display (which
/// handles +Inf, -Inf, NaN per Prometheus convention: "+Inf"/"-Inf"/"NaN").
fn format_value(v: f64) -> String {
    if v.is_nan() {
        "NaN".to_string()
    } else if v.is_infinite() {
        if v.is_sign_positive() {
            "+Inf".to_string()
        } else {
            "-Inf".to_string()
        }
    } else if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{}", v)
    }
}

/// Escape `\`, `\n` in HELP text per Prometheus text format.
fn escape_help(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n")
}

/// Escape `\`, `\n`, `"` in label values per Prometheus text format.
fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> NodeIdentity {
        NodeIdentity {
            network: "aeterna-testnet-0".to_string(),
            version: "0.0.1".to_string(),
            julia_version: "1.12.6".to_string(),
            pq_sig: "Dilithium-5".to_string(),
            pq_kem: "Kyber-1024".to_string(),
        }
    }

    fn snap_with(c: &[(&str, u64)], g: &[(&str, f64)]) -> MetricsSnapshot {
        MetricsSnapshot {
            node_id: "Prometheus-1".to_string(),
            schema_version: 1,
            ts_utc: 1_777_700_000,
            counters: c.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            gauges: g.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    #[test]
    fn empty_snapshot_emits_only_node_info() {
        let out = render(&snap_with(&[], &[]), &ident());
        assert!(out.contains("aeterna_node_info{guardian_id=\"Prometheus-1\""));
        assert!(out.contains("network=\"aeterna-testnet-0\""));
        assert!(out.contains("julia_version=\"1.12.6\""));
        // No other metric appears.
        assert!(!out.contains("aeterna_trust_score"));
    }

    #[test]
    fn curated_counter_renders_with_help_and_type() {
        let out = render(
            &snap_with(&[("santuario_sign_total", 142)], &[]),
            &ident(),
        );
        assert!(out.contains("# HELP santuario_sign_total"));
        assert!(out.contains("# TYPE santuario_sign_total counter"));
        assert!(out.contains("santuario_sign_total 142"));
    }

    #[test]
    fn curated_gauge_renders_with_help_and_type() {
        let out = render(&snap_with(&[], &[("aeterna_trust_score", 48.0)]), &ident());
        assert!(out.contains("# HELP aeterna_trust_score"));
        assert!(out.contains("# TYPE aeterna_trust_score gauge"));
        assert!(out.contains("aeterna_trust_score 48"));
    }

    #[test]
    fn unknown_counter_falls_back_to_generic_help() {
        let out = render(
            &snap_with(&[("aeterna_made_up_total", 7)], &[]),
            &ident(),
        );
        assert!(out.contains("# HELP aeterna_made_up_total Auto-discovered"));
        assert!(out.contains("# TYPE aeterna_made_up_total counter"));
        assert!(out.contains("aeterna_made_up_total 7"));
    }

    #[test]
    fn unknown_gauge_falls_back_to_generic_help() {
        let out = render(&snap_with(&[], &[("santuario_weird_gauge", 3.14)]), &ident());
        assert!(out.contains("# HELP santuario_weird_gauge Auto-discovered"));
        assert!(out.contains("# TYPE santuario_weird_gauge gauge"));
        assert!(out.contains("santuario_weird_gauge 3.14"));
    }

    #[test]
    fn signer_state_synthesizes_three_booleans_normal() {
        let out = render(&snap_with(&[], &[("santuario_signer_state", 0.0)]), &ident());
        assert!(out.contains("santuario_signer_state_normal 1"));
        assert!(out.contains("santuario_signer_state_degraded 0"));
        assert!(out.contains("santuario_signer_state_suspended 0"));
        // The source enum is also passed through (no double-emit conflict).
        assert!(out.contains("santuario_signer_state 0"));
    }

    #[test]
    fn signer_state_synthesizes_degraded() {
        let out = render(&snap_with(&[], &[("santuario_signer_state", 1.0)]), &ident());
        assert!(out.contains("santuario_signer_state_normal 0"));
        assert!(out.contains("santuario_signer_state_degraded 1"));
        assert!(out.contains("santuario_signer_state_suspended 0"));
    }

    #[test]
    fn signer_state_synthesizes_suspended() {
        let out = render(&snap_with(&[], &[("santuario_signer_state", 2.0)]), &ident());
        assert!(out.contains("santuario_signer_state_normal 0"));
        assert!(out.contains("santuario_signer_state_degraded 0"));
        assert!(out.contains("santuario_signer_state_suspended 1"));
    }

    #[test]
    fn signer_state_synthesis_yields_to_explicit_booleans() {
        // If the contributor publishes the booleans directly, the
        // synthesizer steps aside (pass-through wins).
        let out = render(
            &snap_with(
                &[],
                &[
                    ("santuario_signer_state", 1.0),
                    ("santuario_signer_state_normal", 0.0),
                    ("santuario_signer_state_degraded", 1.0),
                    ("santuario_signer_state_suspended", 0.0),
                ],
            ),
            &ident(),
        );
        // Synthesizer left exactly one HELP block per boolean -- the
        // pass-through one. The synthesized HELP would have been the same,
        // but importantly we don't emit two `# TYPE` lines for the same
        // metric (which Prometheus would reject).
        let n_help_normal = out.matches("# HELP santuario_signer_state_normal").count();
        assert_eq!(n_help_normal, 1, "exactly one HELP for the boolean");
    }

    #[test]
    fn signer_state_absent_emits_nothing_synthesized() {
        let out = render(&snap_with(&[], &[]), &ident());
        assert!(!out.contains("santuario_signer_state_normal"));
    }

    #[test]
    fn label_values_are_escaped() {
        let snap = MetricsSnapshot {
            node_id: r#"weird"id\with"#.to_string(),
            ..Default::default()
        };
        let out = render(&snap, &ident());
        assert!(out.contains(r#"guardian_id="weird\"id\\with""#));
    }

    #[test]
    fn integer_floats_render_without_decimal() {
        assert_eq!(format_value(48.0), "48");
        assert_eq!(format_value(3.14), "3.14");
        assert_eq!(format_value(0.0), "0");
        assert_eq!(format_value(-5.0), "-5");
    }

    #[test]
    fn special_floats_use_prometheus_canonical_form() {
        assert_eq!(format_value(f64::INFINITY), "+Inf");
        assert_eq!(format_value(f64::NEG_INFINITY), "-Inf");
        assert_eq!(format_value(f64::NAN), "NaN");
    }

    #[test]
    fn output_is_deterministic_across_runs() {
        // HashMap iteration is non-deterministic but our output uses
        // BTreeMap-ish sort + catalog order, so the result is stable.
        let snap = snap_with(
            &[("z_unknown_total", 1), ("a_unknown_total", 2)],
            &[("z_unk", 1.0), ("a_unk", 2.0)],
        );
        let r1 = render(&snap, &ident());
        let r2 = render(&snap, &ident());
        assert_eq!(r1, r2);
    }

    #[test]
    fn sample_realistic_run() {
        // Smoke test mimicking the "Prometheus-1 after a few minutes
        // beside Prometheus-0" baseline used in the schema validation.
        let snap = snap_with(
            &[
                ("santuario_sign_total", 142),
                ("aeterna_blocks_emitted_total", 142),
                ("aeterna_blocks_validated_total", 87),
                ("aeterna_blocks_rejected_total", 2),
                ("aeterna_gossip_rx_total", 188),
                ("santuario_integrity_alerts_total", 1),
                ("santuario_admin_requests_total", 33),
            ],
            &[
                ("aeterna_trust_score", 48.0),
                ("aeterna_gossip_peers_active", 1.0),
                ("santuario_vault_sealed", 0.0),
                ("santuario_signer_uptime_seconds", 314.7),
                ("santuario_signer_state", 0.0),
            ],
        );
        let out = render(&snap, &ident());
        // Every catalogued metric is present.
        for entry in catalog::CATALOG {
            if snap.counters.contains_key(entry.key) || snap.gauges.contains_key(entry.key) {
                assert!(out.contains(&format!("# TYPE {} ", entry.key)),
                        "missing TYPE line for {}", entry.key);
            }
        }
        // node_info is present once.
        assert_eq!(out.matches("aeterna_node_info{").count(), 1);
        // The signer state synthesis fired (state was 0 -> normal).
        assert!(out.contains("santuario_signer_state_normal 1"));
    }
}
