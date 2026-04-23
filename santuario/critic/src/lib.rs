//! # santuario-critic
//!
//! Phase C of the v0.2.0 "Custos" sprint. A **deterministic, pure-Rust**
//! critic loop that runs inside the signer before any Dilithium-5 signature
//! is emitted. Three checks, in order:
//!
//! 1. [`reflexive::check_reflexive`] — `security.payload_hash` must actually
//!    equal `sha256(canonical_json({header,payload,reproducibility,results}))`.
//! 2. [`symbolic::check_symbolic`] — `payload.parametri` must conform to the
//!    per-task schema declared in `docs/AGP-v1.md §3`.
//! 3. [`axiomatic::check_axiomatic`] — the Prometheus Clause rule engine
//!    (ETHICS.md §2): reject any block that encodes autonomous lethal
//!    control, mass civilian surveillance, rent extraction on medical
//!    knowledge, or axiomatic circumvention.
//!
//! A `LLM-in-the-loop` semantic critique is explicitly *out of scope* for
//! this phase — see decision #3 in sprint-v0.2.0.md §7. The critic MUST
//! remain deterministic so consensus latency is bounded and two honest
//! Guardians always arrive at the same verdict.

pub mod axiomatic;
pub mod reflexive;
pub mod symbolic;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Canonical AGP-v1 payload as seen by the critic. Mirrors the schema in
/// `docs/AGP-v1.md §2`. The critic only reads it; it never mutates.
///
/// Note: `performance.execution_time_ms` is deliberately NOT included in the
/// `payload_hash` — matches AGP-v1 §2 notes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: Header,
    pub payload: Payload,
    pub reproducibility: Reproducibility,
    pub results: Results,
    #[serde(default)]
    pub performance: Option<Performance>,
    pub security: Security,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub protocol_version: String,
    pub timestamp: i64,
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    pub id_task: String,
    pub tipo_analisi: String,
    pub parametri: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reproducibility {
    pub seed_rng: i64,
    pub julia_version: String,
    pub package_manifest_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Results {
    pub metrics: serde_json::Value,
    pub scientific_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Performance {
    pub execution_time_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Security {
    pub payload_hash: String,
    pub results_scientific_hash: String,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub consensus_status: String,
    #[serde(default)]
    pub pow_nonce: Option<i64>,
    #[serde(default)]
    pub pow_hash: Option<String>,
}

/// Categories of critic-rejection. Each variant carries a short `rationale`
/// string — required by sprint risk-mitigation row 4 — so operators can see
/// exactly why a block was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail")]
pub enum Violation {
    #[error("reflexive: {rationale}")]
    Reflexive { rationale: String },
    #[error("symbolic: {rationale}")]
    Symbolic { rationale: String },
    #[error("axiomatic: {rationale}")]
    Axiomatic { rationale: String },
    #[error("malformed: {rationale}")]
    Malformed { rationale: String },
}

impl Violation {
    pub fn reflexive(msg: impl Into<String>) -> Self {
        Self::Reflexive {
            rationale: msg.into(),
        }
    }
    pub fn symbolic(msg: impl Into<String>) -> Self {
        Self::Symbolic {
            rationale: msg.into(),
        }
    }
    pub fn axiomatic(msg: impl Into<String>) -> Self {
        Self::Axiomatic {
            rationale: msg.into(),
        }
    }
    pub fn malformed(msg: impl Into<String>) -> Self {
        Self::Malformed {
            rationale: msg.into(),
        }
    }
}

/// Public critic trait — the signer sees only this interface.
pub trait Critic: Send + Sync {
    fn check(&self, block: &Block) -> Result<(), Violation>;
}

/// Canonical critic built from the three deterministic checks.
#[derive(Debug, Default, Clone)]
pub struct DefaultCritic {
    pub forbidden_terms: Vec<String>,
}

impl DefaultCritic {
    pub fn new() -> Self {
        Self {
            forbidden_terms: default_forbidden_terms()
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    pub fn with_terms(terms: Vec<String>) -> Self {
        Self {
            forbidden_terms: terms,
        }
    }
}

impl Critic for DefaultCritic {
    fn check(&self, block: &Block) -> Result<(), Violation> {
        reflexive::check_reflexive(block)?;
        symbolic::check_symbolic(block)?;
        axiomatic::check_axiomatic(block, &self.forbidden_terms)?;
        Ok(())
    }
}

/// Default forbidden-term corpus. These are the terms that, appearing in a
/// block's payload, constitute prima-facie evidence of attempted Prometheus
/// Clause circumvention. The list is intentionally narrow — false positives
/// on legitimate oncology research would be a sprint-blocking regression
/// (see sprint §6 risk row 4).
pub fn default_forbidden_terms() -> &'static [&'static str] {
    &[
        // §2.1 autonomous lethal systems
        "autonomous_weapon",
        "lethal_targeting",
        "kill_chain_automation",
        // §2.2 mass surveillance
        "mass_surveillance",
        "bulk_civilian_collection",
        "social_scoring",
        // §2.3 rent extraction on medical knowledge
        "paywall_medical_knowledge",
        "deny_patient_access",
        // §2.4 axiomatic circumvention
        "disable_axiom",
        "bypass_santuario",
        "remove_prometheus_clause",
    ]
}

/// Serialize the subset of a block that `security.payload_hash` must cover
/// to the canonical JSON form (sorted keys, no whitespace).
///
/// The wire format in `docs/AGP-v1.md §2` defines the hash as
/// `sha256(canonical_json({header,payload,reproducibility,results}))`.
pub fn canonical_hash_input(block: &Block) -> Result<Vec<u8>, serde_json::Error> {
    let obj = serde_json::json!({
        "header": block.header,
        "payload": block.payload,
        "reproducibility": block.reproducibility,
        "results": block.results,
    });
    // sort_keys via a recursive walk — serde_json does not guarantee key
    // order otherwise. Using Value::to_string produces stable output for
    // scalars but Object ordering follows insertion; sort explicitly.
    let sorted = sort_json_keys(&obj);
    serde_json::to_vec(&sorted)
}

fn sort_json_keys(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), sort_json_keys(&map[&k]));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_json_keys).collect())
        }
        other => other.clone(),
    }
}

/// Parse a block from a JSON string. Used by corpus-driven tests and by
/// `santuarioctl inspect`.
pub fn parse_block(s: &str) -> Result<Block, Violation> {
    serde_json::from_str(s).map_err(|e| Violation::malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_hash_is_stable_on_reorder() {
        let a = r#"{
            "header": {"protocol_version":"AGP-v1","timestamp":1,"node_id":"n"},
            "payload": {"id_task":"TASK-1","tipo_analisi":"genome_analysis","parametri":{"sequence":"ACGT"}},
            "reproducibility": {"seed_rng":1,"julia_version":"1.10.2","package_manifest_hash":"sha256:x"},
            "results": {"metrics":{"gc":0.5},"scientific_hash":"sha256:y"},
            "security": {"payload_hash":"","results_scientific_hash":"sha256:y"}
        }"#;
        let b = r#"{
            "results": {"scientific_hash":"sha256:y","metrics":{"gc":0.5}},
            "header": {"node_id":"n","timestamp":1,"protocol_version":"AGP-v1"},
            "reproducibility": {"package_manifest_hash":"sha256:x","julia_version":"1.10.2","seed_rng":1},
            "payload": {"parametri":{"sequence":"ACGT"},"tipo_analisi":"genome_analysis","id_task":"TASK-1"},
            "security": {"payload_hash":"","results_scientific_hash":"sha256:y"}
        }"#;
        let ha = canonical_hash_input(&parse_block(a).unwrap()).unwrap();
        let hb = canonical_hash_input(&parse_block(b).unwrap()).unwrap();
        assert_eq!(ha, hb);
    }

    #[test]
    fn forbidden_terms_are_stable() {
        let terms = default_forbidden_terms();
        assert!(terms.contains(&"autonomous_weapon"));
        assert!(terms.contains(&"mass_surveillance"));
        assert!(terms.contains(&"disable_axiom"));
    }
}
