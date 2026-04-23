//! Symbolic check — enforce the `payload.parametri` schema from AGP-v1 §3.
//!
//! Each of the six locked `tipo_analisi` values has a tight parameter
//! schema. Any block whose `parametri` does not conform is a protocol
//! violation and the signer MUST refuse.
//!
//! This check is intentionally coarse — it is a schema validator, not a
//! numerical sanity check. Checking e.g. that tumour doubling times are
//! within plausible biological range belongs in the Motore Scientifico,
//! not in the signer's critical path.

use serde_json::Value;

use crate::{Block, Violation};

pub const ALLOWED_TASK_KINDS: &[&str] = &[
    "genome_analysis",
    "genomic_entropy",
    "dna_mutation_hamming",
    "tumor_growth_gompertz",
    "tumor_therapy_sde",
    "protein_folding_hp",
];

pub fn check_symbolic(block: &Block) -> Result<(), Violation> {
    // 1. protocol_version
    if block.header.protocol_version != "AGP-v1" {
        return Err(Violation::symbolic(format!(
            "protocol_version must be 'AGP-v1', got '{}'",
            block.header.protocol_version
        )));
    }
    // 2. id_task prefix
    if !block.payload.id_task.starts_with("TASK-") {
        return Err(Violation::symbolic(format!(
            "id_task must start with 'TASK-', got '{}'",
            block.payload.id_task
        )));
    }
    // 3. tipo_analisi membership
    let t = block.payload.tipo_analisi.as_str();
    if !ALLOWED_TASK_KINDS.contains(&t) {
        return Err(Violation::symbolic(format!(
            "tipo_analisi '{t}' is not one of the six locked task kinds"
        )));
    }
    // 4. parametri per-kind schema
    let p = &block.payload.parametri;
    match t {
        "genome_analysis" | "genomic_entropy" => require_fields(p, &["sequence"], t)?,
        "dna_mutation_hamming" => {
            require_fields(p, &["ref", "obs"], t)?;
            let r = p["ref"].as_str().unwrap_or("");
            let o = p["obs"].as_str().unwrap_or("");
            if r.len() != o.len() {
                return Err(Violation::symbolic(format!(
                    "dna_mutation_hamming: ref and obs must be equal length, got {} vs {}",
                    r.len(),
                    o.len()
                )));
            }
        }
        "tumor_growth_gompertz" => {
            require_fields(p, &["N0", "rho", "K", "sigma", "days"], t)?;
            require_positive_float(p, "N0")?;
            require_positive_float(p, "K")?;
            require_positive_int(p, "days")?;
        }
        "tumor_therapy_sde" => {
            require_fields(
                p,
                &[
                    "N0",
                    "rho",
                    "K",
                    "sigma",
                    "days",
                    "efficacia_farmaco",
                    "giorno_inizio",
                ],
                t,
            )?;
            require_positive_float(p, "N0")?;
            require_positive_float(p, "K")?;
            require_positive_int(p, "days")?;
        }
        "protein_folding_hp" => {
            require_fields(p, &["sequence", "steps"], t)?;
            require_positive_int(p, "steps")?;
        }
        _ => unreachable!("guarded by ALLOWED_TASK_KINDS above"),
    }
    // 5. seed_rng is a plausible int63
    if block.reproducibility.seed_rng < 0 {
        return Err(Violation::symbolic(format!(
            "seed_rng must be non-negative, got {}",
            block.reproducibility.seed_rng
        )));
    }
    Ok(())
}

fn require_fields(v: &Value, fields: &[&str], kind: &str) -> Result<(), Violation> {
    let obj = v
        .as_object()
        .ok_or_else(|| Violation::symbolic(format!("parametri for '{kind}' must be an object")))?;
    for f in fields {
        if !obj.contains_key(*f) {
            return Err(Violation::symbolic(format!(
                "parametri for '{kind}' missing required field '{f}'"
            )));
        }
    }
    Ok(())
}

fn require_positive_float(v: &Value, field: &str) -> Result<(), Violation> {
    let x = v
        .get(field)
        .and_then(|x| x.as_f64())
        .ok_or_else(|| Violation::symbolic(format!("parametri.{field} must be a number")))?;
    if !x.is_finite() || x <= 0.0 {
        return Err(Violation::symbolic(format!(
            "parametri.{field} must be positive and finite, got {x}"
        )));
    }
    Ok(())
}

fn require_positive_int(v: &Value, field: &str) -> Result<(), Violation> {
    let x = v
        .get(field)
        .and_then(|x| x.as_i64())
        .ok_or_else(|| Violation::symbolic(format!("parametri.{field} must be an integer")))?;
    if x <= 0 {
        return Err(Violation::symbolic(format!(
            "parametri.{field} must be positive, got {x}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base() -> Block {
        serde_json::from_value(json!({
            "header": {"protocol_version":"AGP-v1","timestamp":1,"node_id":"n"},
            "payload": {"id_task":"TASK-x","tipo_analisi":"genome_analysis","parametri":{"sequence":"ACGT"}},
            "reproducibility": {"seed_rng":1,"julia_version":"1.10.2","package_manifest_hash":"sha256:x"},
            "results": {"metrics":{},"scientific_hash":"sha256:y"},
            "security": {"payload_hash":"","results_scientific_hash":"sha256:y"}
        })).unwrap()
    }

    #[test]
    fn genome_analysis_minimal_ok() {
        check_symbolic(&base()).unwrap();
    }

    #[test]
    fn unknown_task_kind_rejected() {
        let mut b = base();
        b.payload.tipo_analisi = "nuclear_warhead_targeting".to_string();
        match check_symbolic(&b) {
            Err(Violation::Symbolic { .. }) => {}
            other => panic!("expected Symbolic, got {other:?}"),
        }
    }

    #[test]
    fn missing_gompertz_fields_rejected() {
        let mut b = base();
        b.payload.tipo_analisi = "tumor_growth_gompertz".to_string();
        b.payload.parametri = json!({"N0":1e6});
        match check_symbolic(&b) {
            Err(Violation::Symbolic { .. }) => {}
            other => panic!("expected Symbolic, got {other:?}"),
        }
    }

    #[test]
    fn wrong_protocol_version_rejected() {
        let mut b = base();
        b.header.protocol_version = "AGP-v2".to_string();
        match check_symbolic(&b) {
            Err(Violation::Symbolic { .. }) => {}
            other => panic!("expected Symbolic, got {other:?}"),
        }
    }

    #[test]
    fn id_task_prefix_required() {
        let mut b = base();
        b.payload.id_task = "bogus".to_string();
        match check_symbolic(&b) {
            Err(Violation::Symbolic { .. }) => {}
            other => panic!("expected Symbolic, got {other:?}"),
        }
    }

    #[test]
    fn hamming_unequal_length_rejected() {
        let mut b = base();
        b.payload.tipo_analisi = "dna_mutation_hamming".to_string();
        b.payload.parametri = json!({"ref":"ACGT","obs":"ACG"});
        match check_symbolic(&b) {
            Err(Violation::Symbolic { .. }) => {}
            other => panic!("expected Symbolic, got {other:?}"),
        }
    }
}
