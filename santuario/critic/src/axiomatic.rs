//! Axiomatic check — Prometheus Clause rule engine.
//!
//! Reject any block whose payload contains text that matches the forbidden
//! use corpus derived from ETHICS.md §2:
//!
//! - §2.1 autonomous lethal systems
//! - §2.2 mass surveillance of civilian populations
//! - §2.3 rent extraction on medical knowledge
//! - §2.4 axiomatic circumvention
//!
//! The match is a **whole-word case-insensitive** substring scan over the
//! JSON-serialised `payload` and `results.metrics`. The rule engine is
//! deliberately conservative: a single match of any forbidden term in any
//! string value is enough to reject. The adversarial corpus exercises each
//! rule; the clean corpus exercises the critical false-positive path —
//! legitimate oncology terms like "treatment", "tumor", "patient" MUST NOT
//! trigger.

use crate::{Block, Violation};

pub fn check_axiomatic(block: &Block, forbidden_terms: &[String]) -> Result<(), Violation> {
    // Scan every string leaf of (payload, results). Non-strings are ignored.
    let haystacks = [
        serde_json::to_string(&block.payload).unwrap_or_default(),
        serde_json::to_string(&block.results).unwrap_or_default(),
    ];
    let blob = haystacks.join(" ").to_ascii_lowercase();

    for term in forbidden_terms {
        let needle = term.to_ascii_lowercase();
        if contains_whole_word(&blob, &needle) {
            return Err(Violation::axiomatic(format!(
                "forbidden term matched under ETHICS.md \u{00a7}2: '{term}'"
            )));
        }
    }

    // Explicit structural checks that are not term-matchable:
    // - Reject blocks that admit consensus_status == REJECTED but still
    //   claim a signature is due. The signer must not add signatures to
    //   already-rejected blocks.
    if block
        .security
        .consensus_status
        .eq_ignore_ascii_case("REJECTED")
    {
        return Err(Violation::axiomatic(
            "consensus_status=REJECTED: signer refuses to endorse a rejected block",
        ));
    }

    Ok(())
}

/// Word-ish match — a term surrounded by non-alphanumeric boundaries. Used
/// to reduce false positives like "autonomous_weapon" vs a legitimate
/// mention of the Greek root "autonomous" inside a sequence annotation.
fn contains_whole_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let n = needle.as_bytes();
    let mut i = 0;
    while i + n.len() <= bytes.len() {
        if &bytes[i..i + n.len()] == n {
            let before_ok = i == 0 || !is_word_char(bytes[i - 1]);
            let after = i + n.len();
            let after_ok = after >= bytes.len() || !is_word_char(bytes[after]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_forbidden_terms;
    use serde_json::json;

    fn base() -> Block {
        serde_json::from_value(json!({
            "header": {"protocol_version":"AGP-v1","timestamp":1,"node_id":"n"},
            "payload": {"id_task":"TASK-x","tipo_analisi":"tumor_growth_gompertz","parametri":{"N0":1e6,"rho":0.05,"K":1e12,"sigma":0.1,"days":30}},
            "reproducibility": {"seed_rng":1,"julia_version":"1.10.2","package_manifest_hash":"sha256:x"},
            "results": {"metrics":{},"scientific_hash":"sha256:y"},
            "security": {"payload_hash":"","results_scientific_hash":"sha256:y"}
        })).unwrap()
    }

    fn terms() -> Vec<String> {
        default_forbidden_terms()
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn clean_oncology_block_passes() {
        check_axiomatic(&base(), &terms()).unwrap();
    }

    #[test]
    fn autonomous_weapon_term_rejected() {
        let mut b = base();
        b.payload.parametri = json!({"N0":1e6,"rho":0.05,"K":1e12,"sigma":0.1,"days":30,"note":"autonomous_weapon subtask"});
        match check_axiomatic(&b, &terms()) {
            Err(Violation::Axiomatic { .. }) => {}
            other => panic!("expected Axiomatic, got {other:?}"),
        }
    }

    #[test]
    fn mass_surveillance_term_rejected() {
        let mut b = base();
        b.payload.tipo_analisi = "genome_analysis".to_string();
        b.payload.parametri =
            json!({"sequence":"ACGT","purpose":"mass_surveillance of dissidents"});
        match check_axiomatic(&b, &terms()) {
            Err(Violation::Axiomatic { .. }) => {}
            other => panic!("expected Axiomatic, got {other:?}"),
        }
    }

    #[test]
    fn rejected_status_refused() {
        let mut b = base();
        b.security.consensus_status = "REJECTED".to_string();
        match check_axiomatic(&b, &terms()) {
            Err(Violation::Axiomatic { .. }) => {}
            other => panic!("expected Axiomatic on REJECTED status, got {other:?}"),
        }
    }

    #[test]
    fn benign_prefix_does_not_trigger() {
        // "autonomously" includes "autonomous" as a prefix but the forbidden
        // term is "autonomous_weapon" — different word, MUST pass.
        let mut b = base();
        b.payload.parametri = json!({"N0":1e6,"rho":0.05,"K":1e12,"sigma":0.1,"days":30,"note":"model is autonomously evolving"});
        check_axiomatic(&b, &terms()).unwrap();
    }
}
