//! Reflexive check — `payload_hash` must match the SHA-256 of the
//! canonical JSON of the `{header,payload,reproducibility,results}` tuple.
//!
//! This is a primary cheap filter. If reflexive fails, the block is either
//! malformed or deliberately spoofed, and the signer MUST refuse — without
//! this check the Santuario would blindly sign whatever hash the Sentinel
//! presented, defeating the entire point of pre-sign verification.

use sha2::{Digest, Sha256};

use crate::{canonical_hash_input, Block, Violation};

/// Re-compute the canonical SHA-256 payload hash and compare it to
/// `block.security.payload_hash`. Also verifies
/// `block.security.results_scientific_hash` equals
/// `block.results.scientific_hash` — those two fields MUST agree by
/// AGP-v1 §2 (the separate field exists only for convenience during
/// gossip relay).
pub fn check_reflexive(block: &Block) -> Result<(), Violation> {
    // 1. scientific_hash consistency
    if block.security.results_scientific_hash != block.results.scientific_hash {
        return Err(Violation::reflexive(format!(
            "security.results_scientific_hash ({}) disagrees with results.scientific_hash ({})",
            block.security.results_scientific_hash, block.results.scientific_hash
        )));
    }

    // 2. payload_hash consistency
    let canonical = canonical_hash_input(block)
        .map_err(|e| Violation::malformed(format!("cannot canonicalise block: {e}")))?;
    let mut h = Sha256::new();
    h.update(&canonical);
    let computed = format!("sha256:{}", hex::encode(h.finalize()));

    let claimed = &block.security.payload_hash;
    // Accept both the `sha256:HEX` form used on the wire and a bare hex form
    // for older fixtures — but they must decode to the same digest bytes.
    let normalise = |s: &str| -> String {
        s.trim_start_matches("sha256:").to_ascii_lowercase()
    };
    if normalise(&computed) != normalise(claimed) {
        return Err(Violation::reflexive(format!(
            "payload_hash mismatch: claimed={claimed} computed={computed}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    fn mk_block(payload_hash: &str) -> Block {
        let mut block: Block = serde_json::from_str(r#"{
            "header": {"protocol_version":"AGP-v1","timestamp":1,"node_id":"Prometheus-0"},
            "payload": {"id_task":"TASK-a","tipo_analisi":"genome_analysis","parametri":{"sequence":"ACGT"}},
            "reproducibility": {"seed_rng":42,"julia_version":"1.10.2","package_manifest_hash":"sha256:abc"},
            "results": {"metrics":{"gc_content":0.5},"scientific_hash":"sha256:res"},
            "security": {"payload_hash":"PLACEHOLDER","results_scientific_hash":"sha256:res"}
        }"#).unwrap();
        block.security.payload_hash = payload_hash.to_string();
        block
    }

    fn canonical_digest(block: &Block) -> String {
        let bytes = canonical_hash_input(block).unwrap();
        let mut h = Sha256::new();
        h.update(&bytes);
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    #[test]
    fn reflexive_accepts_correct_hash() {
        let mut b = mk_block("PLACEHOLDER");
        let real = canonical_digest(&b);
        b.security.payload_hash = real;
        check_reflexive(&b).unwrap();
    }

    #[test]
    fn reflexive_rejects_wrong_hash() {
        let b = mk_block("sha256:0000000000000000000000000000000000000000000000000000000000000000");
        match check_reflexive(&b) {
            Err(Violation::Reflexive { .. }) => {}
            other => panic!("expected Reflexive, got {other:?}"),
        }
    }

    #[test]
    fn reflexive_rejects_mismatched_scientific_hash() {
        let mut b = mk_block("PLACEHOLDER");
        let real = canonical_digest(&b);
        b.security.payload_hash = real;
        b.security.results_scientific_hash = "sha256:different".to_string();
        match check_reflexive(&b) {
            Err(Violation::Reflexive { .. }) => {}
            other => panic!("expected Reflexive, got {other:?}"),
        }
    }
}
