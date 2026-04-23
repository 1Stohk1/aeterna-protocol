//! Phase C acceptance test. Drives the entire critic against the corpus
//! checked in at `tests/corpus/{poisoned,clean}/*.json`. The contract:
//!
//! - **50 poisoned** files → all MUST produce a `Violation` of the
//!   expected variant (encoded in the filename prefix: `rx-` reflexive,
//!   `sx-` symbolic, `ax-` axiomatic).
//! - **50 clean** files → all MUST pass.
//!
//! A single failure in either direction fails the sprint.

use santuario_critic::{parse_block, Critic, DefaultCritic, Violation};
use std::fs;
use std::path::Path;

fn load_corpus(subdir: &str) -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join(subdir);
    let mut out = Vec::new();
    for entry in fs::read_dir(&root).expect("corpus dir present") {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") {
            continue;
        }
        let body = fs::read_to_string(entry.path()).unwrap();
        out.push((name, body));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn expected_variant(name: &str) -> &'static str {
    if name.starts_with("rx-") {
        "reflexive"
    } else if name.starts_with("sx-") {
        "symbolic"
    } else if name.starts_with("ax-") {
        "axiomatic"
    } else if name.starts_with("mx-") {
        "malformed"
    } else {
        "any"
    }
}

fn matches_variant(v: &Violation, expected: &str) -> bool {
    matches!(
        (v, expected),
        (Violation::Reflexive { .. }, "reflexive")
            | (Violation::Symbolic { .. }, "symbolic")
            | (Violation::Axiomatic { .. }, "axiomatic")
            | (Violation::Malformed { .. }, "malformed")
            | (_, "any")
    )
}

#[test]
fn poisoned_corpus_is_universally_rejected() {
    let critic = DefaultCritic::new();
    let corpus = load_corpus("poisoned");
    assert!(
        corpus.len() >= 50,
        "poisoned corpus must contain at least 50 entries, got {}",
        corpus.len()
    );
    let mut failures = Vec::new();
    for (name, body) in &corpus {
        let expected = expected_variant(name);
        let verdict = parse_block(body).and_then(|b| critic.check(&b));
        match verdict {
            Err(v) if matches_variant(&v, expected) => {}
            Err(v) => failures.push(format!(
                "{name}: wrong variant, expected {expected}, got {v:?}"
            )),
            Ok(()) => failures.push(format!("{name}: accepted but MUST be rejected")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} poisoned corpus failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn clean_corpus_is_universally_accepted() {
    let critic = DefaultCritic::new();
    let corpus = load_corpus("clean");
    assert!(
        corpus.len() >= 50,
        "clean corpus must contain at least 50 entries, got {}",
        corpus.len()
    );
    let mut failures = Vec::new();
    for (name, body) in &corpus {
        match parse_block(body).and_then(|b| critic.check(&b)) {
            Ok(()) => {}
            Err(v) => failures.push(format!("{name}: rejected with {v:?}")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} clean corpus failures (false positives):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
