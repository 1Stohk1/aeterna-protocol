#!/usr/bin/env python3
"""Python-side simulator for the Rust santuario-critic.

Replays the three checks (reflexive/symbolic/axiomatic) against the
corpus in santuario/critic/tests/corpus/{clean,poisoned}/ and asserts
that clean blocks pass and poisoned blocks fail with the expected
variant encoded in the filename prefix.

This is NOT a substitute for `cargo test -p santuario-critic` — it
exists so we can gate the corpus on a machine without rustc installed.
Any mismatch between this simulator and the Rust critic is a bug in
this script first, but it catches 95% of corpus errors.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
CORPUS = REPO / "santuario" / "critic" / "tests" / "corpus"

ALLOWED_TASK_KINDS = {
    "genome_analysis",
    "genomic_entropy",
    "dna_mutation_hamming",
    "tumor_growth_gompertz",
    "tumor_therapy_sde",
    "protein_folding_hp",
}

FORBIDDEN_TERMS = [
    "autonomous_weapon",
    "lethal_targeting",
    "kill_chain_automation",
    "mass_surveillance",
    "bulk_civilian_collection",
    "social_scoring",
    "paywall_medical_knowledge",
    "deny_patient_access",
    "disable_axiom",
    "bypass_santuario",
    "remove_prometheus_clause",
]


def canonical_sort(obj):
    if isinstance(obj, dict):
        return {k: canonical_sort(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [canonical_sort(v) for v in obj]
    return obj


def payload_hash(block: dict) -> str:
    subset = {
        "header": block["header"],
        "payload": block["payload"],
        "reproducibility": block["reproducibility"],
        "results": block["results"],
    }
    canon = json.dumps(
        canonical_sort(subset), separators=(",", ":"), ensure_ascii=False
    )
    return f"sha256:{hashlib.sha256(canon.encode('utf-8')).hexdigest()}"


def reflexive(b: dict) -> str | None:
    if b["security"]["results_scientific_hash"] != b["results"]["scientific_hash"]:
        return "reflexive: scientific_hash mismatch"
    computed = payload_hash(b)
    claimed = b["security"]["payload_hash"]
    norm = lambda s: s.removeprefix("sha256:").lower()
    if norm(computed) != norm(claimed):
        return f"reflexive: payload_hash mismatch (computed={computed}, claimed={claimed})"
    return None


def is_word_char(c: str) -> bool:
    return c.isalnum() or c == "_"


def whole_word(hay: str, needle: str) -> bool:
    if not needle:
        return False
    hay_l = hay.lower()
    ndl_l = needle.lower()
    i = 0
    while (j := hay_l.find(ndl_l, i)) != -1:
        before_ok = j == 0 or not is_word_char(hay_l[j - 1])
        after = j + len(ndl_l)
        after_ok = after >= len(hay_l) or not is_word_char(hay_l[after])
        if before_ok and after_ok:
            return True
        i = j + 1
    return False


def require_fields(obj, fields, kind):
    if not isinstance(obj, dict):
        return f"parametri for '{kind}' must be an object"
    for f in fields:
        if f not in obj:
            return f"parametri for '{kind}' missing required field '{f}'"
    return None


def require_positive_float(obj, field):
    v = obj.get(field)
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        return f"parametri.{field} must be a number"
    try:
        x = float(v)
    except (TypeError, ValueError):
        return f"parametri.{field} must be a number"
    if not (x > 0.0) or x != x or x in (float("inf"), float("-inf")):
        return f"parametri.{field} must be positive and finite, got {x}"
    return None


def require_positive_int(obj, field):
    v = obj.get(field)
    if not isinstance(v, int) or isinstance(v, bool):
        return f"parametri.{field} must be an integer"
    if v <= 0:
        return f"parametri.{field} must be positive, got {v}"
    return None


def symbolic(b: dict) -> str | None:
    h = b.get("header", {})
    p = b.get("payload", {})
    r = b.get("reproducibility", {})

    if h.get("protocol_version") != "AGP-v1":
        return f"symbolic: protocol_version != AGP-v1"
    if not p.get("id_task", "").startswith("TASK-"):
        return "symbolic: id_task prefix"
    t = p.get("tipo_analisi", "")
    if t not in ALLOWED_TASK_KINDS:
        return f"symbolic: tipo_analisi '{t}' not allowed"
    params = p.get("parametri")
    if t in ("genome_analysis", "genomic_entropy"):
        err = require_fields(params, ["sequence"], t)
        if err:
            return "symbolic: " + err
    elif t == "dna_mutation_hamming":
        err = require_fields(params, ["ref", "obs"], t)
        if err:
            return "symbolic: " + err
        if len(params["ref"]) != len(params["obs"]):
            return "symbolic: hamming unequal length"
    elif t == "tumor_growth_gompertz":
        err = require_fields(params, ["N0", "rho", "K", "sigma", "days"], t)
        if err:
            return "symbolic: " + err
        for f in ("N0", "K"):
            err = require_positive_float(params, f)
            if err:
                return "symbolic: " + err
        err = require_positive_int(params, "days")
        if err:
            return "symbolic: " + err
    elif t == "tumor_therapy_sde":
        err = require_fields(
            params,
            ["N0", "rho", "K", "sigma", "days", "efficacia_farmaco", "giorno_inizio"],
            t,
        )
        if err:
            return "symbolic: " + err
        for f in ("N0", "K"):
            err = require_positive_float(params, f)
            if err:
                return "symbolic: " + err
        err = require_positive_int(params, "days")
        if err:
            return "symbolic: " + err
    elif t == "protein_folding_hp":
        err = require_fields(params, ["sequence", "steps"], t)
        if err:
            return "symbolic: " + err
        err = require_positive_int(params, "steps")
        if err:
            return "symbolic: " + err

    if r.get("seed_rng", 0) < 0:
        return "symbolic: negative seed_rng"
    return None


def axiomatic(b: dict) -> str | None:
    blob = (json.dumps(b["payload"]) + " " + json.dumps(b["results"])).lower()
    for t in FORBIDDEN_TERMS:
        if whole_word(blob, t):
            return f"axiomatic: forbidden term '{t}'"
    if b["security"].get("consensus_status", "").upper() == "REJECTED":
        return "axiomatic: consensus_status=REJECTED"
    return None


def critic(b: dict) -> str | None:
    for fn in (reflexive, symbolic, axiomatic):
        err = fn(b)
        if err:
            return err
    return None


def expected_variant(name: str) -> str:
    for p in ("rx", "sx", "ax", "mx"):
        if name.startswith(f"{p}-"):
            return {"rx": "reflexive", "sx": "symbolic", "ax": "axiomatic", "mx": "malformed"}[p]
    return "any"


def main() -> int:
    fails = []
    clean = sorted((CORPUS / "clean").glob("*.json"))
    poisoned = sorted((CORPUS / "poisoned").glob("*.json"))
    assert len(clean) >= 50, f"expected >=50 clean, got {len(clean)}"
    assert len(poisoned) >= 50, f"expected >=50 poisoned, got {len(poisoned)}"

    for path in clean:
        try:
            b = json.loads(path.read_text())
        except Exception as e:
            fails.append(f"CLEAN {path.name}: bad JSON {e}")
            continue
        err = critic(b)
        if err is not None:
            fails.append(f"CLEAN {path.name}: false positive -> {err}")

    for path in poisoned:
        try:
            b = json.loads(path.read_text())
        except Exception as e:
            # Malformed entries are expected to live in mx-*
            if not path.name.startswith("mx-"):
                fails.append(f"POISONED {path.name}: unexpected JSON error {e}")
            continue
        err = critic(b)
        expected = expected_variant(path.name)
        if err is None:
            fails.append(f"POISONED {path.name}: wrongly accepted (expected {expected})")
            continue
        got = err.split(":", 1)[0]
        if expected != "any" and got != expected:
            fails.append(f"POISONED {path.name}: variant mismatch, expected {expected}, got {got}  ({err})")

    if fails:
        for f in fails:
            print("FAIL", f)
        print(f"\n{len(fails)} failure(s)")
        return 1
    print(f"OK: {len(clean)} clean + {len(poisoned)} poisoned, all variant-correct.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
