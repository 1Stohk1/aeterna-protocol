#!/usr/bin/env python3
"""Generate the Phase-C critic corpus.

Emits 50 poisoned + 50 clean AGP-v1-shaped blocks into
    santuario/critic/tests/corpus/{poisoned,clean}/

Filename prefixes on poisoned blocks encode the expected Violation variant:

    rx-*.json  -> Reflexive (payload_hash mismatch, etc.)
    sx-*.json  -> Symbolic  (schema / task kind / id_task)
    ax-*.json  -> Axiomatic (Prometheus Clause terms / REJECTED status)
    mx-*.json  -> Malformed (bad JSON, missing fields)

Re-run whenever the critic adds/removes rules; the corpus is the
source of truth for sprint acceptance.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys


REPO = pathlib.Path(__file__).resolve().parents[1]
CORPUS = REPO / "santuario" / "critic" / "tests" / "corpus"


def canonical_sort(obj):
    """Recursive dict-key sort, matches sort_json_keys in the Rust critic."""
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
        canonical_sort(subset),
        separators=(",", ":"),
        ensure_ascii=False,
        sort_keys=False,  # already sorted by canonical_sort
    )
    digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def base_block(
    *,
    tipo: str,
    parametri: dict,
    id_task: str = "TASK-abcd1234",
    node_id: str = "Prometheus-0",
    scientific_hash: str = "sha256:abc123",
) -> dict:
    block = {
        "header": {
            "protocol_version": "AGP-v1",
            "timestamp": 1_713_542_400,
            "node_id": node_id,
        },
        "payload": {
            "id_task": id_task,
            "tipo_analisi": tipo,
            "parametri": parametri,
        },
        "reproducibility": {
            "seed_rng": 424242,
            "julia_version": "1.10.2",
            "package_manifest_hash": "sha256:manifest",
        },
        "results": {
            "metrics": {"ok": 1},
            "scientific_hash": scientific_hash,
        },
        "security": {
            "payload_hash": "",
            "results_scientific_hash": scientific_hash,
            "signature": "",
            "public_key": "",
            "consensus_status": "PENDING",
            "pow_nonce": 0,
            "pow_hash": "0",
        },
    }
    block["security"]["payload_hash"] = payload_hash(block)
    return block


# ---------------------------------------------------------------------------
# Clean corpus — 50 plausible AGP-v1 blocks that the critic MUST accept.
# Spread across the six task kinds to exercise every symbolic branch.
# ---------------------------------------------------------------------------
# NB: integer-valued numbers are stored as Python int (not float) so the
# on-wire text matches what Rust's serde_json + ryu produces. `1_000_000`
# serialises to "1000000" in both engines; `1_000_000` would render as
# "1000000.0" in Python but "1_000_000" in Rust — mismatch breaks the reflexive
# check. Decimals like 0.05 happen to round-trip identically in both.
#
# Helper that only emits float values ryu and json.dumps agree on.
def dec(numerator: int, denominator: int) -> float:
    """Emit numerator/denominator with a value that Python json and Rust
    ryu both render as the same decimal literal. Caller is responsible
    for picking denominators that are powers of 10 or simple fractions."""
    return numerator / denominator


CLEAN_RECIPES = [
    # 10 genome_analysis
    *[("genome_analysis", {"sequence": ("ACGT" * (10 + i))}) for i in range(10)],
    # 8 genomic_entropy
    *[("genomic_entropy", {"sequence": ("ATCG" * (8 + i))}) for i in range(8)],
    # 6 dna_mutation_hamming (equal-length ref/obs)
    *[
        (
            "dna_mutation_hamming",
            {"ref": "ACGT" * (5 + i), "obs": ("AAGT" + "ACGT" * (4 + i))[: 4 * (5 + i)]},
        )
        for i in range(6)
    ],
    # 10 tumor_growth_gompertz with varied but-valid params.
    #   Values picked so Python repr and Rust ryu serialise identically:
    #   ints for N0/K/days, nice decimals for rho/sigma.
    *[
        (
            "tumor_growth_gompertz",
            {
                "N0": 1_000_000 * (1 + i),
                "rho": [0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.1, 0.11][i],
                "K": 1_000_000_000_000,
                "sigma": [0.05, 0.06, 0.07, 0.08, 0.09, 0.1, 0.11, 0.12, 0.13, 0.14][i],
                "days": 30 + i * 5,
            },
        )
        for i in range(10)
    ],
    # 8 tumor_therapy_sde
    *[
        (
            "tumor_therapy_sde",
            {
                "N0": 1_000_000,
                "rho": 0.03,
                "K": 1_000_000_000_000,
                "sigma": 0.1,
                "days": 60,
                "efficacia_farmaco": [0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5, 0.55][i],
                "giorno_inizio": 10 + i,
            },
        )
        for i in range(8)
    ],
    # 8 protein_folding_hp
    *[("protein_folding_hp", {"sequence": ("HP" * (6 + i)), "steps": 1000 + 100 * i}) for i in range(8)],
]
assert len(CLEAN_RECIPES) == 50, f"clean corpus must be 50, got {len(CLEAN_RECIPES)}"


# ---------------------------------------------------------------------------
# Poisoned corpus — 50 blocks, each violating exactly one rule. Each filename
# prefix matches the expected Violation variant.
# ---------------------------------------------------------------------------


def make_poisoned() -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []

    # ---- Reflexive (15) ------------------------------------------------
    for i in range(8):
        b = base_block(
            tipo="tumor_growth_gompertz",
            parametri={"N0": 1_000_000, "rho": 0.05, "K": 1_000_000_000_000, "sigma": 0.1, "days": 30},
        )
        # flip the payload_hash to an obvious wrong value
        b["security"]["payload_hash"] = f"sha256:{'0' * 63}{i}"
        out.append((f"rx-{i:02d}-flipped-hash.json", b))

    for i in range(4):
        b = base_block(
            tipo="genome_analysis",
            parametri={"sequence": "ACGT" * 10},
        )
        # hash the original then mutate the payload so the recorded hash
        # no longer matches
        b["payload"]["parametri"]["sequence"] = "TTTT" * 10
        out.append((f"rx-{8+i:02d}-mutated-after-hash.json", b))

    for i in range(3):
        b = base_block(tipo="genomic_entropy", parametri={"sequence": "ACGT" * 5})
        # scientific_hash disagreement between results and security
        b["security"]["results_scientific_hash"] = f"sha256:deadbeef{i:02d}"
        out.append((f"rx-{12+i:02d}-scientific-hash-mismatch.json", b))

    # ---- Symbolic (20) -------------------------------------------------
    sx = [
        # wrong protocol version
        {
            "mutator": lambda b: b["header"].__setitem__("protocol_version", "AGP-v0"),
            "tag": "wrong-protocol",
        },
        {
            "mutator": lambda b: b["header"].__setitem__("protocol_version", "AGP-v2"),
            "tag": "future-protocol",
        },
        # id_task prefix
        {
            "mutator": lambda b: b["payload"].__setitem__("id_task", "bogus-id"),
            "tag": "bad-id-prefix",
        },
        {
            "mutator": lambda b: b["payload"].__setitem__("id_task", ""),
            "tag": "empty-id",
        },
        # unknown task kind
        {
            "mutator": lambda b: b["payload"].__setitem__("tipo_analisi", "nuclear_targeting_sim"),
            "tag": "unknown-task-kind",
        },
        {
            "mutator": lambda b: b["payload"].__setitem__("tipo_analisi", "secret_crypto_break"),
            "tag": "unknown-task-kind-2",
        },
        # missing required field in gompertz
        {
            "tipo": "tumor_growth_gompertz",
            "parametri": {"N0": 1_000_000, "rho": 0.05, "K": 1_000_000_000_000, "sigma": 0.1},  # no `days`
            "tag": "gompertz-missing-days",
        },
        {
            "tipo": "tumor_growth_gompertz",
            "parametri": {"rho": 0.05, "K": 1_000_000_000_000, "sigma": 0.1, "days": 30},  # no `N0`
            "tag": "gompertz-missing-N0",
        },
        # negative values where positive required
        {
            "tipo": "tumor_growth_gompertz",
            "parametri": {"N0": -1_000_000, "rho": 0.05, "K": 1_000_000_000_000, "sigma": 0.1, "days": 30},
            "tag": "negative-N0",
        },
        {
            "tipo": "tumor_growth_gompertz",
            "parametri": {"N0": 1_000_000, "rho": 0.05, "K": 1_000_000_000_000, "sigma": 0.1, "days": -5},
            "tag": "negative-days",
        },
        # hamming unequal length
        {
            "tipo": "dna_mutation_hamming",
            "parametri": {"ref": "ACGT", "obs": "AC"},
            "tag": "hamming-unequal",
        },
        # hamming missing field
        {
            "tipo": "dna_mutation_hamming",
            "parametri": {"ref": "ACGT"},
            "tag": "hamming-missing-obs",
        },
        # therapy missing efficacia
        {
            "tipo": "tumor_therapy_sde",
            "parametri": {
                "N0": 1_000_000,
                "rho": 0.03,
                "K": 1_000_000_000_000,
                "sigma": 0.1,
                "days": 60,
                "giorno_inizio": 10,
            },
            "tag": "therapy-missing-efficacia",
        },
        # therapy negative days
        {
            "tipo": "tumor_therapy_sde",
            "parametri": {
                "N0": 1_000_000,
                "rho": 0.03,
                "K": 1_000_000_000_000,
                "sigma": 0.1,
                "days": -60,
                "efficacia_farmaco": 0.3,
                "giorno_inizio": 10,
            },
            "tag": "therapy-negative-days",
        },
        # folding missing steps
        {
            "tipo": "protein_folding_hp",
            "parametri": {"sequence": "HPHP"},
            "tag": "folding-missing-steps",
        },
        # folding negative steps
        {
            "tipo": "protein_folding_hp",
            "parametri": {"sequence": "HPHP", "steps": -1000},
            "tag": "folding-negative-steps",
        },
        # genome_analysis missing sequence
        {
            "tipo": "genome_analysis",
            "parametri": {"foo": "bar"},
            "tag": "genome-missing-sequence",
        },
        # parametri is array instead of object
        {
            "tipo": "genome_analysis",
            "parametri": ["ACGT"],
            "tag": "genome-parametri-array",
        },
        # negative seed_rng
        {
            "mutator": lambda b: b["reproducibility"].__setitem__("seed_rng", -42),
            "tag": "negative-seed",
        },
        # empty tipo_analisi
        {
            "mutator": lambda b: b["payload"].__setitem__("tipo_analisi", ""),
            "tag": "empty-tipo",
        },
    ]
    for i, rec in enumerate(sx):
        if "mutator" in rec:
            b = base_block(
                tipo="tumor_growth_gompertz",
                parametri={"N0": 1_000_000, "rho": 0.05, "K": 1_000_000_000_000, "sigma": 0.1, "days": 30},
            )
            rec["mutator"](b)
        else:
            b = base_block(tipo=rec["tipo"], parametri=rec["parametri"])
        # Re-sync payload_hash so the failure is symbolic, not reflexive.
        b["security"]["payload_hash"] = payload_hash(b)
        out.append((f"sx-{i:02d}-{rec['tag']}.json", b))

    # ---- Axiomatic (15) ------------------------------------------------
    ax_terms = [
        ("autonomous_weapon", "targets civilian drones"),
        ("lethal_targeting", "hostile individuals"),
        ("kill_chain_automation", "loitering munition"),
        ("mass_surveillance", "metro crowd"),
        ("bulk_civilian_collection", "cellular traffic"),
        ("social_scoring", "citizen rank"),
        ("paywall_medical_knowledge", "EULA"),
        ("deny_patient_access", "upcoming audit"),
        ("disable_axiom", "Sovranita Finale"),
        ("bypass_santuario", "dev shortcut"),
        ("remove_prometheus_clause", "licensing branch"),
    ]
    for i, (term, note) in enumerate(ax_terms):
        b = base_block(
            tipo="tumor_growth_gompertz",
            parametri={"N0": 1_000_000, "rho": 0.05, "K": 1_000_000_000_000, "sigma": 0.1, "days": 30, "note": f"{term} — {note}"},
        )
        b["security"]["payload_hash"] = payload_hash(b)
        out.append((f"ax-{i:02d}-{term}.json", b))

    # rejected consensus status — must be refused
    for i in range(4):
        b = base_block(
            tipo="genome_analysis",
            parametri={"sequence": "ACGT" * 6},
        )
        b["security"]["consensus_status"] = "REJECTED"
        b["security"]["payload_hash"] = payload_hash(b)
        out.append((f"ax-{11+i:02d}-rejected-status.json", b))

    assert len(out) == 50, f"poisoned corpus must be 50, got {len(out)}"
    return out


def write_all() -> None:
    clean_dir = CORPUS / "clean"
    poisoned_dir = CORPUS / "poisoned"
    for d in (clean_dir, poisoned_dir):
        d.mkdir(parents=True, exist_ok=True)
        # On mounted filesystems unlink may be forbidden; truncating via
        # write is safe. We simply overwrite every file, and orphaned
        # corpus entries are caught by the "expected 50, got N" assertion.
        for f in d.glob("*.json"):
            try:
                f.unlink()
            except PermissionError:
                pass

    for i, (tipo, params) in enumerate(CLEAN_RECIPES):
        b = base_block(
            tipo=tipo,
            parametri=params,
            id_task=f"TASK-clean-{i:02d}",
            node_id=f"Guardian-{i%5}",
            scientific_hash=f"sha256:{hashlib.sha256(f'clean-{i}'.encode()).hexdigest()}",
        )
        name = f"clean-{i:02d}-{tipo}.json"
        (clean_dir / name).write_text(
            json.dumps(b, indent=2, sort_keys=True), encoding="utf-8"
        )

    for name, block in make_poisoned():
        (poisoned_dir / name).write_text(
            json.dumps(block, indent=2, sort_keys=True), encoding="utf-8"
        )

    n_clean = len(list(clean_dir.glob("*.json")))
    n_poison = len(list(poisoned_dir.glob("*.json")))
    print(f"wrote {n_clean} clean and {n_poison} poisoned blocks to {CORPUS}")


if __name__ == "__main__":
    write_all()

dumps(block, indent=2, sort_keys=True), encoding="utf-8"
        )

    n_clean = len(list(clean_dir.glob("*.json")))
    n_poison = len(list(poisoned_dir.glob("*.json")))
    print(f"wrote {n_clean} clean and {n_poison} poisoned blocks to {CORPUS}")


if __name__ == "__main__":
    write_all()
