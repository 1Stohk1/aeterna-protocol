#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.append(str(Path(__file__).parent.parent))

from core.poc import (
    REJECTED,
    VALIDATED,
    build_poc_verdict,
    should_validate_block,
    validate_block_by_reexecution,
    verify_poc_verdict,
)
from core.trust_score import TrustScoreBook


class FakeSantuarioClient:
    def __init__(self) -> None:
        self._public_key = b"fake-poc-public-key"

    def get_public_key(self) -> bytes:
        return self._public_key

    def sign(self, payload_hash: bytes) -> bytes:
        return payload_hash[::-1] + self._public_key

    def verify(self, payload_hash: bytes, signature: bytes, public_key: bytes) -> bool:
        return signature == payload_hash[::-1] + public_key


def _hash_metrics(metrics: dict[str, Any]) -> str:
    raw = json.dumps(metrics, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _payload(scientific_hash: str) -> dict[str, Any]:
    return {
        "header": {
            "protocol_version": "AGP-v1",
            "timestamp": 1,
            "node_id": "Prometheus-0",
        },
        "payload": {
            "id_task": "TASK-poc-test",
            "tipo_analisi": "tumor_growth_gompertz",
            "parametri": {"N0": 1.0e6, "rho": 0.01, "K": 1.0e11, "sigma": 0.02, "days": 30},
        },
        "reproducibility": {
            "seed_rng": 424242,
            "julia_version": "1.10.2",
            "package_manifest_hash": "test-manifest",
        },
        "results": {
            "metrics": {"N_final": 123.0},
            "scientific_hash": scientific_hash,
        },
        "security": {
            "payload_hash": "a" * 64,
        },
    }


def main() -> int:
    expected_hash = _hash_metrics({"N_final": 123.0})
    payload = _payload(expected_hash)

    assert should_validate_block(payload, "Prometheus-1", 100)
    assert not should_validate_block(payload, "Prometheus-1", 0)

    ok = validate_block_by_reexecution(
        payload,
        lambda _req: {"status": "ok", "scientific_hash": expected_hash},
    )
    if ok.verdict != VALIDATED:
        print(f"expected VALIDATED, got {ok}")
        return 1

    bad = validate_block_by_reexecution(
        payload,
        lambda _req: {"status": "ok", "scientific_hash": _hash_metrics({"N_final": 999.0})},
    )
    if bad.verdict != REJECTED or bad.reason != "scientific_hash_mismatch":
        print(f"expected REJECTED mismatch, got {bad}")
        return 1

    santuario = FakeSantuarioClient()
    verdict_message = build_poc_verdict(
        validator_id="Prometheus-1",
        block_payload=payload,
        result=ok,
        santuario_client=santuario,
    )
    valid, reason = verify_poc_verdict(verdict_message, santuario)
    if not valid:
        print(f"valid verdict rejected: {reason}")
        return 1

    verdict_message["payload"]["verdict"] = "MAYBE"
    valid, reason = verify_poc_verdict(verdict_message, santuario)
    if valid or reason != "payload_hash mismatch":
        print(f"tampered verdict not rejected correctly: valid={valid} reason={reason}")
        return 1

    trust = TrustScoreBook()
    if trust.apply_poc_verdict("Prometheus-0", VALIDATED) != 1:
        return 1
    if trust.apply_poc_verdict("Prometheus-0", REJECTED) != -1:
        return 1
    if trust.get("Prometheus-0") != 0:
        return 1

    print("PoC naive validation test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
