from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Callable


VALIDATED = "VALIDATED"
REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class PoCResult:
    verdict: str
    reason: str
    expected_scientific_hash: str
    observed_scientific_hash: str


def canonical_json_hash(obj: Any) -> bytes:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).digest()


def should_validate_block(payload: dict[str, Any], validator_id: str, sample_rate_pct: int) -> bool:
    if sample_rate_pct <= 0:
        return False
    if sample_rate_pct >= 100:
        return True

    payload_hash = payload.get("security", {}).get("payload_hash", "")
    selector_material = f"{payload_hash}:{validator_id}".encode("utf-8")
    selector = int.from_bytes(hashlib.sha256(selector_material).digest()[:8], "big")
    return selector % 100 < sample_rate_pct


def build_reexecution_request(payload: dict[str, Any]) -> dict[str, Any]:
    task = payload["payload"]
    reproducibility = payload["reproducibility"]
    return {
        "id_task": task["id_task"],
        "tipo_analisi": task["tipo_analisi"],
        "parametri": task.get("parametri", {}),
        "reproducibility": {
            "seed_rng": reproducibility["seed_rng"],
            "julia_version_expected": reproducibility.get("julia_version"),
            "package_manifest_hash": reproducibility.get("package_manifest_hash"),
        },
    }


def validate_block_by_reexecution(
    payload: dict[str, Any],
    execute_request: Callable[[dict[str, Any]], dict[str, Any]],
) -> PoCResult:
    expected_hash = str(payload.get("results", {}).get("scientific_hash", ""))
    if not expected_hash:
        return PoCResult(
            verdict=REJECTED,
            reason="missing_expected_scientific_hash",
            expected_scientific_hash="",
            observed_scientific_hash="",
        )
    try:
        reply = execute_request(build_reexecution_request(payload))
    except Exception as exc:  # noqa: BLE001
        return PoCResult(
            verdict=REJECTED,
            reason=f"reexecution_failed:{exc}",
            expected_scientific_hash=expected_hash,
            observed_scientific_hash="",
        )

    if reply.get("status") != "ok":
        return PoCResult(
            verdict=REJECTED,
            reason=f"engine_error:{reply.get('error')}",
            expected_scientific_hash=expected_hash,
            observed_scientific_hash=str(reply.get("scientific_hash", "")),
        )

    observed_metrics = reply.get("metrics", {})
    observed_hash = canonical_json_hash(observed_metrics).hex()
    
    if observed_hash == expected_hash:
        return PoCResult(
            verdict=VALIDATED,
            reason="scientific_hash_match",
            expected_scientific_hash=expected_hash,
            observed_scientific_hash=observed_hash,
        )

    return PoCResult(
        verdict=REJECTED,
        reason="scientific_hash_mismatch",
        expected_scientific_hash=expected_hash,
        observed_scientific_hash=observed_hash,
    )


def build_poc_verdict(
    *,
    validator_id: str,
    block_payload: dict[str, Any],
    result: PoCResult,
    santuario_client,
) -> dict[str, Any]:
    public_key = santuario_client.get_public_key()
    body = {
        "validator_id": validator_id,
        "producer_id": block_payload["header"]["node_id"],
        "block_payload_hash": block_payload["security"]["payload_hash"],
        "id_task": block_payload["payload"]["id_task"],
        "verdict": result.verdict,
        "reason": result.reason,
        "expected_scientific_hash": result.expected_scientific_hash,
        "observed_scientific_hash": result.observed_scientific_hash,
        "timestamp": int(time.time()),
    }
    body_hash = canonical_json_hash(body)
    signature = santuario_client.sign(body_hash)
    return {
        "kind": "poc_verdict",
        "payload": body,
        "security": {
            "payload_hash": body_hash.hex(),
            "signature": signature.hex(),
            "public_key": public_key.hex(),
        },
    }


def verify_poc_verdict(message: dict[str, Any], santuario_client) -> tuple[bool, str]:
    payload = message.get("payload")
    security = message.get("security")
    if not isinstance(payload, dict) or not isinstance(security, dict):
        return False, "missing payload or security block"

    try:
        claimed_hash = bytes.fromhex(security.get("payload_hash", ""))
        expected_hash = canonical_json_hash(payload)
        if claimed_hash != expected_hash:
            return False, "payload_hash mismatch"

        signature = bytes.fromhex(security.get("signature", ""))
        public_key = bytes.fromhex(security.get("public_key", ""))
    except (TypeError, ValueError):
        return False, "malformed hex field"

    if payload.get("verdict") not in {VALIDATED, REJECTED}:
        return False, "invalid verdict"

    if not santuario_client.verify(claimed_hash, signature, public_key):
        return False, "invalid cryptographic signature"

    return True, "ok"
