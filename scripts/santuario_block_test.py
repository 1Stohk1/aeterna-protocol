#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
import logging
import sys
from pathlib import Path
from typing import Any

sys.path.append(str(Path(__file__).parent.parent))

from core.santuario_client import SantuarioClient
from core.sentinel import Sentinel, SentinelConfig


def _scientific_hash(metrics: dict[str, Any]) -> str:
    raw = json.dumps(metrics, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("santuario_block_test")

    cfg = SentinelConfig.from_toml(Path("aeterna.toml"))
    client = SantuarioClient()
    sentinel = Sentinel(cfg, manifesto_path=Path("MANIFESTO.md"))
    sentinel._santuario = client
    sentinel._public_key = client.get_public_key()

    metrics = {"N_final": 1.23e9, "doubling_days": 14.6}
    task = {
        "id_task": "TASK-santuario-block-test",
        "tipo_analisi": "tumor_growth_gompertz",
        "parametri": {"N0": 1.0e6, "rho": 0.01, "K": 1.0e11, "sigma": 0.02, "days": 30},
    }
    result = {
        "seed_rng": 424242,
        "julia_version": cfg.freeze_julia_version,
        "metrics": metrics,
        "scientific_hash": _scientific_hash(metrics),
        "performance": {"execution_time_ms": 1.0},
    }

    try:
        payload = sentinel.build_agp_payload(task, result)
        nonce, pow_hash = sentinel.solve_pow(payload)
        payload["security"]["pow_nonce"] = nonce
        payload["security"]["pow_hash"] = pow_hash
        sentinel._sign_block(payload)

        valid, reason = sentinel._verify_peer_block(payload)
        if not valid:
            log.error("valid block was rejected: %s", reason)
            return 1
        log.info("valid signed block accepted")

        tampered = copy.deepcopy(payload)
        tampered["results"]["metrics"]["N_final"] = 9.99e9
        valid, reason = sentinel._verify_peer_block(tampered)
        if valid or reason != "payload_hash mismatch":
            log.error("tampered block was not rejected as expected: valid=%s reason=%s", valid, reason)
            return 1
        log.info("tampered block rejected: %s", reason)

        forged = copy.deepcopy(payload)
        forged["security"]["signature"] = "00" + forged["security"]["signature"][2:]
        valid, reason = sentinel._verify_peer_block(forged)
        if valid or reason != "invalid cryptographic signature":
            log.error("forged signature was not rejected as expected: valid=%s reason=%s", valid, reason)
            return 1
        log.info("forged signature rejected: %s", reason)
    finally:
        client.close()

    log.info("Santuario block verification test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
