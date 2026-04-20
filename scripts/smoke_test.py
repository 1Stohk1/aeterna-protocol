#!/usr/bin/env python3
"""
AETERNA — Sentinel↔Julia smoke test.

Sends one request of each of the six frozen AGP-v1 task kinds directly to the
Julia scientific engine on ``tcp://localhost:5555``. For each kind it:

    1. verifies the response status is "ok",
    2. prints the execution time and scientific_hash,
    3. replays the same request and asserts the scientific_hash is byte-identical
       (determinism under the seed imposed by the Sentinel — PoC prerequisite).

Run this *after* ``./bootstrap.sh`` is up, from another terminal::

    python3 scripts/smoke_test.py

Exit code 0 = all six task kinds healthy and deterministic.
Exit code 1 = at least one task failed or diverged between replays.
"""
from __future__ import annotations

import sys
import time
from typing import Any

import zmq

ENDPOINT = "tcp://localhost:5555"
SEED = 424242

TASKS: list[tuple[str, dict[str, Any]]] = [
    ("genome_analysis",       {"sequence": "GATTACAGATTACAGATTACA"}),
    ("genomic_entropy",       {"sequence": "GATTACAGATTACAGATTACA"}),
    ("dna_mutation_hamming",  {"ref": "GATTACAGATTACA", "obs": "GATTAGAGATTACA"}),
    ("tumor_growth_gompertz", {"N0": 1.0e6, "rho": 0.01, "K": 1.0e11,
                               "sigma": 0.02, "days": 30}),
    ("tumor_therapy_sde",     {"N0": 1.0e6, "rho": 0.01, "K": 1.0e11,
                               "sigma": 0.02, "days": 30,
                               "efficacia_farmaco": 0.35,
                               "giorno_inizio": 10}),
    ("protein_folding_hp",    {"sequence": "HPHPPHHPHPPHPHHPPHPH", "steps": 5_000}),
]


def _send(sock: zmq.Socket, kind: str, params: dict[str, Any]) -> dict[str, Any]:
    req = {
        "id_task": f"smoke-{kind}",
        "tipo_analisi": kind,
        "parametri": params,
        "reproducibility": {
            "seed_rng": SEED,
            "julia_version_expected": "1.10",
            "package_manifest_hash": "smoke-test-constant",
        },
    }
    sock.send_json(req)
    return sock.recv_json()  # type: ignore[return-value]


def main() -> int:
    ctx = zmq.Context.instance()
    sock = ctx.socket(zmq.REQ)
    sock.setsockopt(zmq.SNDTIMEO, 5_000)
    sock.setsockopt(zmq.RCVTIMEO, 120_000)
    sock.connect(ENDPOINT)

    failures: list[str] = []
    print(f"AETERNA smoke test → {ENDPOINT}  seed={SEED}")
    print("-" * 72)

    for kind, params in TASKS:
        print(f"[{kind}]")
        try:
            t0 = time.perf_counter()
            reply1 = _send(sock, kind, params)
            dt_ms = (time.perf_counter() - t0) * 1000.0
        except zmq.error.Again:
            failures.append(f"{kind}: timeout waiting for engine")
            print("  TIMEOUT — is bootstrap.sh running?")
            continue

        if reply1.get("status") != "ok":
            failures.append(f"{kind}: {reply1.get('error')}")
            print(f"  FAIL  status={reply1.get('status')}  error={reply1.get('error')}")
            continue

        h1 = reply1.get("scientific_hash", "")
        engine_ms = (reply1.get("performance") or {}).get("execution_time_ms")
        engine_str = f"engine {engine_ms:7.1f} ms" if engine_ms is not None else "engine    n/a"
        print(f"  ok  round-trip {dt_ms:7.1f} ms  {engine_str}  hash={h1[:16]}…")

        # Determinism replay.
        reply2 = _send(sock, kind, params)
        h2 = reply2.get("scientific_hash", "")
        if h1 != h2:
            failures.append(f"{kind}: non-deterministic ({h1[:12]}… vs {h2[:12]}…)")
            print(f"  FAIL  determinism violated")
        else:
            print(f"  ✓ deterministic under seed={SEED}")

    sock.close(linger=0)
    print("-" * 72)
    if failures:
        for f in failures:
            print("FAIL:", f)
        print(f"\nsmoke test FAILED — {len(failures)}/{len(TASKS)} task(s) broken")
        return 1
    print(f"\nsmoke test PASSED — {len(TASKS)}/{len(TASKS)} task kinds healthy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
