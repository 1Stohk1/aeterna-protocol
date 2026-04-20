"""
AETERNA Sentinel — Python userland orchestrator.

Responsibilities (v0.0.1 "Genesis"):

    1. Load and validate ``aeterna.toml``.
    2. Probe the GPU (RTX 5070 — Prometheus-0) and record a hardware snapshot.
    3. Sign the Manifesto at first boot (Axiom I — Sovranità Finale).
    4. Bind the UDP gossip socket (:class:`core.gossip.AeternaGossipNet`).
    5. Open a ZMQ REQ channel to the Julia scientific engine.
    6. Harvest tasks from gossip, dispatch to Julia, wrap the result in an
       AGP-v1 payload, solve PoW (SHA-256 difficulty 4), broadcast the block.

What this module deliberately does NOT do:

    - Hold sovereignty-grade secrets (that is the Rust Santuario's job).
    - Sign the consensus block (v0.1.0: done via gRPC/UDS to the Santuario).
    - Persist checkpoints (v0.1.0: Santuario writes to encrypted NVMe vault).

Run with::

    python -m core.sentinel --config aeterna.toml
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import secrets
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:  # Python ≥ 3.11
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

import zmq

from core.gossip import AeternaGossipNet

LOG = logging.getLogger("aeterna.sentinel")

AGP_VERSION = "AGP-v1"
SENTINEL_VERSION = "0.0.1"


# ---------------------------------------------------------------------------
# Configuration container
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class SentinelConfig:
    guardian_id: str
    gpu_model: str
    vram_gb: int
    zmq_endpoint: str
    zmq_send_timeout_ms: int
    zmq_recv_timeout_ms: int
    gossip_port: int
    gossip_fanout: int
    gossip_ttl: int
    bootstrap_peers: list[tuple[str, int]]
    pow_difficulty: int
    default_task: str
    agp_protocol_version: str
    freeze_julia_version: str
    raw: dict[str, Any] = field(repr=False, default_factory=dict)

    @classmethod
    def from_toml(cls, path: Path) -> "SentinelConfig":
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        bootstrap = [
            _parse_peer(p) for p in raw.get("gossip", {}).get("bootstrap_peers", [])
        ]
        return cls(
            guardian_id=raw["identity"]["guardian_id"],
            gpu_model=raw["hardware"]["gpu_model"],
            vram_gb=int(raw["hardware"]["vram_gb"]),
            zmq_endpoint=raw["sentinel"]["zmq"]["endpoint"],
            zmq_send_timeout_ms=int(raw["sentinel"]["zmq"]["send_timeout_ms"]),
            zmq_recv_timeout_ms=int(raw["sentinel"]["zmq"]["recv_timeout_ms"]),
            gossip_port=int(raw["gossip"]["port"]),
            gossip_fanout=int(raw["gossip"]["fanout"]),
            gossip_ttl=int(raw["gossip"]["ttl"]),
            bootstrap_peers=bootstrap,
            pow_difficulty=int(raw["sentinel"]["pow_difficulty"]),
            default_task=raw["mission"]["default_task"],
            agp_protocol_version=raw["agp"]["protocol_version"],
            freeze_julia_version=raw["agp"]["freeze_julia_version"],
            raw=raw,
        )


def _parse_peer(raw: str) -> tuple[str, int]:
    # "udp://host:port"  →  (host, port)
    if raw.startswith("udp://"):
        raw = raw[len("udp://") :]
    host, _, port = raw.partition(":")
    return host, int(port)


# ---------------------------------------------------------------------------
# The Sentinel
# ---------------------------------------------------------------------------
class Sentinel:
    """A Guardian node's userland orchestrator."""

    def __init__(self, cfg: SentinelConfig, *, manifesto_path: Path) -> None:
        self.cfg = cfg
        self.manifesto_path = manifesto_path

        self._ctx = zmq.Context.instance()
        self._zmq: zmq.Socket | None = None
        self._gossip: AeternaGossipNet | None = None
        self._running = False

        self._task_queue: list[dict[str, Any]] = []
        self._package_manifest_hash = self._hash_python_manifest()

    # ------------------------------------------------------------------
    # Boot sequence — Axiom I, II, III
    # ------------------------------------------------------------------
    def awaken(self) -> None:
        LOG.info("=" * 60)
        LOG.info("AETERNA Sentinel v%s — waking up %s", SENTINEL_VERSION, self.cfg.guardian_id)
        LOG.info("=" * 60)

        self._check_gpu()
        self._sign_manifesto()

        self._zmq = self._ctx.socket(zmq.REQ)
        self._zmq.setsockopt(zmq.SNDTIMEO, self.cfg.zmq_send_timeout_ms)
        self._zmq.setsockopt(zmq.RCVTIMEO, self.cfg.zmq_recv_timeout_ms)
        self._zmq.connect(self.cfg.zmq_endpoint)
        LOG.info("ZMQ REQ → %s", self.cfg.zmq_endpoint)

        self._gossip = AeternaGossipNet(
            guardian_id=self.cfg.guardian_id,
            port=self.cfg.gossip_port,
            bootstrap_peers=self.cfg.bootstrap_peers,
            fanout=self.cfg.gossip_fanout,
            ttl=self.cfg.gossip_ttl,
            on_message=self._on_gossip,
        )
        self._gossip.start()
        LOG.info("gossip bound on :%d (fanout=%d, ttl=%d, peers=%d)",
                 self.cfg.gossip_port, self.cfg.gossip_fanout,
                 self.cfg.gossip_ttl, len(self.cfg.bootstrap_peers))

    def _check_gpu(self) -> None:
        try:
            import torch  # type: ignore[import-not-found]
        except ImportError:
            LOG.warning("torch not installed — running in CPU-degraded mode")
            return
        if not torch.cuda.is_available():
            LOG.warning("CUDA unavailable — running in CPU-degraded mode")
            return
        device = torch.cuda.get_device_properties(0)
        vram_gb = device.total_memory / (1024 ** 3)
        LOG.info("GPU detected: %s — %.1f GB VRAM", device.name, vram_gb)
        if vram_gb + 0.5 < self.cfg.vram_gb:
            LOG.warning("VRAM (%.1f GB) below declared %.1f GB — hardware attestation may fail",
                        vram_gb, self.cfg.vram_gb)

    def _sign_manifesto(self) -> None:
        # v0.0.1: compute the SHA3-256 of MANIFESTO.md and log it. Dilithium-5
        # signing is delegated to the Santuario in v0.1.0 via gRPC.
        if not self.manifesto_path.exists():
            LOG.error("MANIFESTO.md missing — refusing to boot (Axiom I violation)")
            raise SystemExit(2)
        digest = hashlib.sha3_256(self.manifesto_path.read_bytes()).hexdigest()
        LOG.info("Manifesto digest (sha3-256): %s", digest)
        LOG.info("  [v0.0.1] Dilithium-5 signing deferred to Santuario (santuario/ stub)")

    # ------------------------------------------------------------------
    # Task lifecycle
    # ------------------------------------------------------------------
    def run_lifecycle(self) -> None:
        self._running = True
        LOG.info("entering lifecycle loop — Ctrl-C to stop")
        while self._running:
            task = self.harvest_task()
            if task is None:
                time.sleep(1.0)
                continue

            try:
                result = self.dispatch_task(task)
            except Exception:  # noqa: BLE001
                LOG.exception("task dispatch failed — skipping")
                continue

            payload = self.build_agp_payload(task, result)
            nonce, block_hash = self.solve_pow(payload)
            payload["security"]["pow_nonce"] = nonce
            payload["security"]["pow_hash"] = block_hash

            assert self._gossip is not None
            mid = self._gossip.gossip({"kind": "agp_block", "payload": payload})
            LOG.info("block broadcast mid=%s pow=%s…", mid[:12], block_hash[:12])

    def harvest_task(self) -> dict[str, Any] | None:
        """Pull the next pending task. In v0.0.1, gossip is still bootstrapping,
        so the Sentinel synthesizes a self-task for Missione Alpha if no peer
        has proposed one."""
        if self._task_queue:
            return self._task_queue.pop(0)

        # Self-seed Missione Alpha — the genesis Guardian has no one else yet.
        return {
            "id_task": f"TASK-{uuid.uuid4()}",
            "tipo_analisi": self.cfg.default_task,
            "parametri": _default_parameters_for(self.cfg.default_task),
        }

    def dispatch_task(self, task: dict[str, Any]) -> dict[str, Any]:
        assert self._zmq is not None
        # Canonical seed source = Sentinel. Imposes determinism on Julia.
        seed = secrets.randbits(63)
        request = {
            "id_task": task["id_task"],
            "tipo_analisi": task["tipo_analisi"],
            "parametri": task.get("parametri", {}),
            "reproducibility": {
                "seed_rng": seed,
                "julia_version_expected": self.cfg.freeze_julia_version,
                "package_manifest_hash": self._package_manifest_hash,
            },
        }
        LOG.info("→ Julia: %s (task=%s seed=%d)",
                 task["tipo_analisi"], task["id_task"][:16], seed)
        self._zmq.send_json(request)
        reply: dict[str, Any] = self._zmq.recv_json()  # type: ignore[assignment]
        if reply.get("status") != "ok":
            raise RuntimeError(f"Julia engine error: {reply.get('error')}")
        return reply

    # ------------------------------------------------------------------
    # AGP-v1 payload construction
    # ------------------------------------------------------------------
    def build_agp_payload(
        self, task: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]:
        header = {
            "protocol_version": self.cfg.agp_protocol_version,
            "timestamp": int(time.time()),
            "node_id": self.cfg.guardian_id,
        }
        payload_body = {
            "id_task": task["id_task"],
            "tipo_analisi": task["tipo_analisi"],
            "parametri": task.get("parametri", {}),
        }
        reproducibility = {
            "seed_rng": result.get("seed_rng"),
            "julia_version": result.get("julia_version"),
            "package_manifest_hash": self._package_manifest_hash,
        }
        results_block = {
            "metrics": result.get("metrics", {}),
            "scientific_hash": result.get("scientific_hash"),
        }
        payload_hash = _canonical_sha256({
            "header": header,
            "payload": payload_body,
            "reproducibility": reproducibility,
            "results": results_block,
        })
        return {
            "header": header,
            "payload": payload_body,
            "reproducibility": reproducibility,
            "results": results_block,
            "security": {
                "payload_hash": payload_hash,
                "results_scientific_hash": results_block["scientific_hash"],
                "consensus_status": "PENDING",
            },
        }

    # ------------------------------------------------------------------
    # Proof of Work — Level 0 of the consensus pipeline
    # ------------------------------------------------------------------
    def solve_pow(self, payload: dict[str, Any]) -> tuple[int, str]:
        target_prefix = "0" * self.cfg.pow_difficulty
        seed = payload["security"]["payload_hash"]
        nonce = 0
        while True:
            candidate = f"{seed}:{nonce}".encode("utf-8")
            digest = hashlib.sha256(candidate).hexdigest()
            if digest.startswith(target_prefix):
                return nonce, digest
            nonce += 1
            if nonce & 0xFFFFF == 0:
                LOG.debug("pow grinding nonce=%d", nonce)

    # ------------------------------------------------------------------
    # Gossip inbound
    # ------------------------------------------------------------------
    def _on_gossip(self, message: dict[str, Any]) -> None:
        kind = message.get("kind")
        if kind == "task_offer":
            self._task_queue.append(message["task"])
        elif kind == "agp_block":
            LOG.debug("observed peer block: %s",
                      message["payload"]["header"].get("node_id"))

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------
    def _hash_python_manifest(self) -> str:
        req = Path(__file__).parent / "requirements.txt"
        if not req.exists():
            return "missing"
        return hashlib.sha256(req.read_bytes()).hexdigest()

    def shutdown(self) -> None:
        LOG.info("shutdown requested — draining")
        self._running = False
        if self._gossip:
            self._gossip.stop()
        if self._zmq:
            self._zmq.close(linger=0)


def _canonical_sha256(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _default_parameters_for(task_kind: str) -> dict[str, Any]:
    # Minimal sane defaults per task. Real missions override via gossip.
    defaults: dict[str, dict[str, Any]] = {
        "genome_analysis":        {"sequence": "GATTACAGATTACAGATTACA"},
        "genomic_entropy":        {"sequence": "GATTACAGATTACAGATTACA"},
        "dna_mutation_hamming":   {"ref":  "GATTACAGATTACA",
                                   "obs":  "GATTAGAGATTACA"},
        "tumor_growth_gompertz":  {"N0": 1.0e6, "rho": 0.01, "K": 1.0e11,
                                   "sigma": 0.02, "days": 180},
        "tumor_therapy_sde":      {"N0": 1.0e6, "rho": 0.01, "K": 1.0e11,
                                   "sigma": 0.02, "days": 180,
                                   "efficacia_farmaco": 0.35,
                                   "giorno_inizio": 30},
        "protein_folding_hp":     {"sequence": "HPHPPHHPHPPHPHHPPHPH",
                                   "steps": 50_000},
    }
    return defaults.get(task_kind, {})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aeterna.sentinel")
    parser.add_argument("--config", type=Path, default=Path("aeterna.toml"))
    parser.add_argument("--manifesto", type=Path, default=Path("MANIFESTO.md"))
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    cfg = SentinelConfig.from_toml(args.config)
    sentinel = Sentinel(cfg, manifesto_path=args.manifesto)

    def _sig(_signum: int, _frame: Any) -> None:
        sentinel.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    sentinel.awaken()
    sentinel.run_lifecycle()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
