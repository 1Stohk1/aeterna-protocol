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
import hmac
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
from core.nat_udp import RendezvousHint, parse_rendezvous_hints
from core.poc import (
    build_poc_verdict,
    should_validate_block,
    validate_block_by_reexecution,
    verify_poc_verdict,
)
from core.santuario_client import SantuarioClient
from core.handshake import build_peer_announce, verify_peer_announce
from core.trust_score import TrustScoreBook

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
    rendezvous_hints: list[RendezvousHint]
    pow_difficulty: int
    default_task: str
    agp_protocol_version: str
    freeze_julia_version: str
    accept_agpl_license: bool
    accept_prometeo_clause: bool
    poc_sample_rate_pct: int
    raw: dict[str, Any] = field(repr=False, default_factory=dict)

    @classmethod
    def from_toml(cls, path: Path) -> "SentinelConfig":
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        # Merge local overrides if present
        local_path = path.with_name("aeterna.local.toml")
        if local_path.exists():
            local_raw = tomllib.loads(local_path.read_text(encoding="utf-8"))
            # Deep merge simple dicts
            def _merge(d1, d2):
                for k, v in d2.items():
                    if isinstance(v, dict) and k in d1 and isinstance(d1[k], dict):
                        _merge(d1[k], v)
                    else:
                        d1[k] = v
            _merge(raw, local_raw)
            LOG.info(f"Loaded local overrides from {local_path.name}")
        bootstrap = [
            _parse_peer(p) for p in raw.get("gossip", {}).get("bootstrap_peers", [])
        ]
        rendezvous_hints = parse_rendezvous_hints(
            raw.get("gossip", {}).get("rendezvous_hints", [])
        )
        ethics = raw.get("ethics", {})
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
            rendezvous_hints=rendezvous_hints,
            pow_difficulty=int(raw["sentinel"]["pow_difficulty"]),
            default_task=raw["mission"]["default_task"],
            agp_protocol_version=raw["agp"]["protocol_version"],
            freeze_julia_version=raw["agp"]["freeze_julia_version"],
            accept_agpl_license=bool(ethics.get("accept_agpl_license", False)),
            accept_prometeo_clause=bool(ethics.get("accept_prometeo_clause", False)),
            poc_sample_rate_pct=int(raw.get("consensus", {}).get("poc_sample_rate_pct", 100)),
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

        self._ctx = zmq.Context()
        self._zmq: zmq.Socket | None = None
        self._gossip: AeternaGossipNet | None = None
        self._santuario: SantuarioClient | None = None
        self._public_key: bytes | None = None
        self._running = False
        self._last_announce_ts: float = 0.0

        self._task_queue: list[dict[str, Any]] = []
        self._poc_queue: list[dict[str, Any]] = []
        self._poc_seen_blocks: set[str] = set()
        self._trust_scores = TrustScoreBook()
        self._package_manifest_hash = self._hash_python_manifest()

    # ------------------------------------------------------------------
    # Boot sequence — Axiom I, II, III
    # ------------------------------------------------------------------
    def awaken(self) -> None:
        LOG.info("=" * 60)
        LOG.info("AETERNA Sentinel v%s — waking up %s", SENTINEL_VERSION, self.cfg.guardian_id)
        LOG.info("=" * 60)

        self._verify_ethics_consent()
        self._check_gpu()
        self._sign_manifesto()

        self._zmq = self._ctx.socket(zmq.REQ)
        self._zmq.setsockopt(zmq.SNDTIMEO, self.cfg.zmq_send_timeout_ms)
        self._zmq.setsockopt(zmq.RCVTIMEO, self.cfg.zmq_recv_timeout_ms)
        self._zmq.connect(self.cfg.zmq_endpoint)
        LOG.info("ZMQ REQ → %s", self.cfg.zmq_endpoint)

        if self.cfg.raw.get("santuario", {}).get("enabled", False):
            self._santuario = SantuarioClient()
            self._public_key = self._santuario.get_public_key()
            LOG.info(f"Santuario signer connected. Pubkey len: {len(self._public_key)} bytes")
        else:
            self._santuario = None
            self._public_key = b"stub_public_key"
            LOG.warning("Santuario is disabled in aeterna.toml. Running in Genesis mode without signatures.")

        self._gossip = AeternaGossipNet(
            guardian_id=self.cfg.guardian_id,
            port=self.cfg.gossip_port,
            bootstrap_peers=self.cfg.bootstrap_peers,
            fanout=self.cfg.gossip_fanout,
            ttl=self.cfg.gossip_ttl,
            rendezvous_hints=self.cfg.rendezvous_hints,
            on_message=self._on_gossip,
        )
        self._gossip.start()
        LOG.info("gossip bound on :%d (fanout=%d, ttl=%d, peers=%d)",
                 self.cfg.gossip_port, self.cfg.gossip_fanout,
                 self.cfg.gossip_ttl, len(self.cfg.bootstrap_peers))

    def _verify_ethics_consent(self) -> None:
        """Hard boot gate — Sovranità Finale.

        The Sentinel refuses to awaken unless the operator has explicitly
        acknowledged both the AGPLv3 license and the Prometheus Clause in
        ``aeterna.toml``. This is not a click-through EULA: the signed
        Manifesto embedded in the Identity SBT (v0.1.0) will reference these
        flags, making the consent cryptographically binding rather than
        merely contractual.
        """
        missing: list[str] = []
        if not self.cfg.accept_agpl_license:
            missing.append("accept_agpl_license")
        if not self.cfg.accept_prometeo_clause:
            missing.append("accept_prometeo_clause")
        if missing:
            LOG.error("=" * 60)
            LOG.error("ETHICS GATE CLOSED — refusing to boot.")
            LOG.error("")
            LOG.error("The Guardian may not run until the operator has read")
            LOG.error("  LICENSE    (AGPLv3)")
            LOG.error("  ETHICS.md  (Prometheus Clause)")
            LOG.error("and set the following flags to ``true`` in aeterna.toml:")
            for k in missing:
                LOG.error("  [ethics] %s", k)
            LOG.error("")
            LOG.error("This is Axiom I — Sovranità Finale. No override exists.")
            LOG.error("=" * 60)
            raise SystemExit(3)
        LOG.info("ethics gate passed: AGPLv3 + Prometheus Clause acknowledged")

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
            # Broadcast peer_announce periodically
            now = time.time()
            if now - self._last_announce_ts > 30.0:
                self._broadcast_announce()
                self._last_announce_ts = now

            self._process_next_poc_validation()

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

            self._sign_block(payload)

            assert self._gossip is not None
            mid = self._gossip.gossip({"kind": "agp_block", "payload": payload})
            LOG.info("block broadcast mid=%s pow=%s…", mid[:12], block_hash[:12])

    def _sign_block(self, payload: dict[str, Any]) -> None:
        if self._santuario is None:
            # Genesis mode: no signatures
            payload["security"]["signature"] = ""
            payload["security"]["public_key"] = ""
            return

        assert self._public_key is not None

        payload_hash_hex = payload["security"]["payload_hash"]
        signature = self._santuario.sign(bytes.fromhex(payload_hash_hex))
        payload["security"]["signature"] = signature.hex()
        payload["security"]["public_key"] = self._public_key.hex()

    def _broadcast_announce(self) -> None:
        if not self._santuario or not self._gossip:
            return
        announce_msg = build_peer_announce(
            guardian_id=self.cfg.guardian_id,
            manifesto_path=str(self.manifesto_path),
            santuario_client=self._santuario
        )
        self._gossip.gossip(announce_msg)
        LOG.debug("broadcasted peer_announce")

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

    def _execute_poc_request(self, request: dict[str, Any]) -> dict[str, Any]:
        assert self._zmq is not None
        LOG.info("PoC replay -> Julia: %s (task=%s seed=%s)",
                 request["tipo_analisi"], request["id_task"][:16],
                 request["reproducibility"].get("seed_rng"))
        self._zmq.send_json(request)
        return self._zmq.recv_json()  # type: ignore[return-value]

    def _process_next_poc_validation(self) -> None:
        if not self._poc_queue or not self._santuario or not self._gossip:
            return

        payload = self._poc_queue.pop(0)
        payload_hash = payload.get("security", {}).get("payload_hash", "")
        if not payload_hash or payload_hash in self._poc_seen_blocks:
            return
        self._poc_seen_blocks.add(payload_hash)

        producer_id = payload.get("header", {}).get("node_id", "unknown")
        if producer_id == self.cfg.guardian_id:
            return
        if not should_validate_block(payload, self.cfg.guardian_id, self.cfg.poc_sample_rate_pct):
            LOG.debug("PoC selector skipped block %s from %s", payload_hash[:12], producer_id)
            return

        result = validate_block_by_reexecution(payload, self._execute_poc_request)
        verdict_message = build_poc_verdict(
            validator_id=self.cfg.guardian_id,
            block_payload=payload,
            result=result,
            santuario_client=self._santuario,
        )
        delta = self._trust_scores.apply_poc_verdict(producer_id, result.verdict)
        self._gossip.gossip(verdict_message)
        LOG.info(
            "PoC %s for %s block=%s reason=%s trust_delta=%+d local_trust=%d",
            result.verdict,
            producer_id,
            payload_hash[:12],
            result.reason,
            delta,
            self._trust_scores.get(producer_id),
        )

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
        # Engine-reported timings are informational and intentionally EXCLUDED
        # from payload_hash — wall-clock ms varies across hardware and would
        # defeat deterministic consensus if it entered the hashed body.
        performance_block = dict(result.get("performance", {}) or {})
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
            "performance": performance_block,
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
        peer_addr = message.pop("__peer_addr__", None)
        kind = message.get("kind")
        if kind == "task_offer":
            self._task_queue.append(message["task"])
        elif kind == "peer_announce":
            assert self._santuario is not None
            valid, reason = verify_peer_announce(message, self._santuario)
            if valid:
                payload = message.get("payload", {})
                guardian_id = payload.get("guardian_id", "unknown")
                if peer_addr and self._gossip:
                    self._gossip.peer_table.add_or_update(peer_addr[0], peer_addr[1], guardian_id)
                LOG.info(f"peer_announce received and verified from {guardian_id}")
            else:
                LOG.warning("invalid peer_announce dropped: %s", reason)

        elif kind == "agp_block":
            payload = message.get("payload", {})
            valid, reason = self._verify_peer_block(payload)
            if not valid:
                LOG.warning(
                    "dropping block from %s: %s",
                    payload.get("header", {}).get("node_id"),
                    reason,
                )
                return

            LOG.debug("observed peer block: %s (signature verified)",
                      payload["header"].get("node_id"))
            self._poc_queue.append(payload)

        elif kind == "poc_verdict":
            assert self._santuario is not None
            valid, reason = verify_poc_verdict(message, self._santuario)
            if not valid:
                LOG.warning("invalid poc_verdict dropped: %s", reason)
                return

            verdict_payload = message.get("payload", {})
            producer_id = verdict_payload.get("producer_id", "unknown")
            verdict = verdict_payload.get("verdict", "")
            delta = self._trust_scores.apply_poc_verdict(producer_id, verdict)
            LOG.info(
                "PoC verdict received: %s validated block=%s from=%s trust_delta=%+d trust=%d",
                verdict_payload.get("validator_id", "unknown"),
                verdict_payload.get("block_payload_hash", "")[:12],
                producer_id,
                delta,
                self._trust_scores.get(producer_id),
            )

    def _verify_peer_block(self, payload: dict[str, Any]) -> tuple[bool, str]:
        if self._santuario is None:
            return True, "genesis mode: signature verification bypassed"

        try:
            security = payload["security"]
            claimed_hash_hex = security["payload_hash"]
            expected_hash_hex = _canonical_sha256({
                "header": payload["header"],
                "payload": payload["payload"],
                "reproducibility": payload["reproducibility"],
                "results": payload["results"],
            })
            if not hmac.compare_digest(claimed_hash_hex, expected_hash_hex):
                return False, "payload_hash mismatch"

            pow_nonce = security.get("pow_nonce")
            pow_hash = security.get("pow_hash")
            if pow_nonce is not None and pow_hash:
                expected_pow = hashlib.sha256(
                    f"{claimed_hash_hex}:{int(pow_nonce)}".encode("utf-8")
                ).hexdigest()
                target_prefix = "0" * self.cfg.pow_difficulty
                if not hmac.compare_digest(pow_hash, expected_pow):
                    return False, "pow_hash mismatch"
                if not pow_hash.startswith(target_prefix):
                    return False, "pow difficulty not satisfied"

            signature = bytes.fromhex(security.get("signature", ""))
            public_key = bytes.fromhex(security.get("public_key", ""))
            payload_hash = bytes.fromhex(claimed_hash_hex)
        except (KeyError, TypeError, ValueError):
            return False, "malformed AGP security fields"

        if not signature or not public_key:
            return False, "missing signature or public_key"

        if not self._santuario.verify(payload_hash, signature, public_key):
            return False, "invalid cryptographic signature"

        return True, "ok"

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
        if self._santuario:
            self._santuario.close()


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
