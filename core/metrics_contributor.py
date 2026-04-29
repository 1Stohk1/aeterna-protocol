"""
AETERNA v0.3.0 "Oculus" — Sentinel-side metrics contributor.

The Rust Santuario's Admin service hosts the ``GetMetrics`` and
``ListPeers`` RPCs, but the Sentinel owns half the telemetry:

* gossip rx/tx counts
* task queue depth & harvest cadence
* heartbeat cadence & last-announce age
* mission state

This module is how the Sentinel publishes that data. It maintains an
in-process counter/gauge store and atomically writes two snapshot
files that the Admin service reads at query time:

::

    santuario/integrity/sentinel_metrics.json
        {
            "snapshot_utc": 1713542400,
            "counters": {"aeterna_gossip_rx_total": 42, ...},
            "gauges":   {"aeterna_task_queue_depth": 3.0, ...}
        }

    santuario/integrity/peers.json
        {
            "snapshot_utc": 1713542400,
            "peers": [
                {"address": "udp://192.168.1.19:4444",
                 "node_id": "Prometheus-2",
                 "last_seen_utc": 1713542390,
                 "rx_count": 12, "tx_count": 7,
                 "is_bootstrap": true}
            ]
        }

Writes are atomic (``tempfile`` + ``os.replace``) so a concurrent
Admin reader never sees a half-written file.

Naming convention — ``aeterna_*`` for Sentinel signals, ``santuario_*``
for Rust signals. See ``santuario/proto/admin.proto`` for the canonical
contract.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from threading import Lock
from typing import Any, Iterable

LOG = logging.getLogger("aeterna.metrics")

SENTINEL_METRICS_REL = "santuario/integrity/sentinel_metrics.json"
PEERS_SNAPSHOT_REL = "santuario/integrity/peers.json"


class MetricsContributor:
    """Thread-safe counter/gauge store with atomic snapshot writer.

    Counters only ever go up. Gauges are last-write-wins. The keyspace
    is flat strings — no labels, no histograms — to match the minimal
    surface in ``admin.proto``.
    """

    def __init__(self, repo_root: Path | str) -> None:
        self._repo = Path(repo_root)
        self._counters: dict[str, int] = {}
        self._gauges: dict[str, float] = {}
        self._lock = Lock()
        self._last_dump_monotonic: float = 0.0

    # --- recording ----------------------------------------------------
    def incr(self, name: str, by: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + by

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = float(value)

    def snapshot(self) -> dict[str, Any]:
        """Return an in-memory copy of the current state (for tests)."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
            }

    # --- dumping ------------------------------------------------------
    def dump_now(
        self,
        peer_table: Any | None = None,
        bootstrap_addrs: Iterable[str] | None = None,
    ) -> None:
        """Write both snapshot files atomically.

        ``peer_table`` is accepted duck-typed; the contributor reads the
        private ``_peers`` dict defined by :class:`core.peer_table.PeerTable`
        when available, else treats the peer list as empty.
        """
        now_utc = int(time.time())
        with self._lock:
            metrics_payload = {
                "snapshot_utc": now_utc,
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
            }
        _atomic_write_json(self._repo / SENTINEL_METRICS_REL, metrics_payload)

        if peer_table is not None:
            self._dump_peers(peer_table, set(bootstrap_addrs or ()), now_utc)

        self._last_dump_monotonic = time.monotonic()

    def maybe_dump(
        self,
        peer_table: Any | None = None,
        bootstrap_addrs: Iterable[str] | None = None,
        min_interval_s: float = 5.0,
    ) -> None:
        """Rate-limited dump — safe to call every loop iteration."""
        if time.monotonic() - self._last_dump_monotonic < min_interval_s:
            return
        try:
            self.dump_now(peer_table=peer_table, bootstrap_addrs=bootstrap_addrs)
        except Exception as exc:  # pragma: no cover — belt-and-braces
            LOG.warning("metrics dump failed: %s", exc)

    # --- helpers ------------------------------------------------------
    def _dump_peers(
        self, peer_table: Any, bootstrap_addrs: set[str], now_utc: int
    ) -> None:
        peers: list[dict[str, Any]] = []
        # ``PeerTable._peers`` shape: {(host, port) -> {guardian_id, last_seen_ts, ...}}
        raw = getattr(peer_table, "_peers", {})
        for (host, port), meta in raw.items():
            address = f"udp://{host}:{port}"
            peers.append(
                {
                    "address": address,
                    "node_id": meta.get("guardian_id", "") or "",
                    "last_seen_utc": int(meta.get("last_seen_ts", 0) or 0),
                    "rx_count": int(meta.get("rx_count", 0) or 0),
                    "tx_count": int(meta.get("tx_count", 0) or 0),
                    "is_bootstrap": address in bootstrap_addrs,
                }
            )
        payload = {"snapshot_utc": now_utc, "peers": peers}
        _atomic_write_json(self._repo / PEERS_SNAPSHOT_REL, payload)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write ``payload`` as canonical JSON to ``path`` atomically.

    The write is two-step: a sibling ``.tmp`` file receives the full
    payload, then ``os.replace`` swaps it into place. ``os.replace`` is
    atomic on the same filesystem on both POSIX and Windows, so a
    concurrent reader always sees either the old or new file — never a
    torn one.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, separators=(",", ":"), sort_keys=True),
        encoding="utf-8",
    )
    os.replace(tmp, path)
