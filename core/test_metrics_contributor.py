"""Smoke tests for :class:`core.metrics_contributor.MetricsContributor`.

Run with::

    python -m unittest core.test_metrics_contributor
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from core.metrics_contributor import (
    MetricsContributor,
    PEERS_SNAPSHOT_REL,
    SENTINEL_METRICS_REL,
)


class _FakePeerTable:
    """Minimal duck-type matching :class:`core.peer_table.PeerTable`."""

    def __init__(self) -> None:
        self._peers = {
            ("192.168.1.19", 4444): {
                "guardian_id": "Prometheus-2",
                "last_seen_ts": 1_713_542_390,
                "rx_count": 12,
                "tx_count": 7,
            },
            ("203.0.113.10", 4444): {
                "guardian_id": "",
                "last_seen_ts": 0,
            },
        }


class MetricsContributorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        self.contrib = MetricsContributor(self.repo)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_counters_only_go_up(self) -> None:
        self.contrib.incr("aeterna_gossip_rx_total")
        self.contrib.incr("aeterna_gossip_rx_total", by=5)
        snap = self.contrib.snapshot()
        self.assertEqual(snap["counters"]["aeterna_gossip_rx_total"], 6)

    def test_gauges_overwrite(self) -> None:
        self.contrib.set_gauge("aeterna_task_queue_depth", 4.0)
        self.contrib.set_gauge("aeterna_task_queue_depth", 0.0)
        self.assertEqual(
            self.contrib.snapshot()["gauges"]["aeterna_task_queue_depth"], 0.0
        )

    def test_dump_writes_metrics_file_atomically(self) -> None:
        self.contrib.incr("aeterna_block_tx_total", by=3)
        self.contrib.set_gauge("aeterna_task_queue_depth", 2.0)
        self.contrib.dump_now()
        path = self.repo / SENTINEL_METRICS_REL
        self.assertTrue(path.exists())
        data = json.loads(path.read_text())
        self.assertEqual(data["counters"]["aeterna_block_tx_total"], 3)
        self.assertEqual(data["gauges"]["aeterna_task_queue_depth"], 2.0)
        self.assertGreater(data["snapshot_utc"], 0)
        # Stale .tmp must NOT linger after a successful os.replace.
        self.assertFalse(path.with_suffix(path.suffix + ".tmp").exists())

    def test_dump_writes_peers_when_table_provided(self) -> None:
        table = _FakePeerTable()
        bootstrap = {"udp://192.168.1.19:4444"}
        self.contrib.dump_now(peer_table=table, bootstrap_addrs=bootstrap)
        peers_file = self.repo / PEERS_SNAPSHOT_REL
        self.assertTrue(peers_file.exists())
        data = json.loads(peers_file.read_text())
        addrs = {p["address"] for p in data["peers"]}
        self.assertIn("udp://192.168.1.19:4444", addrs)
        self.assertIn("udp://203.0.113.10:4444", addrs)
        # Bootstrap flag honored.
        for p in data["peers"]:
            if p["address"] == "udp://192.168.1.19:4444":
                self.assertTrue(p["is_bootstrap"])
                self.assertEqual(p["node_id"], "Prometheus-2")
                self.assertEqual(p["rx_count"], 12)
                self.assertEqual(p["tx_count"], 7)
            else:
                self.assertFalse(p["is_bootstrap"])

    def test_maybe_dump_rate_limits(self) -> None:
        self.contrib.incr("aeterna_gossip_rx_total")
        self.contrib.maybe_dump(min_interval_s=60.0)
        first_mtime = (self.repo / SENTINEL_METRICS_REL).stat().st_mtime
        # Second call within the window should NOT re-write.
        self.contrib.maybe_dump(min_interval_s=60.0)
        second_mtime = (self.repo / SENTINEL_METRICS_REL).stat().st_mtime
        self.assertEqual(first_mtime, second_mtime)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
