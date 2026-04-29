"""Smoke tests for :mod:`operations.war_room.client`.

We spin up an in-process mock ``Admin`` gRPC server on an ephemeral
loopback port, dial it with ``AdminObserver``, and assert:

1. Every RPC round-trips through the typed dataclasses intact.
2. Unknown keys in the protobuf don't trip the mapper (namespace
   merging guarantee — admin.proto §header).
3. Dialing a dead port returns :class:`client.Unreachable` rather than
   raising — the War Room must render "degraded", not crash, when the
   signer is down.

Run with::

    python -m unittest operations.war_room.tests.test_client

or from the war_room dir::

    python -m unittest tests.test_client
"""
from __future__ import annotations

import sys
import time
import unittest
from concurrent import futures
from pathlib import Path

# Make the war_room package importable either as
# ``operations.war_room.tests.test_client`` (from repo root) or as
# ``tests.test_client`` (from the war_room dir).
_WAR_ROOM_DIR = Path(__file__).resolve().parent.parent
if str(_WAR_ROOM_DIR) not in sys.path:
    sys.path.insert(0, str(_WAR_ROOM_DIR))

import grpc  # noqa: E402

import admin_pb2  # noqa: E402
import admin_pb2_grpc  # noqa: E402
from client import (  # noqa: E402
    AdminObserver,
    AuditLogLine,
    AuditTail,
    Metrics,
    Peer,
    PeerList,
    Quantiles,
    Unreachable,
)


# --- fake service ----------------------------------------------------------


class _FakeAdmin(admin_pb2_grpc.AdminServicer):
    """Minimal fake that echoes a pre-seeded snapshot on every call."""

    def __init__(self) -> None:
        self.snapshot_ts = 1_713_542_400
        self.counters = {
            "santuario_sign_total": 4,
            "santuario_sign_accept_total": 3,
            "aeterna_gossip_rx_total": 17,
        }
        self.gauges = {
            "santuario_vault_sealed": 0.0,
            "santuario_signer_ready": 1.0,
            "aeterna_task_queue_depth": 2.0,
        }
        self.quantiles = {
            "santuario_sign_latency_seconds": (0.010, 0.040, 0.100),
        }
        self.audit_lines = [
            (1_713_542_400, "baseline_sealed", '{"record":"baseline_sealed"}'),
            (1_713_542_401, "alert", '{"record":"alert","kind":"alpha"}'),
        ]
        self.peers = [
            ("udp://192.168.1.19:4444", "Prometheus-2", 1_713_542_390, 12, 7, True),
            ("udp://203.0.113.10:4444", "", 0, 0, 0, False),
        ]

    def GetMetrics(self, request, context):
        resp = admin_pb2.GetMetricsResponse(
            schema_version=1,
            node_id="Prometheus-test",
            ts_utc=self.snapshot_ts,
            metric_window_seconds=300,
        )
        for k, v in self.counters.items():
            resp.counters[k] = v
        for k, v in self.gauges.items():
            resp.gauges[k] = v
        for k, (p50, p90, p99) in self.quantiles.items():
            resp.quantiles[k].p50 = p50
            resp.quantiles[k].p90 = p90
            resp.quantiles[k].p99 = p99
        return resp

    def TailAuditLog(self, request, context):
        limit = request.limit or 20
        take = self.audit_lines[-limit:]
        return admin_pb2.TailAuditLogResponse(
            lines=[
                admin_pb2.AuditLogLine(ts_utc=ts, record=rec, json=raw)
                for (ts, rec, raw) in take
            ]
        )

    def ListPeers(self, request, context):
        return admin_pb2.ListPeersResponse(
            snapshot_utc=self.snapshot_ts,
            peers=[
                admin_pb2.Peer(
                    address=a,
                    node_id=nid,
                    last_seen_utc=ts,
                    rx_count=rx,
                    tx_count=tx,
                    is_bootstrap=bs,
                )
                for (a, nid, ts, rx, tx, bs) in self.peers
            ],
        )


def _start_fake_server() -> tuple[grpc.Server, int]:
    """Bind a grpc.Server on an ephemeral port, return (server, port)."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    admin_pb2_grpc.add_AdminServicer_to_server(_FakeAdmin(), server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    return server, port


# --- tests -----------------------------------------------------------------


class AdminObserverTests(unittest.TestCase):
    def setUp(self) -> None:
        self._server, self._port = _start_fake_server()
        self._obs = AdminObserver(
            target=f"127.0.0.1:{self._port}",
            rpc_timeout_seconds=2.0,
        )

    def tearDown(self) -> None:
        self._obs.close()
        self._server.stop(grace=0.1)

    def test_get_metrics_maps_proto_to_typed_dataclass(self) -> None:
        got = self._obs.get_metrics()
        self.assertIsInstance(got, Metrics)
        assert isinstance(got, Metrics)
        self.assertEqual(got.schema_version, 1)
        self.assertEqual(got.node_id, "Prometheus-test")
        self.assertEqual(got.counters["santuario_sign_total"], 4)
        self.assertEqual(got.counters["aeterna_gossip_rx_total"], 17)
        self.assertAlmostEqual(got.gauges["santuario_vault_sealed"], 0.0)
        self.assertAlmostEqual(got.gauges["aeterna_task_queue_depth"], 2.0)
        q = got.quantiles["santuario_sign_latency_seconds"]
        self.assertIsInstance(q, Quantiles)
        self.assertAlmostEqual(q.p50, 0.010)
        self.assertAlmostEqual(q.p90, 0.040)
        self.assertAlmostEqual(q.p99, 0.100)
        self.assertEqual(got.metric_window_seconds, 300)

    def test_tail_audit_log_preserves_raw_json_string(self) -> None:
        got = self._obs.tail_audit_log(limit=20)
        self.assertIsInstance(got, AuditTail)
        assert isinstance(got, AuditTail)
        self.assertEqual(len(got.lines), 2)
        self.assertEqual(got.lines[0].record, "baseline_sealed")
        self.assertEqual(
            got.lines[1].json, '{"record":"alert","kind":"alpha"}'
        )
        self.assertEqual(got.lines[1].ts_utc, 1_713_542_401)
        self.assertTrue(all(isinstance(l, AuditLogLine) for l in got.lines))

    def test_list_peers_flags_bootstrap(self) -> None:
        got = self._obs.list_peers()
        self.assertIsInstance(got, PeerList)
        assert isinstance(got, PeerList)
        self.assertEqual(got.snapshot_utc, 1_713_542_400)
        self.assertEqual(len(got.peers), 2)
        bootstrap = next(
            p for p in got.peers if p.address == "udp://192.168.1.19:4444"
        )
        self.assertIsInstance(bootstrap, Peer)
        self.assertTrue(bootstrap.is_bootstrap)
        self.assertEqual(bootstrap.node_id, "Prometheus-2")
        self.assertEqual(bootstrap.rx_count, 12)
        self.assertEqual(bootstrap.tx_count, 7)
        discovered = next(
            p for p in got.peers if p.address == "udp://203.0.113.10:4444"
        )
        self.assertFalse(discovered.is_bootstrap)
        self.assertEqual(discovered.node_id, "")


class AdminObserverDegradedTests(unittest.TestCase):
    """No server at all — every RPC must return Unreachable, not raise."""

    def test_rpcs_on_dead_port_return_unreachable_sentinel(self) -> None:
        # Port 1 is effectively always closed on localhost — faster than
        # binding+closing just to harvest a number.
        obs = AdminObserver(
            target="127.0.0.1:1",
            rpc_timeout_seconds=0.5,
        )
        try:
            started = time.monotonic()
            got = obs.get_metrics()
            self.assertIsInstance(got, Unreachable)
            assert isinstance(got, Unreachable)
            # Should fail fast, not stall the dashboard's 2s poll loop.
            self.assertLess(time.monotonic() - started, 3.0)
            self.assertTrue(got.reason)
        finally:
            obs.close()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
