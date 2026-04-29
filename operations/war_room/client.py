"""Typed wrapper around the Admin gRPC surface (admin.proto v0.3.0 "Oculus").

Design rules:

* The UI (``app.py``) never touches raw protobuf objects. It consumes
  the dataclasses defined here — stable Python shapes that outlast
  field-number changes in the proto.
* Every RPC has a short deadline (``rpc_timeout_seconds=2.0``). The
  Streamlit poll loop runs every 2s; a blocked RPC must NOT stall the
  whole dashboard. On timeout the wrapper returns an ``Unreachable``
  sentinel — the UI renders "degraded" rather than crashing.
* The channel is reused across calls. The Streamlit app caches the
  ``AdminObserver`` across reruns via ``st.cache_resource``.
* Target discovery matches ``core/santuario_client.py``: explicit
  argument > ``$SANTUARIO_PORT`` env > Windows default TCP > Unix
  default UDS.

No method in this module writes to the signer. The Admin service is
read-only by contract (admin.proto §header); this wrapper mirrors that.
"""
from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Generated stubs live next to this file — prepend to path so their
# internal cross-import (`import admin_pb2`) resolves cleanly when the
# War Room is imported as `operations.war_room.client`.
_HERE = Path(__file__).parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import grpc
import admin_pb2  # noqa: E402
import admin_pb2_grpc  # noqa: E402

LOG = logging.getLogger("aeterna.war_room.client")


# --- wire-format-neutral dataclasses ---------------------------------------


@dataclass(frozen=True)
class Quantiles:
    """Latency quantile triple, seconds."""

    p50: float
    p90: float
    p99: float


@dataclass(frozen=True)
class Metrics:
    """One GetMetrics snapshot, in Python-native types."""

    schema_version: int
    node_id: str
    ts_utc: int
    counters: dict[str, int] = field(default_factory=dict)
    gauges: dict[str, float] = field(default_factory=dict)
    quantiles: dict[str, Quantiles] = field(default_factory=dict)
    metric_window_seconds: int = 0


@dataclass(frozen=True)
class AuditLogLine:
    """One record from the append-only audit log."""

    ts_utc: int
    record: str
    json: str


@dataclass(frozen=True)
class AuditTail:
    """Response of TailAuditLog."""

    lines: list[AuditLogLine]


@dataclass(frozen=True)
class Peer:
    """One gossip peer."""

    address: str
    node_id: str
    last_seen_utc: int
    rx_count: int
    tx_count: int
    is_bootstrap: bool


@dataclass(frozen=True)
class PeerList:
    """Response of ListPeers."""

    peers: list[Peer]
    snapshot_utc: int


@dataclass(frozen=True)
class Unreachable:
    """Sentinel returned when an RPC times out or the channel is down.

    The War Room renders this as a red 'degraded' banner and keeps
    polling. Observability must be resilient to transient signer
    unavailability — a suspended or crashing signer is exactly when the
    operator needs the dashboard most.
    """

    reason: str
    elapsed_s: float


# --- client ---------------------------------------------------------------


def _default_target() -> str:
    """Mirror ``core/santuario_client.py`` target resolution."""
    if "SANTUARIO_PORT" in os.environ:
        return f"127.0.0.1:{os.environ['SANTUARIO_PORT']}"
    if sys.platform == "win32":
        return "127.0.0.1:50051"
    socket_path = os.environ.get(
        "SANTUARIO_SOCKET", "/run/aeterna/santuario.sock"
    )
    return f"unix://{socket_path}"


class AdminObserver:
    """Read-only observer of the signer's Admin gRPC surface.

    Wraps the generated ``AdminStub`` with (a) typed dataclasses
    instead of protobuf, (b) per-RPC timeouts, (c) single-shot
    reconnect on transient RpcError. The War Room constructs one of
    these per Streamlit session.
    """

    def __init__(
        self,
        *,
        target: Optional[str] = None,
        rpc_timeout_seconds: float = 1.5,
    ) -> None:
        self._target = target or _default_target()
        self._rpc_timeout = rpc_timeout_seconds
        self._channel: Optional[grpc.Channel] = None
        self._stub: Optional[admin_pb2_grpc.AdminStub] = None

    # --- lifecycle ---

    @property
    def target(self) -> str:
        return self._target

    def _ensure_channel(self) -> None:
        """Create the channel lazily. Does NOT block on readiness.

        We deliberately skip ``grpc.channel_ready_future`` here: the
        War Room polls every 2s and must never stall the whole page
        waiting for a reconnect. If the signer is down, the RPC itself
        fails fast (``Connection refused`` on loopback is immediate,
        off-host dials timeout at ``rpc_timeout_seconds``); gRPC then
        transitions the channel back to IDLE on its own and the next
        RPC attempts re-connection.
        """
        if self._channel is not None and self._stub is not None:
            return
        ch = grpc.insecure_channel(self._target)
        self._channel = ch
        self._stub = admin_pb2_grpc.AdminStub(ch)

    def close(self) -> None:
        if self._channel is not None:
            try:
                self._channel.close()
            except Exception:
                pass
            self._channel = None
            self._stub = None

    # --- RPCs ---

    def get_metrics(self) -> Metrics | Unreachable:
        return self._call("GetMetrics", admin_pb2.GetMetricsRequest(), self._map_metrics)

    def tail_audit_log(self, limit: int = 20) -> AuditTail | Unreachable:
        req = admin_pb2.TailAuditLogRequest(limit=max(0, int(limit)))
        return self._call("TailAuditLog", req, self._map_tail)

    def list_peers(self) -> PeerList | Unreachable:
        return self._call("ListPeers", admin_pb2.ListPeersRequest(), self._map_peers)

    # --- internal ---

    def _call(self, method_name: str, request, mapper):
        self._ensure_channel()
        assert self._stub is not None
        started = time.monotonic()
        try:
            pb_resp = getattr(self._stub, method_name)(
                request, timeout=self._rpc_timeout
            )
            return mapper(pb_resp)
        except grpc.RpcError as exc:
            elapsed = time.monotonic() - started
            code = exc.code() if hasattr(exc, "code") else None
            reason = f"{code.name if code else 'RpcError'}: {exc.details() if hasattr(exc, 'details') else exc}"
            # No manual reconnect. gRPC's own state machine transitions
            # the channel back to IDLE after a failed RPC; the next call
            # triggers a fresh connection attempt. Calling close()+rebuild
            # here on every failure used to stall the Streamlit render
            # loop for ~3s, which kept a stale "dimmed" frame on screen
            # instead of the red 'degraded' banner.
            LOG.warning("Admin %s failed (%s)", method_name, reason)
            return Unreachable(reason=reason, elapsed_s=elapsed)

    # --- protobuf → dataclass mappers ---

    @staticmethod
    def _map_metrics(pb) -> Metrics:
        return Metrics(
            schema_version=int(pb.schema_version),
            node_id=str(pb.node_id),
            ts_utc=int(pb.ts_utc),
            counters={k: int(v) for k, v in pb.counters.items()},
            gauges={k: float(v) for k, v in pb.gauges.items()},
            quantiles={
                k: Quantiles(p50=float(v.p50), p90=float(v.p90), p99=float(v.p99))
                for k, v in pb.quantiles.items()
            },
            metric_window_seconds=int(pb.metric_window_seconds),
        )

    @staticmethod
    def _map_tail(pb) -> AuditTail:
        return AuditTail(
            lines=[
                AuditLogLine(ts_utc=int(l.ts_utc), record=str(l.record), json=str(l.json))
                for l in pb.lines
            ]
        )

    @staticmethod
    def _map_peers(pb) -> PeerList:
        return PeerList(
            peers=[
                Peer(
                    address=str(p.address),
                    node_id=str(p.node_id),
                    last_seen_utc=int(p.last_seen_utc),
                    rx_count=int(p.rx_count),
                    tx_count=int(p.tx_count),
                    is_bootstrap=bool(p.is_bootstrap),
                )
                for p in pb.peers
            ],
            snapshot_utc=int(pb.snapshot_utc),
        )
