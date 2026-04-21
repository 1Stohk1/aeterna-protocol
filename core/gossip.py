"""
AeternaGossipNet — pure UDP P2P gossip for the Sentinel.

No central broker. No DHT in v0.0.1 (bootstrap list only). Every Guardian
keeps a bounded set of recently-seen message hashes to suppress storms and
relays unseen messages to a random subset of known peers.

This module is deliberately small. Hardening (fanout tuning, peer scoring,
onion routing for Saggio-tier peers) lands in v0.2.0.
"""

from __future__ import annotations

import json
import logging
import random
import socket
import threading
import time
from collections import deque
from hashlib import sha256
from typing import Callable, Iterable

from core.nat_udp import (
    RendezvousHint,
    build_register_packet,
    extract_rendezvous_peers,
    is_rendezvous_peers_packet,
)
from core.peer_table import PeerTable

LOG = logging.getLogger("aeterna.gossip")


class AeternaGossipNet:
    """UDP gossip transport for the Sentinel.

    Parameters
    ----------
    guardian_id:
        Human-readable identity of this node (e.g. ``"Prometheus-0"``).
    bind_host, port:
        UDP bind address. The default ``0.0.0.0:4444`` matches ``aeterna.toml``.
    bootstrap_peers:
        Initial peer list as ``(host, port)`` tuples. New peers discovered at
        runtime are appended to :attr:`known_peers`.
    fanout, ttl:
        Each unseen message is relayed to ``fanout`` randomly-chosen peers
        until its TTL decays to zero.
    seen_cache_size:
        Size of the LRU of message hashes used to drop duplicates.
    on_message:
        Callback invoked for every freshly-accepted message. Receives the
        parsed dict. Errors inside the callback are logged and swallowed —
        the gossip listener must never die.
    """

    def __init__(
        self,
        guardian_id: str,
        *,
        bind_host: str = "0.0.0.0",
        port: int = 4444,
        bootstrap_peers: Iterable[tuple[str, int]] = (),
        fanout: int = 4,
        ttl: int = 7,
        seen_cache_size: int = 10_000,
        rendezvous_hints: Iterable[RendezvousHint] = (),
        on_message: Callable[[dict], None] | None = None,
    ) -> None:
        self.guardian_id = guardian_id
        self.bind_host = bind_host
        self.port = port
        self.fanout = fanout
        self.default_ttl = ttl
        self.on_message = on_message

        self.peer_table = PeerTable(max_age_seconds=120)
        for peer_host, peer_port in bootstrap_peers:
            self.peer_table.add_or_update(peer_host, peer_port)
        self.rendezvous_hints = list(rendezvous_hints)
        self._rendezvous_targets = {(hint.host, hint.port) for hint in self.rendezvous_hints}

        self._seen: deque[str] = deque(maxlen=seen_cache_size)
        self._seen_set: set[str] = set()
        self._last_rendezvous_register_ts = 0.0

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind_host, self.port))
        self.port = int(self._sock.getsockname()[1])

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._listen_loop, name="gossip-listen", daemon=True
        )
        self._thread.start()
        LOG.info("gossip listening on %s:%d", self.bind_host, self.port)
        self._maybe_register_rendezvous(force=True)

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def gossip(self, message: dict, *, ttl: int | None = None) -> str:
        """Broadcast a new message. Returns the message hash."""
        envelope = {
            "src": self.guardian_id,
            "ts": int(time.time()),
            "ttl": ttl if ttl is not None else self.default_ttl,
            "body": message,
        }
        raw = json.dumps(envelope, sort_keys=True).encode("utf-8")
        mid = sha256(raw).hexdigest()
        envelope["mid"] = mid
        self._remember(mid)
        self._maybe_register_rendezvous()
        self._relay(envelope)
        return mid

    def add_peer(self, host: str, port: int) -> None:
        if (host, port) != (self.bind_host, self.port):
            self.peer_table.add_or_update(host, port)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _remember(self, mid: str) -> bool:
        if mid in self._seen_set:
            return False
        self._seen.append(mid)
        self._seen_set.add(mid)
        # Keep the set trimmed to the deque window.
        if len(self._seen_set) > self._seen.maxlen:  # type: ignore[operator]
            self._seen_set = set(self._seen)
        return True

    def _relay(self, envelope: dict) -> None:
        if self._stop.is_set():
            return
        active_peers = self.peer_table.get_active_peers()
        if envelope["ttl"] <= 0:
            return
        envelope["ttl"] -= 1
        payload = json.dumps(envelope, sort_keys=True).encode("utf-8")
        targets = set(random.sample(active_peers, min(self.fanout, len(active_peers))))
        targets.update(self._rendezvous_targets)
        if not targets:
            return
        for host, port in targets:
            try:
                self._sock.sendto(payload, (host, port))
            except OSError as exc:
                if self._stop.is_set():
                    return
                LOG.warning("relay to %s:%d failed: %s", host, port, exc)

    def _maybe_register_rendezvous(self, *, force: bool = False) -> None:
        if not self.rendezvous_hints:
            return
        now = time.time()
        if not force and now - self._last_rendezvous_register_ts < 30.0:
            return
        packet = build_register_packet(self.guardian_id, self.port)
        for hint in self.rendezvous_hints:
            try:
                self._sock.sendto(packet, (hint.host, hint.port))
            except OSError as exc:
                LOG.warning("rendezvous register to %s:%d failed: %s", hint.host, hint.port, exc)
        self._last_rendezvous_register_ts = now

    def _listen_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65_535)
            except OSError:
                break
            try:
                envelope = json.loads(data.decode("utf-8"))
                mid = envelope.get("mid") or sha256(data).hexdigest()
            except (UnicodeDecodeError, json.JSONDecodeError):
                LOG.warning("dropped malformed datagram from %s", addr)
                continue

            if is_rendezvous_peers_packet(envelope):
                for host, port, guardian_id in extract_rendezvous_peers(envelope, self.guardian_id):
                    self.peer_table.add_or_update(host, port, guardian_id)
                continue

            if not self._remember(mid):
                continue  # duplicate — already relayed

            # Opportunistic peer discovery. With UDP, the source port is the
            # peer's reachable gossip port when it sends from its bound socket.
            if addr not in self._rendezvous_targets:
                self.add_peer(addr[0], addr[1])

            if self.on_message is not None:
                try:
                    body = envelope.get("body", {})
                    if isinstance(body, dict):
                        body["__peer_addr__"] = addr
                    self.on_message(body)
                except Exception:  # noqa: BLE001  — gossip must not die
                    LOG.exception("on_message callback raised")

            self._relay(envelope)
