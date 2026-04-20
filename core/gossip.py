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
        on_message: Callable[[dict], None] | None = None,
    ) -> None:
        self.guardian_id = guardian_id
        self.bind_host = bind_host
        self.port = port
        self.fanout = fanout
        self.default_ttl = ttl
        self.on_message = on_message

        self.known_peers: list[tuple[str, int]] = list(bootstrap_peers)
        self._seen: deque[str] = deque(maxlen=seen_cache_size)
        self._seen_set: set[str] = set()

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind_host, port))

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

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

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
        self._relay(envelope)
        return mid

    def add_peer(self, host: str, port: int) -> None:
        peer = (host, port)
        if peer not in self.known_peers and peer != (self.bind_host, self.port):
            self.known_peers.append(peer)
            LOG.debug("peer added %s:%d", host, port)

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
        if envelope["ttl"] <= 0 or not self.known_peers:
            return
        envelope["ttl"] -= 1
        payload = json.dumps(envelope, sort_keys=True).encode("utf-8")
        targets = random.sample(
            self.known_peers, min(self.fanout, len(self.known_peers))
        )
        for host, port in targets:
            try:
                self._sock.sendto(payload, (host, port))
            except OSError as exc:
                LOG.warning("relay to %s:%d failed: %s", host, port, exc)

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

            if not self._remember(mid):
                continue  # duplicate — already relayed

            # Opportunistic peer discovery.
            self.add_peer(addr[0], self.port)

            if self.on_message is not None:
                try:
                    self.on_message(envelope.get("body", {}))
                except Exception:  # noqa: BLE001  — gossip must not die
                    LOG.exception("on_message callback raised")

            self._relay(envelope)
