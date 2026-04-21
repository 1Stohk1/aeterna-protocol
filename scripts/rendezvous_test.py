#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys
import threading
import time
from pathlib import Path
from typing import Any

sys.path.append(str(Path(__file__).parent.parent))

from core.gossip import AeternaGossipNet
from core.handshake import build_peer_announce, verify_peer_announce
from core.nat_udp import RendezvousHint
from ops.rendezvous.server import RendezvousRelay


class FakeSantuarioClient:
    def __init__(self, public_key: bytes) -> None:
        self._public_key = public_key

    def get_public_key(self) -> bytes:
        return self._public_key

    def sign(self, payload_hash: bytes) -> bytes:
        return payload_hash[::-1] + self._public_key

    def verify(self, payload_hash: bytes, signature: bytes, public_key: bytes) -> bool:
        return signature == payload_hash[::-1] + public_key


def _callback(
    net: AeternaGossipNet,
    santuario: FakeSantuarioClient,
    seen: dict[str, str],
) -> Any:
    def _inner(message: dict[str, Any]) -> None:
        message.pop("__peer_addr__", None)
        if message.get("kind") != "peer_announce":
            return
        valid, reason = verify_peer_announce(message, santuario)
        if not valid:
            raise AssertionError(reason)
        seen[net.guardian_id] = message["payload"]["guardian_id"]

    return _inner


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("rendezvous_test")

    relay = RendezvousRelay("127.0.0.1", 0)
    relay_host, relay_port = relay.bound_address
    relay_thread = threading.Thread(target=relay.serve_forever, name="rendezvous-test", daemon=True)
    relay_thread.start()

    seen: dict[str, str] = {}
    client_a = FakeSantuarioClient(b"test-public-key-a")
    client_b = FakeSantuarioClient(b"test-public-key-b")
    hint = RendezvousHint(relay_host, relay_port)

    net_a = AeternaGossipNet(
        "Prometheus-A",
        bind_host="127.0.0.1",
        port=0,
        rendezvous_hints=[hint],
        on_message=None,
    )
    net_b = AeternaGossipNet(
        "Prometheus-B",
        bind_host="127.0.0.1",
        port=0,
        rendezvous_hints=[hint],
        on_message=None,
    )
    net_a.on_message = _callback(net_a, client_b, seen)
    net_b.on_message = _callback(net_b, client_a, seen)

    try:
        net_a.start()
        net_b.start()
        time.sleep(0.2)

        net_a.gossip(build_peer_announce("Prometheus-A", "MANIFESTO.md", client_a))
        net_b.gossip(build_peer_announce("Prometheus-B", "MANIFESTO.md", client_b))

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if seen.get("Prometheus-A") == "Prometheus-B" and seen.get("Prometheus-B") == "Prometheus-A":
                log.info("rendezvous relay passed via %s:%d", relay_host, relay_port)
                return 0
            time.sleep(0.05)

        log.error("rendezvous relay timed out: seen=%s", seen)
        return 1
    finally:
        net_a.stop()
        net_b.stop()
        relay.stop()


if __name__ == "__main__":
    sys.exit(main())
