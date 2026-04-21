#!/usr/bin/env python3
from __future__ import annotations

import logging
import socket
import sys
import time
from pathlib import Path
from typing import Any

sys.path.append(str(Path(__file__).parent.parent))

from core.gossip import AeternaGossipNet
from core.handshake import build_peer_announce, verify_peer_announce


class FakeSantuarioClient:
    def __init__(self, public_key: bytes) -> None:
        self._public_key = public_key

    def get_public_key(self) -> bytes:
        return self._public_key

    def sign(self, payload_hash: bytes) -> bytes:
        return payload_hash[::-1] + self._public_key

    def verify(self, payload_hash: bytes, signature: bytes, public_key: bytes) -> bool:
        return signature == payload_hash[::-1] + public_key


def _free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _callback(
    net: AeternaGossipNet,
    santuario: FakeSantuarioClient,
    seen: dict[str, str],
) -> Any:
    def _inner(message: dict[str, Any]) -> None:
        peer_addr = message.pop("__peer_addr__", None)
        if message.get("kind") != "peer_announce":
            return

        valid, reason = verify_peer_announce(message, santuario)
        if not valid:
            raise AssertionError(reason)

        payload = message["payload"]
        guardian_id = payload["guardian_id"]
        seen[net.guardian_id] = guardian_id
        if peer_addr is not None:
            net.peer_table.add_or_update(peer_addr[0], peer_addr[1], guardian_id)

    return _inner


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("gossip_discovery_test")

    port_a = _free_udp_port()
    port_b = _free_udp_port()
    seen: dict[str, str] = {}

    client_a = FakeSantuarioClient(b"test-public-key-a")
    client_b = FakeSantuarioClient(b"test-public-key-b")

    net_a = AeternaGossipNet(
        "Prometheus-A",
        bind_host="127.0.0.1",
        port=port_a,
        bootstrap_peers=[("127.0.0.1", port_b)],
        on_message=None,
    )
    net_b = AeternaGossipNet(
        "Prometheus-B",
        bind_host="127.0.0.1",
        port=port_b,
        bootstrap_peers=[("127.0.0.1", port_a)],
        on_message=None,
    )
    net_a.on_message = _callback(net_a, client_b, seen)
    net_b.on_message = _callback(net_b, client_a, seen)

    try:
        net_a.start()
        net_b.start()
        time.sleep(0.1)

        net_a.gossip(build_peer_announce("Prometheus-A", "MANIFESTO.md", client_a))
        net_b.gossip(build_peer_announce("Prometheus-B", "MANIFESTO.md", client_b))

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if seen.get("Prometheus-A") == "Prometheus-B" and seen.get("Prometheus-B") == "Prometheus-A":
                log.info("peer discovery passed on ports %d/%d", port_a, port_b)
                return 0
            time.sleep(0.05)

        log.error("peer discovery timed out: seen=%s", seen)
        return 1
    finally:
        net_a.stop()
        net_b.stop()


if __name__ == "__main__":
    sys.exit(main())
