#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import socket
import time
from dataclasses import dataclass
from typing import Any

LOG = logging.getLogger("aeterna.rendezvous")

REGISTER_KIND = "rendezvous_register"
PEERS_KIND = "rendezvous_peers"


@dataclass(slots=True)
class Peer:
    guardian_id: str
    host: str
    port: int
    last_seen_ts: float

    @property
    def endpoint(self) -> tuple[str, int]:
        return (self.host, self.port)


class RendezvousRelay:
    """Small UDP rendezvous relay for Phase D fallback.

    The relay learns public UDP endpoints from register packets and forwards
    opaque Aeterna gossip envelopes to other recently-seen peers. It does not
    parse, validate, persist, or mutate AGP payloads.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 4450, *, max_age_seconds: int = 120) -> None:
        self.host = host
        self.port = port
        self.max_age_seconds = max_age_seconds
        self._peers: dict[str, Peer] = {}
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._running = False

    @property
    def bound_address(self) -> tuple[str, int]:
        host, port = self._sock.getsockname()
        return str(host), int(port)

    def stop(self) -> None:
        self._running = False
        self._sock.close()

    def serve_forever(self) -> None:
        self._running = True
        LOG.info("rendezvous relay listening on %s:%d", *self.bound_address)
        while self._running:
            try:
                self.serve_once()
            except OSError:
                if self._running:
                    raise

    def serve_once(self) -> None:
        data, addr = self._sock.recvfrom(65_535)
        try:
            packet = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            LOG.warning("dropping malformed datagram from %s:%d", addr[0], addr[1])
            return

        if isinstance(packet, dict) and packet.get("kind") == REGISTER_KIND:
            self._handle_register(packet, addr)
            return

        self._forward_opaque_gossip(data, packet, addr)

    def _handle_register(self, packet: dict[str, Any], addr: tuple[str, int]) -> None:
        guardian_id = str(packet.get("guardian_id", "unknown"))
        self._prune()
        self._peers[guardian_id] = Peer(
            guardian_id=guardian_id,
            host=addr[0],
            port=addr[1],
            last_seen_ts=time.time(),
        )
        LOG.info("registered %s at %s:%d", guardian_id, addr[0], addr[1])
        self._send_peer_list(addr, exclude_guardian_id=guardian_id)

    def _send_peer_list(self, addr: tuple[str, int], *, exclude_guardian_id: str) -> None:
        peers = [
            {"guardian_id": peer.guardian_id, "host": peer.host, "port": peer.port}
            for peer in self._peers.values()
            if peer.guardian_id != exclude_guardian_id
        ]
        payload = json.dumps({"kind": PEERS_KIND, "peers": peers}, sort_keys=True).encode("utf-8")
        self._sock.sendto(payload, addr)

    def _forward_opaque_gossip(self, data: bytes, packet: Any, addr: tuple[str, int]) -> None:
        self._prune()
        source_guardian_id = packet.get("src") if isinstance(packet, dict) else None
        forwarded = 0
        for peer in list(self._peers.values()):
            if peer.endpoint == addr or peer.guardian_id == source_guardian_id:
                continue
            self._sock.sendto(data, peer.endpoint)
            forwarded += 1
        LOG.debug("forwarded datagram from %s:%d to %d peer(s)", addr[0], addr[1], forwarded)

    def _prune(self) -> None:
        now = time.time()
        stale = [
            guardian_id
            for guardian_id, peer in self._peers.items()
            if now - peer.last_seen_ts > self.max_age_seconds
        ]
        for guardian_id in stale:
            del self._peers[guardian_id]


def main() -> int:
    parser = argparse.ArgumentParser(prog="aeterna-rendezvous")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4450)
    parser.add_argument("--max-age-seconds", type=int, default=120)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args()

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    relay = RendezvousRelay(args.host, args.port, max_age_seconds=args.max_age_seconds)
    try:
        relay.serve_forever()
    except KeyboardInterrupt:
        LOG.info("rendezvous relay stopping")
    finally:
        relay.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
