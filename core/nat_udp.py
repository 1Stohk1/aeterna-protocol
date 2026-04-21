from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Iterable


RENDEZVOUS_REGISTER = "rendezvous_register"
RENDEZVOUS_PEERS = "rendezvous_peers"


@dataclass(frozen=True, slots=True)
class RendezvousHint:
    host: str
    port: int


def parse_rendezvous_hints(raw_hints: Iterable[str]) -> list[RendezvousHint]:
    hints: list[RendezvousHint] = []
    for raw in raw_hints:
        value = raw.strip()
        if value.startswith("udp://"):
            value = value[len("udp://"):]
        host, sep, port_raw = value.rpartition(":")
        if not sep or not host:
            raise ValueError(f"invalid rendezvous hint: {raw!r}")
        hints.append(RendezvousHint(host=host, port=int(port_raw)))
    return hints


def build_register_packet(guardian_id: str, listen_port: int) -> bytes:
    return json.dumps(
        {
            "kind": RENDEZVOUS_REGISTER,
            "guardian_id": guardian_id,
            "listen_port": listen_port,
            "ts": int(time.time()),
        },
        sort_keys=True,
    ).encode("utf-8")


def is_rendezvous_peers_packet(packet: dict[str, Any]) -> bool:
    return packet.get("kind") == RENDEZVOUS_PEERS and isinstance(packet.get("peers"), list)


def extract_rendezvous_peers(packet: dict[str, Any], guardian_id: str) -> list[tuple[str, int, str]]:
    peers: list[tuple[str, int, str]] = []
    for peer in packet.get("peers", []):
        if not isinstance(peer, dict):
            continue
        peer_id = str(peer.get("guardian_id", "unknown"))
        if peer_id == guardian_id:
            continue
        host = peer.get("host")
        port = peer.get("port")
        if not isinstance(host, str) or not isinstance(port, int):
            continue
        peers.append((host, port, peer_id))
    return peers
