"""
End-to-end smoke test for Sigillum-wrapped gossip on loopback UDP.

Two AeternaGossipNet instances bound to ephemeral 127.0.0.1 ports
share a single ephemeral GossipCipher root key. The test verifies
that:

* a message gossiped from A reaches B via UDP
* the wire bytes are NOT plaintext (they MUST be ChaCha20 ciphertext)
* a frame addressed to a different cipher does NOT reach the
  application-level callback (auth fails silently)
"""

from __future__ import annotations

import secrets
import socket
import time
import unittest

from core.gossip import AeternaGossipNet
from core.sigillum_gossip import GossipCipher


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


class GossipIntegrationTests(unittest.TestCase):
    def test_e2e_message_round_trip_under_sigillum(self) -> None:
        port_a = _free_port()
        port_b = _free_port()
        shared_root = secrets.token_bytes(32)
        received_at_b: list[dict] = []

        net_a = AeternaGossipNet(
            "Prometheus-A",
            cipher=GossipCipher(shared_root),
            bind_host="127.0.0.1",
            port=port_a,
            bootstrap_peers=[("127.0.0.1", port_b)],
            on_message=None,
        )
        net_b = AeternaGossipNet(
            "Prometheus-B",
            cipher=GossipCipher(shared_root),
            bind_host="127.0.0.1",
            port=port_b,
            bootstrap_peers=[("127.0.0.1", port_a)],
            on_message=lambda body: received_at_b.append(body),
        )
        try:
            net_a.start()
            net_b.start()
            # Brief warm-up so peer-table entries settle.
            time.sleep(0.05)
            net_a.gossip({"hello": "from-a", "secret": "rosebud"})
            # Allow propagation.
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and not received_at_b:
                time.sleep(0.02)
        finally:
            net_a.stop()
            net_b.stop()

        self.assertTrue(received_at_b, "B never received A's gossip")
        body = received_at_b[0]
        self.assertEqual(body.get("hello"), "from-a")
        self.assertEqual(body.get("secret"), "rosebud")

    def test_wrong_cipher_blocks_message(self) -> None:
        # B has a different root key; A's frames must fail auth at B.
        port_a = _free_port()
        port_b = _free_port()
        received_at_b: list[dict] = []

        net_a = AeternaGossipNet(
            "Prometheus-A",
            cipher=GossipCipher(secrets.token_bytes(32)),
            bind_host="127.0.0.1",
            port=port_a,
            bootstrap_peers=[("127.0.0.1", port_b)],
            on_message=None,
        )
        net_b = AeternaGossipNet(
            "Prometheus-B",
            cipher=GossipCipher(secrets.token_bytes(32)),  # DIFFERENT root
            bind_host="127.0.0.1",
            port=port_b,
            bootstrap_peers=[("127.0.0.1", port_a)],
            on_message=lambda body: received_at_b.append(body),
        )
        try:
            net_a.start()
            net_b.start()
            time.sleep(0.05)
            net_a.gossip({"forbidden": "payload"})
            time.sleep(0.5)
        finally:
            net_a.stop()
            net_b.stop()

        self.assertEqual(
            received_at_b,
            [],
            "B must not see A's payload when the root keys differ",
        )

    def test_wire_bytes_are_ciphertext(self) -> None:
        # Sniff the bytes on the wire and assert the secret string
        # does NOT appear in plaintext.
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sniffer.bind(("127.0.0.1", 0))
        sniffer_port = sniffer.getsockname()[1]
        sniffer.settimeout(2.0)

        shared_root = secrets.token_bytes(32)
        # A relays to the sniffer as if it were a peer.
        net_a = AeternaGossipNet(
            "Prometheus-A",
            cipher=GossipCipher(shared_root),
            bind_host="127.0.0.1",
            port=_free_port(),
            bootstrap_peers=[("127.0.0.1", sniffer_port)],
            on_message=None,
        )
        try:
            net_a.start()
            time.sleep(0.05)
            net_a.gossip({"top_secret": "rosebud_xyz_unique"})
            data, _addr = sniffer.recvfrom(65_535)
        finally:
            net_a.stop()
            sniffer.close()

        self.assertEqual(data[0], 0x04, "first byte must be Sigillum schema_version")
        # The unique substring MUST NOT be grep-able in the wire bytes.
        self.assertNotIn(
            b"rosebud_xyz_unique",
            data,
            "plaintext leak: secret substring found in encrypted gossip frame",
        )


if __name__ == "__main__":
    unittest.main()
