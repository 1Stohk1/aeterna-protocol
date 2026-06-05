"""
Integration and unit tests for Aeterna's Bloom Filter and optimized P2P Anti-Entropy recovery.
"""

import os
import sys
import time
import socket
import secrets
import unittest
from pathlib import Path

# Adjust path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.bloom_filter import BloomFilter
from core.sentinel import Sentinel, SentinelConfig
from core.sigillum_gossip import GossipCipher


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


class TestBloomFilterUnit(unittest.TestCase):
    def test_basic_add_and_contains(self) -> None:
        bf = BloomFilter(size_bits=512, num_hashes=7)
        items = ["hash1", "hash2", "hash3"]
        for item in items:
            bf.add(item)

        for item in items:
            self.assertIn(item, bf)

        self.assertNotIn("hash4", bf)

    def test_serialization_roundtrip(self) -> None:
        bf = BloomFilter(size_bits=256, num_hashes=5)
        bf.add("test-item-123")
        bf.add("another-item")

        b64 = bf.to_base64()
        self.assertIsInstance(b64, str)

        bf_restored = BloomFilter.from_base64(b64, size_bits=256, num_hashes=5)
        self.assertIn("test-item-123", bf_restored)
        self.assertIn("another-item", bf_restored)
        self.assertNotIn("missing-item", bf_restored)


class TestBloomAntiEntropyIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).parent.parent
        self.manifesto_path = self.repo_root / "MANIFESTO.md"
        if not self.manifesto_path.exists():
            self.manifesto_path.write_text("# Dummy Manifesto for Test", encoding="utf-8")
            self._cleanup_manifesto = True
        else:
            self._cleanup_manifesto = False

        self.shared_root_key = secrets.token_bytes(32)

    def tearDown(self) -> None:
        if getattr(self, "_cleanup_manifesto", False) and self.manifesto_path.exists():
            self.manifesto_path.unlink()

    def test_e2e_bloom_push_gap_resolution(self) -> None:
        port_a = _free_port()
        port_b = _free_port()

        # Node A (Receiver who misses the message)
        cfg_a = SentinelConfig(
            guardian_id="Prometheus-A",
            gpu_model="RTX 5070",
            vram_gb=12,
            zmq_endpoint="tcp://127.0.0.1:5559",
            zmq_send_timeout_ms=1000,
            zmq_recv_timeout_ms=1000,
            gossip_port=port_a,
            gossip_fanout=2,
            gossip_ttl=3,
            bootstrap_peers=[("127.0.0.1", port_b)],
            rendezvous_hints=[],
            pow_difficulty=1,
            default_task="tumor_growth_gompertz",
            agp_protocol_version="AGP-v1",
            freeze_julia_version="1.10.2",
            accept_agpl_license=True,
            accept_prometeo_clause=True,
            poc_sample_rate_pct=100,
            raw={"santuario": {"enabled": False}, "nucleo": {"reflexive_enabled": False}}
        )

        # Node B (Sender who caches the message)
        cfg_b = SentinelConfig(
            guardian_id="Prometheus-B",
            gpu_model="RTX 5070",
            vram_gb=12,
            zmq_endpoint="tcp://127.0.0.1:5560",
            zmq_send_timeout_ms=1000,
            zmq_recv_timeout_ms=1000,
            gossip_port=port_b,
            gossip_fanout=2,
            gossip_ttl=3,
            bootstrap_peers=[("127.0.0.1", port_a)],
            rendezvous_hints=[],
            pow_difficulty=1,
            default_task="tumor_growth_gompertz",
            agp_protocol_version="AGP-v1",
            freeze_julia_version="1.10.2",
            accept_agpl_license=True,
            accept_prometeo_clause=True,
            poc_sample_rate_pct=100,
            raw={"santuario": {"enabled": False}, "nucleo": {"reflexive_enabled": False}}
        )

        sentinel_a = Sentinel(cfg_a, manifesto_path=self.manifesto_path)
        sentinel_b = Sentinel(cfg_b, manifesto_path=self.manifesto_path)

        cipher_a = GossipCipher(self.shared_root_key)
        cipher_b = GossipCipher(self.shared_root_key)

        received_messages_a = []

        try:
            # Wake up sentinels
            sentinel_a.awaken()
            sentinel_a._gossip.cipher = cipher_a

            sentinel_b.awaken()
            sentinel_b._gossip.cipher = cipher_b

            # Track received messages on Node-A
            original_on_gossip_a = sentinel_a._on_gossip
            def mock_on_gossip_a(msg):
                received_messages_a.append(msg)
                original_on_gossip_a(msg)
            sentinel_a._on_gossip = mock_on_gossip_a
            sentinel_a._gossip.on_message = mock_on_gossip_a

            # 1. NODE B GOSSIPS MESSAGE WHILE DISCONNECTED FROM NODE A
            # Temporarily clear Node-A from Node-B's active peer table
            sentinel_b._gossip.peer_table._peers.clear()

            # Node-B gossips the task offer
            msg_payload = {"kind": "task_offer", "task": {"id_task": "TASK-LOST-BLOOM", "tipo_analisi": "tumor_growth_gompertz"}}
            lost_mid = sentinel_b._gossip.gossip(msg_payload)

            # Assert Node-A has not received it yet
            time.sleep(0.1)
            self.assertEqual(len(received_messages_a), 0, "Node A should not have received the message yet")

            # 2. RESTORE CONNECTION & EXCHANGE BLOOM FILTER
            sentinel_a._gossip.add_peer("127.0.0.1", port_b)
            sentinel_b._gossip.add_peer("127.0.0.1", port_a)

            # Node-A sends its entropy digest (Bloom Filter) to Node-B
            # Node-A's Bloom Filter represents A's seen cache, which does NOT contain lost_mid
            bf = BloomFilter(size_bits=512, num_hashes=7)
            # Add any dummy hashes that A might have seen
            bf.add("some-dummy-mid-hash")
            
            digest_msg = {
                "kind": "entropy_digest",
                "payload": {
                    "sender_id": sentinel_a.cfg.guardian_id,
                    "bloom_filter": bf.to_base64()
                }
            }
            # Send the digest directly to Node-B
            sentinel_a._gossip.send_direct_message("127.0.0.1", port_b, digest_msg)

            # 3. VERIFY AUTO-RECOVERY (2-STEP PUSH)
            # When Node-B receives the Bloom Filter, it checks its cache.
            # lost_mid is in B's cache but is not in A's Bloom Filter.
            # Node-B should push lost_mid directly to Node-A.
            deadline = time.time() + 2.0
            recovered = False
            while time.time() < deadline:
                for msg in received_messages_a:
                    if msg.get("kind") == "task_offer" and msg.get("task", {}).get("id_task") == "TASK-LOST-BLOOM":
                        recovered = True
                        break
                if recovered:
                    break
                time.sleep(0.05)

            self.assertTrue(recovered, "Node A did not recover the lost message through Bloom Filter push")

        finally:
            sentinel_a.shutdown()
            sentinel_b.shutdown()


if __name__ == "__main__":
    unittest.main()
