"""
Integration test for the Aeterna P2P Anti-Entropy recovery protocol over loopback UDP.
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
from core.sentinel import Sentinel, SentinelConfig
from core.sigillum_gossip import GossipCipher


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


class TestAntiEntropyIntegration(unittest.TestCase):
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

    def test_gap_detection_and_retransmission(self) -> None:
        port_a = _free_port()
        port_b = _free_port()

        # Config Sentinel A
        cfg_a = SentinelConfig(
            guardian_id="Prometheus-A",
            gpu_model="RTX 5070",
            vram_gb=12,
            zmq_endpoint="tcp://127.0.0.1:5557",
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

        # Config Sentinel B
        cfg_b = SentinelConfig(
            guardian_id="Prometheus-B",
            gpu_model="RTX 5070",
            vram_gb=12,
            zmq_endpoint="tcp://127.0.0.1:5558",
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

        received_messages_b = []

        try:
            # Wake up sentinels
            sentinel_a.awaken()
            sentinel_a._gossip.cipher = cipher_a

            sentinel_b.awaken()
            sentinel_b._gossip.cipher = cipher_b
            
            # Setup custom callback on Node-B to capture received messages
            original_on_gossip = sentinel_b._on_gossip
            def mock_on_gossip(msg):
                received_messages_b.append(msg)
                original_on_gossip(msg)
            sentinel_b._on_gossip = mock_on_gossip
            sentinel_b._gossip.on_message = mock_on_gossip

            # 1. SIMULATE MESSAGE GENERATION ON A WITH B OFFLINE/DISCONNECTED
            # We temporarily clear Node-B from Node-A's active peer table so that A's gossip does not reach B
            sentinel_a._gossip.peer_table._peers.clear()

            # Node-A gossips a message (e.g. a task offer)
            msg_payload = {"kind": "task_offer", "task": {"id_task": "TASK-LOST-123", "tipo_analisi": "tumor_growth_gompertz"}}
            lost_mid = sentinel_a._gossip.gossip(msg_payload)

            # Node-B has NOT received the message
            time.sleep(0.1)
            self.assertEqual(len(received_messages_b), 0, "Node B should not have received the message yet")

            # 2. RESTORE CONNECTION & EXCHANGE ENTROPY DIGEST
            # Restore peer tables
            sentinel_a._gossip.add_peer("127.0.0.1", port_b)
            sentinel_b._gossip.add_peer("127.0.0.1", port_a)

            # Node-A sends its entropy digest containing the lost message mid to Node-B
            digest_msg = {
                "kind": "entropy_digest",
                "payload": {
                    "sender_id": sentinel_a.cfg.guardian_id,
                    "recent_mids": [lost_mid]
                }
            }
            # We send it directly to Node-B
            sentinel_a._gossip.send_direct_message("127.0.0.1", port_b, digest_msg)

            # 3. VERIFY AUTO-RECOVERY
            # When Node-B receives the digest, it will see that lost_mid is missing.
            # It will send a message_request to Node-A.
            # Node-A will receive the request, retrieve the message from its body cache, and retransmit it.
            deadline = time.time() + 2.0
            recovered = False
            while time.time() < deadline:
                # Check if Node-B received the task_offer
                for msg in received_messages_b:
                    if msg.get("kind") == "task_offer" and msg.get("task", {}).get("id_task") == "TASK-LOST-123":
                        recovered = True
                        break
                if recovered:
                    break
                time.sleep(0.05)

            self.assertTrue(recovered, "Node B did not recover the lost message through Anti-Entropy")

        finally:
            sentinel_a.shutdown()
            sentinel_b.shutdown()


if __name__ == "__main__":
    unittest.main()
