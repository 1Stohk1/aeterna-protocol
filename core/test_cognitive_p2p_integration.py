"""
End-to-end integration test for Rosetta Stone cognitive nodes and P2P expert sharing over real UDP sockets.
"""

import os
import sys
import time
import socket
import secrets
import unittest
import numpy as np
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


class TestCognitiveP2PIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).parent.parent
        self.manifesto_path = self.repo_root / "MANIFESTO.md"
        # Create a dummy MANIFESTO.md if it doesn't exist for test environment
        if not self.manifesto_path.exists():
            self.manifesto_path.write_text("# Dummy Manifesto for Test", encoding="utf-8")
            self._cleanup_manifesto = True
        else:
            self._cleanup_manifesto = False

        self.shared_root_key = secrets.token_bytes(32)

    def tearDown(self) -> None:
        if getattr(self, "_cleanup_manifesto", False) and self.manifesto_path.exists():
            self.manifesto_path.unlink()

    def test_e2e_sprout_gossip_and_assimilation(self) -> None:
        port_a = _free_port()
        port_b = _free_port()

        # Build configurations
        cfg_a = SentinelConfig(
            guardian_id="Prometheus-A",
            gpu_model="RTX 5070",
            vram_gb=12,
            zmq_endpoint="tcp://127.0.0.1:5555",
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
            raw={"santuario": {"enabled": False}, "nucleo": {"reflexive_enabled": True}}
        )

        cfg_b = SentinelConfig(
            guardian_id="Prometheus-B",
            gpu_model="RTX 5070",
            vram_gb=12,
            zmq_endpoint="tcp://127.0.0.1:5556",
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
            raw={"santuario": {"enabled": False}, "nucleo": {"reflexive_enabled": True}}
        )

        # Create Sentinel instances
        sentinel_a = Sentinel(cfg_a, manifesto_path=self.manifesto_path)
        sentinel_b = Sentinel(cfg_b, manifesto_path=self.manifesto_path)

        # Override gossip cipher creation inside awaken by provisioning the shared cipher
        # we bypass load_or_generate_root_key inside awaken for predictability
        cipher_a = GossipCipher(self.shared_root_key)
        cipher_b = GossipCipher(self.shared_root_key)

        try:
            # Wake up sentinels (awaken binds the sockets)
            sentinel_a.awaken()
            # Force mock cipher for test
            sentinel_a._gossip.cipher = cipher_a
            
            sentinel_b.awaken()
            sentinel_b._gossip.cipher = cipher_b

            # Verify both cognitive nodes are successfully initialized
            self.assertIsNotNone(sentinel_a.cognitive_node, "Cognitive node A should be initialized")
            self.assertIsNotNone(sentinel_b.cognitive_node, "Cognitive node B should be initialized")

            # Setup initial experts (ensuring they lie within the valid subspace basis)
            D_shared = 64
            proj_matrix = sentinel_a.cognitive_node.projection_basis
            
            latent_onco = np.random.randn(1, proj_matrix.shape[0])
            oncology_centroid = np.dot(latent_onco, proj_matrix).flatten()
            oncology_centroid /= np.linalg.norm(oncology_centroid)
            
            sentinel_a.cognitive_node.router.add_expert("Oncologia", oncology_centroid)
            sentinel_b.cognitive_node.router.add_expert("Oncologia", oncology_centroid)

            # Generate a novel concept vector in Omega space (lying in the valid anchor subspace)
            # Create a vector lying in the subspace
            latent_climate = np.random.randn(1, proj_matrix.shape[0])
            climate_concept = np.dot(latent_climate, proj_matrix).flatten()
            # Orthogonalize from Oncology to ensure it triggers sprouting
            climate_concept -= np.dot(climate_concept, oncology_centroid) * oncology_centroid
            climate_concept /= np.linalg.norm(climate_concept)

            # --- NODE B VERIFICATION BEFORE GOSSIP ---
            # Node-B has no Expert_2 and should sprout if it processes this vector
            status_b1, result_b1, _, _ = sentinel_b.cognitive_node.process_input(climate_concept)
            self.assertEqual(status_b1, "SPROUTED", "Node B should sprout before assimilation")
            self.assertEqual(result_b1, "Expert_2", "Sprouted expert name should be Expert_2")

            # Let's revert Node B's state (remove sprouted expert to test assimilation)
            sentinel_b.cognitive_node.router.experts.pop("Expert_2", None)

            # --- NODE A SPROUTS & GOSSIPS ---
            # Node-A processes the vector. This will sprout "Expert_2" locally AND gossip it.
            status_a, result_a, pre_a, metric_a = sentinel_a.process_semantic_vector(climate_concept)
            self.assertEqual(status_a, "SPROUTED")
            self.assertEqual(result_a, "Expert_2")

            # Allow gossip network propagation time (UDP loopback)
            time.sleep(0.3)

            # --- NODE B VERIFICATION AFTER GOSSIP ---
            # Check if Node-B received and assimilated "Expert_2"
            self.assertIn("Expert_2", sentinel_b.cognitive_node.router.experts, "Node B should have assimilated Expert_2")

            # Node-B now processes the same vector. It should successfully route to "Expert_2" without sprouting!
            status_b2, result_b2, pre_b2, metric_b2 = sentinel_b.cognitive_node.process_input(climate_concept)
            self.assertEqual(status_b2, "ROUTE_SUCCESS", "Node B should route successfully to Expert_2 after assimilation")
            self.assertEqual(result_b2, "Expert_2", "Should be routed to Expert_2")
            self.assertTrue(pre_b2 <= sentinel_b.cognitive_node.pre_threshold, "PRE must be below threshold after assimilation")

        finally:
            sentinel_a.shutdown()
            sentinel_b.shutdown()


if __name__ == "__main__":
    unittest.main()
