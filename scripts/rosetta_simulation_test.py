import sys
import os
import numpy as np

# Adjust path to import core.rosetta
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.rosetta import RosettaAligner

def main():
    print("======================================================================")
    print("AETERNA PROTOCOL - SEMANTIC ALIGNMENT & IMMUNOLOGY SIMULATION")
    print("======================================================================")
    
    np.random.seed(42)
    
    # 1. SETUP THE SHARED SPACE AND SUBSPACE ANCHORS
    D_shared = 64      # Omega space dimension
    D_intrinsic = 20   # Intrinsic dimension of the semantic manifold
    num_anchors = 100  # Calibration anchor set size
    
    print(f"\n[1] Inizializzazione dello Spazio di Ancoraggio Omega (Dimensioni: {D_shared}, Intrinseca: {D_intrinsic})")
    
    # Generate low-rank shared anchors using an orthogonal projection matrix
    latent_anchors = np.random.randn(num_anchors, D_intrinsic)
    projection_basis = np.random.randn(D_intrinsic, D_shared)
    q_proj, _ = np.linalg.qr(projection_basis.T)
    projection_matrix = q_proj.T # D_intrinsic x D_shared orthogonal rows
    
    # Shared anchors lie entirely in the D_intrinsic subspace
    Omega_anchors = np.dot(latent_anchors, projection_matrix)
    Omega_anchors /= np.linalg.norm(Omega_anchors, axis=1, keepdims=True)
    
    # 2. CREATE A MULTI-NODE NETWORK MESH
    # We define 5 honest nodes with asymmetric internal dimensionalities
    node_configs = [
        {"name": "Osservatore-A", "dim": 128},
        {"name": "Guardiano-B",   "dim": 256},
        {"name": "Saggio-C",      "dim": 512},
        {"name": "Architetto-D",  "dim": 384},
        {"name": "Sentinel-E",   "dim": 192}
    ]
    
    nodes = []
    print(f"\n[2] Calibrazione locale di {len(node_configs)} nodi asimmetrici...")
    
    for idx, config in enumerate(node_configs):
        name = config["name"]
        d_local = config["dim"]
        
        # Instantiate Rosetta aligner for this node
        aligner = RosettaAligner(shared_dim=D_shared, local_dim=d_local)
        
        # Generate a unique distortion transformation for this node's internal model
        true_transform = np.random.randn(D_shared, d_local)
        true_transform /= np.linalg.norm(true_transform, axis=0) # Normalize columns
        
        # Node's local representations of the anchors, adding unique pretraining noise
        local_noise = np.random.normal(0, 0.05, (num_anchors, d_local))
        local_anchors = np.dot(Omega_anchors, true_transform) + local_noise
        
        # Calibrate the node's local projection matrix W
        rmse = aligner.calibrate(local_anchors, Omega_anchors)
        
        nodes.append({
            "name": name,
            "aligner": aligner,
            "true_transform": true_transform,
            "rmse": rmse
        })
        print(f"  -> Nodo {idx} [{name}] (d={d_local}): Calibrazione completata (RMSE: {rmse:.4f})")

    # 3. SEMANTIC GOSSIP (CONCEPT PROPAGATION WITH NETWORK NOISE)
    print("\n[3] Simulazione di Gossip Semantico (Propagazione di concetti)...")
    
    # Node 0 (Osservatore-A) generates a new concept in the shared subspace
    source_node = nodes[0]
    print(f"  * {source_node['name']} scopre un nuovo concetto interno...")
    
    # Generate random active state in Node 0's internal representation from the valid subspace
    latent_concept = np.random.randn(1, D_intrinsic)
    shared_concept_omega = np.dot(latent_concept, projection_matrix)
    shared_concept_omega /= np.linalg.norm(shared_concept_omega)
    
    local_concept_vector = np.dot(shared_concept_omega, source_node["true_transform"]) + np.random.normal(0, 0.02, (1, source_node["aligner"].local_dim))
    
    # Project to the shared Omega space
    shared_concept_omega_actual = source_node["aligner"].project(local_concept_vector)
    
    # Gossip the concept across the network, adding transmission noise
    transmission_noise_level = 0.02
    print(f"  * Gossip in corso... Aggiunta rumore di trasmissione (sigma={transmission_noise_level})")
    
    # Simulate gossip delivery to all other nodes
    for idx, dest_node in enumerate(nodes[1:], start=1):
        # Add independent noise to simulation
        noise = np.random.normal(0, transmission_noise_level, (1, D_shared))
        received_omega = shared_concept_omega_actual + noise
        
        # Destination node reconstructs the vector into its local space
        reconstructed_local = dest_node["aligner"].reconstruct(received_omega)
        
        # Destination node projects back to shared space to measure similarity
        reprojected_omega = dest_node["aligner"].project(reconstructed_local)
        
        # Calculate cosine similarity with the original source concept
        similarity = dest_node["aligner"].cosine_similarity(shared_concept_omega_actual, reprojected_omega)
        
        print(f"    -> Connessione con {dest_node['name']} (d={dest_node['aligner'].local_dim}):")
        print(f"       Similarita Cosenuale del Significato: {similarity * 100:.2f}%")
        
        # Assert similarity is high (>90% under noise)
        assert similarity > 0.90, f"La similarita per {dest_node['name']} e' troppo bassa!"

    # 4. SEMANTIC IMMUNOLOGY (ATTACK FILTERING)
    print("\n[4] Simulazione di Immunologia Semantica (Rifiuto payload nocivi/estranei)...")
    
    # Define an immunological threshold based on calibration errors
    # If the projection reconstruction error (PRE) exceeds this, the node rejects the packet.
    immunology_threshold = 0.35
    print(f"  * Impostazione Soglia Immunitaria (Distanza PRE max: {immunology_threshold})")
    
    # Test Node 1 (Guardiano-B) as the validator
    validator = nodes[1]
    
    # Case A: Honest message from Node 0
    honest_noise = np.random.normal(0, 0.02, (1, D_shared))
    honest_packet = shared_concept_omega_actual + honest_noise
    
    # Validate honest message
    reconstructed_h = validator["aligner"].reconstruct(honest_packet)
    reprojected_h = validator["aligner"].project(reconstructed_h)
    pre_honest = np.linalg.norm(honest_packet - reprojected_h)
    
    print(f"\n  * Validazione pacchetto onesto da {validator['name']}:")
    print(f"    - Errore di ricostruzione (PRE): {pre_honest:.4f}")
    if pre_honest <= immunology_threshold:
        print("    - [ACCETTATO] Il concetto si integra armonicamente nella matrice cognitiva locale.")
    else:
        print("    - [RIFIUTATO] Rilevata anomalia semantica!")
    assert pre_honest <= immunology_threshold, "Il pacchetto onesto non avrebbe dovuto essere rifiutato!"
        
    # Case B: Malicious random payload (Spam / High-Entropy Attack)
    # Generate a completely random 64D vector that will lie outside the 20D subspace
    malicious_packet = np.random.randn(1, D_shared)
    malicious_packet /= np.linalg.norm(malicious_packet) # Scale similarly
    
    # Validate malicious random message
    reconstructed_m = validator["aligner"].reconstruct(malicious_packet)
    reprojected_m = validator["aligner"].project(reconstructed_m)
    pre_malicious = np.linalg.norm(malicious_packet - reprojected_m)
    
    print(f"\n  * Validazione pacchetto malevolo (Spam casuale) da {validator['name']}:")
    print(f"    - Errore di ricostruzione (PRE): {pre_malicious:.4f}")
    if pre_malicious <= immunology_threshold:
        print("    - [ACCETTATO] Il concetto si integra armonicamente nella matrice cognitiva locale.")
    else:
        print("    - [RIFIUTATO] Rilevata anomalia semantica! Pacchetto messo in quarantena.")
    assert pre_malicious > immunology_threshold, "L'attacco di spam casuale avrebbe dovuto essere rifiutato!"
        
    # Case C: Malicious OOD targeted attack (Adversarial Concept orthogonal to the anchor space)
    # We construct a vector in the nullspace of the projection matrix
    # Project a random vector onto the orthogonal complement of the projection_matrix rows
    u, s, vh = np.linalg.svd(projection_matrix)
    # vh has shape D_shared x D_shared. The last (D_shared - D_intrinsic) rows are orthogonal to the projection space.
    orthogonal_basis = vh[D_intrinsic:] # (D_shared - D_intrinsic) x D_shared
    
    # Linear combination of orthogonal vectors
    adversarial_packet = np.dot(np.random.randn(1, D_shared - D_intrinsic), orthogonal_basis)
    adversarial_packet /= np.linalg.norm(adversarial_packet)
    
    reconstructed_adv = validator["aligner"].reconstruct(adversarial_packet)
    reprojected_adv = validator["aligner"].project(reconstructed_adv)
    pre_adv = np.linalg.norm(adversarial_packet - reprojected_adv)
    
    print(f"\n  * Validazione pacchetto avversario (Fuori Distribuzione) da {validator['name']}:")
    print(f"    - Errore di ricostruzione (PRE): {pre_adv:.4f}")
    if pre_adv <= immunology_threshold:
        print("    - [ACCETTATO] Il concetto si integra armonicamente nella matrice cognitiva locale.")
    else:
        print("    - [RIFIUTATO] Rilevata anomalia semantica! Pacchetto messo in quarantena.")
    assert pre_adv > immunology_threshold, "L'attacco avversario OOD avrebbe dovuto essere rifiutato!"

    print("\n======================================================================")
    print("SIMULAZIONE COMPLETATA CON SUCCESSO! TUTTE LE ASSERZIONI SUPERATE.")
    print("======================================================================")

if __name__ == "__main__":
    main()
