import sys
import os
import numpy as np

# Adjust path to import core.rosetta
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.rosetta import RosettaAligner, SemanticRouter, NeuroplasticNode

def main():
    print("======================================================================")
    print("AETERNA PROTOCOL - NEUROPLASTIC NODE SIMULATION (ROUTING & SPROUTING)")
    print("======================================================================")
    
    np.random.seed(42)
    
    # 1. SETUP THE SHARED SPACE AND SUBSPACE ANCHORS
    D_shared = 64      # Omega space dimension
    D_intrinsic = 20   # Intrinsic dimension of the semantic manifold
    num_anchors = 100  # Calibration anchor set size
    
    print(f"\n[1] Inizializzazione dello Spazio di Ancoraggio Omega (Dimensioni: {D_shared}, Intrinseca: {D_intrinsic})")
    
    # Generate low-rank shared anchors using an orthogonal projection basis
    latent_anchors = np.random.randn(num_anchors, D_intrinsic)
    projection_basis = np.random.randn(D_intrinsic, D_shared)
    q_proj, _ = np.linalg.qr(projection_basis.T)
    projection_matrix = q_proj.T # D_intrinsic x D_shared orthogonal rows
    
    # Shared anchors lie entirely in the D_intrinsic subspace
    Omega_anchors = np.dot(latent_anchors, projection_matrix)
    Omega_anchors /= np.linalg.norm(Omega_anchors, axis=1, keepdims=True)
    
    # 2. INSTANTIATE NEUROPLASTIC NODE
    d_local = 256
    print(f"\n[2] Creazione e calibrazione del nodo neuroplastico 'Guardiano-B' (d={d_local})...")
    
    true_transform = np.random.randn(D_shared, d_local)
    true_transform /= np.linalg.norm(true_transform, axis=0)
    
    local_noise = np.random.normal(0, 0.05, (num_anchors, d_local))
    local_anchors = np.dot(Omega_anchors, true_transform) + local_noise
    
    # Create the neuroplastic node with our subspace basis
    node = NeuroplasticNode(
        name="Guardiano-B", 
        shared_dim=D_shared, 
        local_dim=d_local, 
        true_transform=true_transform, 
        projection_basis=projection_matrix
    )
    
    # Initialize calibration
    init_rmse = node.initialize_calibration(local_anchors, Omega_anchors)
    print(f"    - Calibrazione iniziale completata. RMSE: {init_rmse:.4f}")
    
    # 3. CONFIGURE INITIAL EXPERTS
    # We seed the node with two default semantic categories
    print("\n[3] Configurazione delle categorie semantiche iniziali (Esperti)...")
    
    # Expert 1: Oncology (Centered in a specific subspace direction)
    latent_oncology = np.random.randn(1, D_intrinsic)
    oncology_centroid = np.dot(latent_oncology, projection_matrix)
    oncology_centroid /= np.linalg.norm(oncology_centroid)
    node.router.add_expert("Oncologia", oncology_centroid)
    print("    - Aggiunto esperto: 'Oncologia'")
    
    # Expert 2: Folding Math
    latent_folding = np.random.randn(1, D_intrinsic)
    folding_centroid = np.dot(latent_folding, projection_matrix)
    folding_centroid /= np.linalg.norm(folding_centroid)
    node.router.add_expert("HP-Folding", folding_centroid)
    print("    - Aggiunto esperto: 'HP-Folding'")

    # 4. TEST CASE 1: SEMANTIC ROUTING OF KNOWN CONCEPTS
    print("\n[4] TEST CASE 1: Routing Semantico di un concetto noto (Oncologia)...")
    
    # Generate an input concept close to the Oncology expert (adding small noise)
    input_oncology = oncology_centroid + np.random.normal(0, 0.05, (1, D_shared))
    input_oncology /= np.linalg.norm(input_oncology)
    
    # Process input
    status, result, pre, metric = node.process_input(input_oncology, threshold=0.35)
    
    print(f"    - Stato elaborazione: {status}")
    print(f"    - Risultato routing: {result}")
    print(f"    - Errore di ricostruzione (PRE): {pre:.4f}")
    print(f"    - Similarita Cosenuale con l'esperto: {metric * 100:.2f}%")
    
    assert status == "ROUTE_SUCCESS", "Il routing avrebbe dovuto avere successo!"
    assert result == "Oncologia", "Il concetto avrebbe dovuto essere indirizzato a 'Oncologia'!"
    assert pre <= 0.35, "L'errore PRE avrebbe dovuto essere inferiore alla soglia!"
    print("    - [PASS] Concetto noto instradato correttamente.")

    # 5. TEST CASE 2: NOVEL CONCEPT AND DYNAMIC SPROUTING (LEARNING)
    print("\n[5] TEST CASE 2: Ricezione di un concetto valido ma ignoto (Fisica del Clima)...")
    
    # Generate a concept in the valid 20D subspace but far/orthogonal to Oncology/Folding
    # We construct a vector orthogonal to both centroids in the subspace
    proj_space_cents = np.vstack([oncology_centroid, folding_centroid])
    # Generate random vector in 20D subspace
    latent_climate = np.random.randn(1, D_intrinsic)
    climate_concept = np.dot(latent_climate, projection_matrix)
    # Project out components of Oncology and Folding
    for cent in proj_space_cents:
        climate_concept -= np.dot(climate_concept, cent.T) * cent
    climate_concept /= np.linalg.norm(climate_concept)
    
    print("    - Invio del nuovo concetto semantico al nodo...")
    
    # First attempt: Node has never calibrated for this direction
    status, result, pre, metric = node.process_input(climate_concept, threshold=0.35)
    
    print(f"    - Primo tentativo:")
    print(f"      - Stato: {status}")
    print(f"      - Risultato: {result}")
    print(f"      - Errore PRE: {pre:.4f}")
    print(f"      - Errore Sottospazio: {metric:.4f}")
    
    # The first attempt should trigger sprouting because PRE > 0.35 but subspace_err <= 0.15
    assert status == "SPROUTED", "Il concetto avrebbe dovuto innescare la germogliazione (Sprouting)!"
    assert result == "Expert_3", "Dovrebbe essere stato creato l'esperto 'Expert_3'!"
    print("    - [SPROUT] Rilevata novita semantica valida. Creato 'Expert_3' e avviata ricalibrazione locale.")
    
    # Second attempt: Send the SAME concept again. Now the node has sprouted the expert and recalibrated its W!
    print("    - Re-invio dello stesso concetto dopo la germogliazione e ricalibrazione...")
    status_2, result_2, pre_2, metric_2 = node.process_input(climate_concept, threshold=0.35)
    
    print(f"    - Secondo tentativo:")
    print(f"      - Stato: {status_2}")
    print(f"      - Risultato routing: {result_2}")
    print(f"      - Nuovo Errore PRE: {pre_2:.4f}")
    print(f"      - Similarita Cosenuale con il nuovo esperto: {metric_2 * 100:.2f}%")
    
    assert status_2 == "ROUTE_SUCCESS", "Dopo la ricalibrazione, il routing avrebbe dovuto avere successo!"
    assert result_2 == "Expert_3", "Il concetto deve essere instradato a 'Expert_3'!"
    assert pre_2 <= 0.35, "Dopo la calibrazione, il PRE deve rientrare nella soglia di conformita!"
    print("    - [PASS] Apprendimento completato con successo! Il nodo ora comprende e instrada il nuovo concetto.")

    # 6. TEST CASE 3: ADVERSARIAL SPAM SCREENING
    print("\n[6] TEST CASE 3: Tentativo di iniezione di spam casuale (Payload estraneo)...")
    
    # Completely random 64D noise, outside the 20D subspace
    spam_vector = np.random.randn(1, D_shared)
    spam_vector /= np.linalg.norm(spam_vector)
    
    status_s, result_s, pre_s, metric_s = node.process_input(spam_vector, threshold=0.35)
    
    print(f"    - Stato elaborazione: {status_s}")
    print(f"    - Risultato: {result_s}")
    print(f"    - Errore PRE: {pre_s:.4f}")
    print(f"    - Errore Sottospazio: {metric_s:.4f}")
    
    assert status_s == "REJECTED_SPAM", "Lo spam avrebbe dovuto essere rifiutato!"
    assert result_s == "quarantine", "Lo spam deve essere inviato in quarantena!"
    print("    - [PASS] Lo spam e' stato identificato come anomalia semantica ed e' stato isolato.")

    print("\n======================================================================")
    print("SIMULAZIONE NEUROPLASTICA COMPLETATA CON SUCCESSO! ASSERZIONI SUPERATE.")
    print("======================================================================")

if __name__ == "__main__":
    main()
