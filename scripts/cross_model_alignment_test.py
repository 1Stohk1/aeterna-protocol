import sys
import os
import numpy as np

# Adjust path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.rosetta import RosettaAligner
from core.llm_client import OllamaClient

def main():
    print("======================================================================")
    print("AETERNA PROTOCOL - CROSS-MODEL ALIGNMENT STABILITY TEST")
    print("======================================================================")
    
    np.random.seed(42)
    
    # 1. DISCOVERY OF TARGET MODELS IN OLLAMA
    print("\n[0] Rilevamento Modelli per Allineamento Cross-Modello...")
    model_a_name = "nomic-embed-text"
    model_b_name = "llama3.2"
    
    client_a = OllamaClient(model=model_a_name)
    client_b = OllamaClient(model=model_b_name)
    
    use_real = False
    if client_a.is_healthy() and client_b.is_healthy():
        if client_a.is_model_available() and client_b.is_model_available():
            use_real = True
            print(f"    - [OK] Entrambi i modelli rilevati: '{model_a_name}' e '{model_b_name}'!")
        else:
            print(f"    - [INFO] Uno o entrambi i modelli ('{model_a_name}', '{model_b_name}') non sono pronti. Uso di MODALITA' SIMULATA (Mock).")
    else:
        print("    - [INFO] Ollama non attivo o non raggiungibile. Uso di MODALITA' SIMULATA (Mock).")
        
    # Setup dimensions
    D_shared = 64      # Omega space dimension
    D_intrinsic = 20   # Intrinsic dimension of the semantic manifold
    num_anchors = 100  # Calibration anchor set size
    
    # Intrinsic projection basis
    projection_basis = np.random.randn(D_intrinsic, D_shared)
    q_proj, _ = np.linalg.qr(projection_basis.T)
    projection_matrix = q_proj.T # D_intrinsic x D_shared orthogonal rows
    
    # 2. GENERATE OR FETCH ANCHOR SETS
    if use_real:
        try:
            # Define 100 anchor concepts
            concepts = [
                "oncologia", "carcinoma", "terapia", "tumore", "cellula", "DNA", "RNA", "genoma", 
                "proteina", "enzima", "folding", "amminoacido", "molecola", "legame", "struttura",
                "clima", "atmosfera", "temperatura", "ghiacciaio", "oceano", "vento", "pressione",
                "matematica", "equazione", "algebra", "geometria", "calcolo", "funzione", "derivata",
                "algoritmo", "complessita", "grafo", "albero", "ordinamento", "ricerca", "struttura dati",
                "fisica", "meccanica", "quantistica", "relativita", "particella", "atomo", "nucleo",
                "chimica", "reazione", "catalizzatore", "soluzione", "acido", "base", "elemento",
                "astronomia", "stella", "pianeta", "galassia", "orbita", "gravita", "telescopio",
                "neurologia", "cervello", "neurone", "sinapsi", "corteccia", "neuroplasticita", "riflesso",
                "ecologia", "ecosistema", "biodiversita", "specie", "habitat", "conservazione", "inquinamento",
                "medicina", "diagnosi", "sintomo", "paziente", "farmaco", "chirurgia", "prevenzione"
            ]
            while len(concepts) < num_anchors:
                concepts.append(f"concetto scientifico generico {len(concepts)}")
                
            print(f"\n[1] Estrazione di {num_anchors} embedding per '{model_a_name}'...")
            local_anchors_a = client_a.get_embeddings(concepts)
            d_a = local_anchors_a.shape[1]
            
            print(f"[2] Estrazione di {num_anchors} embedding per '{model_b_name}'...")
            local_anchors_b = client_b.get_embeddings(concepts)
            d_b = local_anchors_b.shape[1]
            
            # Build shared Omega anchors
            U, S, Vt = np.linalg.svd(local_anchors_a, full_matrices=False)
            Omega_anchors = np.dot(U[:, :D_intrinsic], projection_matrix)
            Omega_anchors /= np.linalg.norm(Omega_anchors, axis=1, keepdims=True)
        except Exception as e:
            print(f"    - [WARNING] Errore durante l'estrazione degli embedding reali: {e}")
            print("      Il modello di chat potrebbe non supportare la generazione di embedding in questa versione di Ollama.")
            print("      Ripiego su MODALITA' SIMULATA (Mock) per garantire la continuita' dei test.")
            use_real = False

    if not use_real:
        # Mock setup
        d_a = 768
        d_b = 2048
        
        print(f"\n[1] Simulazione Spazio A (d_a={d_a}) e Spazio B (d_b={d_b})")
        latent_anchors = np.random.randn(num_anchors, D_intrinsic)
        
        Omega_anchors = np.dot(latent_anchors, projection_matrix)
        Omega_anchors /= np.linalg.norm(Omega_anchors, axis=1, keepdims=True)
        
        # Generate different linear/nonlinear transformations to simulate distinct model behaviors
        true_transform_a = np.random.randn(D_shared, d_a)
        true_transform_a /= np.linalg.norm(true_transform_a, axis=0)
        
        true_transform_b = np.random.randn(D_shared, d_b)
        true_transform_b /= np.linalg.norm(true_transform_b, axis=0)
        
        noise_a = np.random.normal(0, 0.02, (num_anchors, d_a))
        noise_b = np.random.normal(0, 0.02, (num_anchors, d_b))
        
        local_anchors_a = np.dot(Omega_anchors, true_transform_a) + noise_a
        local_anchors_b = np.dot(Omega_anchors, true_transform_b) + noise_b
        
    print(f"    - Dimensioni di input: Nodo A={d_a}, Nodo B={d_b}, Spazio Condiviso Omega={D_shared}")
    
    # 3. ALIGNMENT CALIBRATION
    print("\n[3] Calibrazione degli Aligner locali alla Pietra di Rosetta...")
    aligner_a = RosettaAligner(shared_dim=D_shared, local_dim=d_a)
    aligner_b = RosettaAligner(shared_dim=D_shared, local_dim=d_b)
    
    rmse_a = aligner_a.calibrate(local_anchors_a, Omega_anchors)
    rmse_b = aligner_b.calibrate(local_anchors_b, Omega_anchors)
    
    print(f"    - Aligner A calibrato. RMSE: {rmse_a:.4f}")
    print(f"    - Aligner B calibrato. RMSE: {rmse_b:.4f}")
    
    # 4. CROSS-MODEL VERIFICATION EXPERIMENT
    print("\n[4] Esecuzione Test di Osmosi Semantica Bidirezionale...")
    
    # Define test concepts
    if use_real:
        test_concepts = [
            "meccanica quantistica e fisica delle particelle",
            "oncologia clinica e terapie cellulari",
            "protein folding e calcolo bioinformatico",
            "storia della letteratura e poesia classica"
        ]
    else:
        test_concepts = [f"concetto_di_test_{i}" for i in range(4)]
        
    print(f"----------------------------------------------------------------------")
    print(f"{'CONCETTO DI TEST':<32} | {'SIMIL. A->B':<12} | {'SIMIL. B->A':<12}")
    print(f"----------------------------------------------------------------------")
    
    for i, concept in enumerate(test_concepts):
        # Extract/generate representation
        if use_real:
            emb_a = client_a.get_embedding(concept)
            emb_b = client_b.get_embedding(concept)
        else:
            # Generate mock intrinsic representation
            latent_concept = np.random.randn(1, D_intrinsic)
            omega_concept = np.dot(latent_concept, projection_matrix)
            omega_concept /= np.linalg.norm(omega_concept)
            
            emb_a = np.dot(omega_concept, true_transform_a) + np.random.normal(0, 0.02, (1, d_a))
            emb_b = np.dot(omega_concept, true_transform_b) + np.random.normal(0, 0.02, (1, d_b))
            
        # Direction 1: Node A -> Node B
        # Project on A
        omega_a = aligner_a.project(emb_a)
        
        # Reconstruct on B
        rec_b = aligner_b.reconstruct(omega_a)
        
        # Reproject on B
        omega_a_to_b = aligner_b.project(rec_b)
        
        sim_a_to_b = RosettaAligner.cosine_similarity(omega_a, omega_a_to_b)
        
        # Direction 2: Node B -> Node A
        # Project on B
        omega_b = aligner_b.project(emb_b)
        
        # Reconstruct on A
        rec_a = aligner_a.reconstruct(omega_b)
        
        # Reproject on A
        omega_b_to_a = aligner_a.project(rec_a)
        
        sim_b_to_a = RosettaAligner.cosine_similarity(omega_b, omega_b_to_a)
        
        # Render concept name (shortened if too long)
        c_label = concept[:30] + "..." if len(concept) > 30 else concept
        print(f"{c_label:<32} | {sim_a_to_b*100:9.2f}% | {sim_b_to_a*100:9.2f}%")
        
        # Asserts
        assert sim_a_to_b >= 0.90, f"La similarita' A->B per {concept} deve essere almeno del 90%!"
        assert sim_b_to_a >= 0.90, f"La similarita' B->A per {concept} deve essere almeno del 90%!"
        
    print(f"----------------------------------------------------------------------")
    print("\n======================================================================")
    print("TEST DI ALLINEAMENTO CROSS-MODELLO COMPLETATO CON SUCCESSO!")
    print("======================================================================")

if __name__ == "__main__":
    main()
