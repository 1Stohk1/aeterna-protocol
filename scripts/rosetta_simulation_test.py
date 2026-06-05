import sys
import os
import time
import numpy as np

# Adjust path to import core modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.rosetta import RosettaAligner, SemanticRouter, NeuroplasticNode
from core.memory import EpisodicMemory, DialogueTurn
from core.vector_store import SemanticMemory
from core.knowledge_sharing import build_expert_share_message, verify_expert_share_message
from core.llm_client import OllamaClient

def main():
    print("======================================================================")
    print("AETERNA PROTOCOL - NEUROPLASTIC NODE & MEMORY SIMULATION")
    print("======================================================================")
    
    np.random.seed(42)
    
    # 1. DETECT LOCAL OLLAMA INSTANCE
    print("\n[0] Rilevamento Backend LLM Locale...")
    ollama_client = None
    use_real_embeddings = False
    candidate_models = ["nomic-embed-text", "llama3.2", "llama3", "gemma2"]
    
    for model_name in candidate_models:
        client = OllamaClient(model=model_name)
        if client.is_healthy() and client.is_model_available():
            ollama_client = client
            use_real_embeddings = True
            print(f"    - [OK] Ollama attivo rilevato con modello: '{model_name}'")
            break
            
    if not use_real_embeddings:
        print("    - [INFO] Ollama locale non rilevato o nessun modello disponibile. Esecuzione in MODALITA' SIMULATA (Mock).")
    
    # Setup dimension parameters
    D_shared = 64      # Omega space dimension
    D_intrinsic = 20   # Intrinsic dimension of the semantic manifold
    num_anchors = 100  # Calibration anchor set size
    
    print(f"\n[1] Inizializzazione dello Spazio di Ancoraggio Omega (Dimensioni: {D_shared}, Intrinseca: {D_intrinsic})")
    
    # Generate orthogonal projection basis for intrinsic subspace mapping
    projection_basis = np.random.randn(D_intrinsic, D_shared)
    q_proj, _ = np.linalg.qr(projection_basis.T)
    projection_matrix = q_proj.T # D_intrinsic x D_shared orthogonal rows

    # 2. GENERATE CALIBRATION ANCHORS (REAL OR MOCK)
    if use_real_embeddings:
        # Define 100 actual semantic concepts
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
            concepts.append(f"concetto generale scientifico numero {len(concepts)}")
            
        print(f"    - Estrazione di {num_anchors} embedding reali da Ollama...")
        local_anchors = ollama_client.get_embeddings(concepts)
        d_local = local_anchors.shape[1]
        
        # Project local anchors into shared space to build Omega anchors lying in D_intrinsic subspace
        # We perform SVD to isolate the 20D intrinsic representation
        U, S, Vt = np.linalg.svd(local_anchors, full_matrices=False)
        latent_anchors = U[:, :D_intrinsic]
        
        Omega_anchors = np.dot(latent_anchors, projection_matrix)
        Omega_anchors /= np.linalg.norm(Omega_anchors, axis=1, keepdims=True)
        
        # Fit a distortion matrix mapping Omega back to local space for sprout simulations
        true_transform, _, _, _ = np.linalg.lstsq(Omega_anchors, local_anchors, rcond=None)
    else:
        # Standard mock data generation
        d_local = 256
        latent_anchors = np.random.randn(num_anchors, D_intrinsic)
        
        Omega_anchors = np.dot(latent_anchors, projection_matrix)
        Omega_anchors /= np.linalg.norm(Omega_anchors, axis=1, keepdims=True)
        
        true_transform = np.random.randn(D_shared, d_local)
        true_transform /= np.linalg.norm(true_transform, axis=0)
        
        local_noise = np.random.normal(0, 0.05, (num_anchors, d_local))
        local_anchors = np.dot(Omega_anchors, true_transform) + local_noise

    # 3. INSTANTIATE NEUROPLASTIC NODE
    print(f"\n[2] Creazione e calibrazione del nodo neuroplastico 'Guardiano-B' (d={d_local})...")
    node = NeuroplasticNode(
        name="Guardiano-B", 
        shared_dim=D_shared, 
        local_dim=d_local, 
        true_transform=true_transform, 
        projection_basis=projection_matrix
    )
    
    init_rmse = node.initialize_calibration(local_anchors, Omega_anchors)
    print(f"    - Calibrazione iniziale completata. RMSE: {init_rmse:.4f}")
    
    # 4. CONFIGURE INITIAL EXPERTS
    print("\n[3] Configurazione delle categorie semantiche iniziali (Esperti)...")
    if use_real_embeddings:
        # Centroids generated from actual text concepts
        oncology_centroid = node.aligner.project(ollama_client.get_embedding("oncologia medica e cura dei tumori"))
        oncology_centroid /= np.linalg.norm(oncology_centroid)
        
        folding_centroid = node.aligner.project(ollama_client.get_embedding("struttura di protein folding e biologia molecolare"))
        folding_centroid /= np.linalg.norm(folding_centroid)
    else:
        latent_oncology = np.random.randn(1, D_intrinsic)
        oncology_centroid = np.dot(latent_oncology, projection_matrix)
        oncology_centroid /= np.linalg.norm(oncology_centroid)
        
        latent_folding = np.random.randn(1, D_intrinsic)
        folding_centroid = np.dot(latent_folding, projection_matrix)
        folding_centroid /= np.linalg.norm(folding_centroid)
        
    node.router.add_expert("Oncologia", oncology_centroid)
    print("    - Aggiunto esperto: 'Oncologia'")
    node.router.add_expert("HP-Folding", folding_centroid)
    print("    - Aggiunto esperto: 'HP-Folding'")

    # 5. TEST CASE 1: SEMANTIC ROUTING OF KNOWN CONCEPTS
    print("\n[4] TEST CASE 1: Routing Semantico di un concetto noto (Oncologia)...")
    if use_real_embeddings:
        local_input_onco = ollama_client.get_embedding("terapie oncologiche sperimentali")
        input_oncology = node.aligner.project(local_input_onco)
        input_oncology /= np.linalg.norm(input_oncology)
    else:
        input_oncology = oncology_centroid + np.random.normal(0, 0.05, (1, D_shared))
        input_oncology /= np.linalg.norm(input_oncology)
        
    status, result, pre, metric = node.process_input(input_oncology)
    
    print(f"    - Stato elaborazione: {status}")
    print(f"    - Risultato routing: {result}")
    print(f"    - Errore di ricostruzione (PRE): {pre:.4f}")
    print(f"    - Similarita Cosenuale con l'esperto: {metric * 100:.2f}%")
    
    assert status == "ROUTE_SUCCESS", "Il routing avrebbe dovuto avere successo!"
    assert result == "Oncologia", "Il concetto avrebbe dovuto essere indirizzato a 'Oncologia'!"
    assert pre <= node.pre_threshold, "L'errore PRE avrebbe dovuto essere inferiore alla soglia!"
    print("    - [PASS] Concetto noto instradato correttamente.")

    # 6. TEST CASE 2: NOVEL CONCEPT AND DYNAMIC SPROUTING (LEARNING)
    print("\n[5] TEST CASE 2: Ricezione di un concetto valido ma ignoto (Fisica del Clima)...")
    if use_real_embeddings:
        local_climate = ollama_client.get_embedding("fisica del clima e riscaldamento globale dell'atmosfera")
        climate_concept = node.aligner.project(local_climate)
        climate_concept /= np.linalg.norm(climate_concept)
    else:
        proj_space_cents = np.vstack([oncology_centroid, folding_centroid])
        latent_climate = np.random.randn(1, D_intrinsic)
        climate_concept = np.dot(latent_climate, projection_matrix)
        for cent in proj_space_cents:
            climate_concept -= np.dot(climate_concept, cent.T) * cent
        climate_concept /= np.linalg.norm(climate_concept)
        
    pre_threshold_before = node.pre_threshold
    subspace_threshold_before = node.subspace_threshold

    print("    - Invio del nuovo concetto semantico al nodo...")
    status, result, pre, metric = node.process_input(climate_concept)
    
    print(f"    - Primo tentativo:")
    print(f"      - Stato: {status}")
    print(f"      - Risultato: {result}")
    print(f"      - Errore PRE: {pre:.4f}")
    print(f"      - Errore Sottospazio/Metric: {metric:.4f}")
    
    assert status == "SPROUTED", "Il concetto avrebbe dovuto innescare la germogliazione (Sprouting)!"
    assert result == "Expert_3", "Dovrebbe essere stato creato l'esperto 'Expert_3'!"
    print("    - [SPROUT] Rilevata novita semantica valida. Creato 'Expert_3' e avviata ricalibrazione locale.")
    
    print("    - Re-invio dello stesso concetto dopo la germogliazione e ricalibrazione...")
    status_2, result_2, pre_2, metric_2 = node.process_input(climate_concept)
    
    print(f"    - Secondo tentativo:")
    print(f"      - Stato: {status_2}")
    print(f"      - Risultato routing: {result_2}")
    print(f"      - Nuovo Errore PRE: {pre_2:.4f}")
    print(f"      - Similarita Cosenuale con il nuovo esperto: {metric_2 * 100:.2f}%")
    
    assert status_2 == "ROUTE_SUCCESS", "Dopo la ricalibrazione, il routing avrebbe dovuto avere successo!"
    assert result_2 == "Expert_3", "Il concetto deve essere instradato a 'Expert_3'!"
    assert pre_2 <= node.pre_threshold, "Dopo la calibrazione, il PRE deve rientrare nella soglia di conformita!"
    assert node.pre_threshold == pre_threshold_before, "La soglia PRE non deve cambiare durante lo sprouting!"
    assert node.subspace_threshold == subspace_threshold_before, "La soglia di sottospazio non deve cambiare durante lo sprouting!"
    print("    - [PASS] Apprendimento completato con successo (soglie immutate come previsto).")

    # 7. TEST CASE 3: ADVERSARIAL SPAM SCREENING
    print("\n[6] TEST CASE 3: Tentativo di iniezione di spam casuale (Payload estraneo)...")
    spam_vector = np.random.randn(1, D_shared)
    spam_vector /= np.linalg.norm(spam_vector)
    
    status_s, result_s, pre_s, metric_s = node.process_input(spam_vector)
    
    print(f"    - Stato elaborazione: {status_s}")
    print(f"    - Risultato: {result_s}")
    print(f"    - Errore PRE: {pre_s:.4f}")
    print(f"    - Errore Sottospazio: {metric_s:.4f}")
    
    assert status_s == "REJECTED_SPAM", "Lo spam avrebbe dovuto essere rifiutato!"
    assert result_s == "quarantine", "Lo spam deve essere inviato in quarantena!"
    print("    - [PASS] Lo spam e' stato identificato come anomalia semantica ed e' stato isolato.")

    # 8. TEST CASE 4: SHORT-TERM EPISODIC MEMORY & SLIDING WINDOW
    print("\n[7] TEST CASE 4: Memoria Episodica a Finestra Mobile (Sliding Window)...")
    episodic_mem = EpisodicMemory(max_age_days=30.0)
    
    now = time.time()
    t_old = now - (40 * 86400)  # 40 days ago (expired)
    t_recent = now - (10 * 86400) # 10 days ago (active)
    
    dummy_vector = np.zeros(D_shared)
    
    episodic_mem.add_turn("user", "Messaggio scaduto di prova", dummy_vector, timestamp=t_old)
    episodic_mem.add_turn("guardian", "Risposta recente di prova", dummy_vector, timestamp=t_recent)
    episodic_mem.add_turn("user", "Messaggio corrente", dummy_vector, timestamp=now)
    
    print(f"    - Messaggi in memoria prima del pruning: {len(episodic_mem.get_active_turns())}")
    assert len(episodic_mem.get_active_turns()) == 3, "Dovrebbero esserci 3 messaggi."
    
    episodic_mem.prune_expired(current_time=now)
    
    print(f"    - Messaggi in memoria dopo il pruning (finestra 30 giorni): {len(episodic_mem.get_active_turns())}")
    assert len(episodic_mem.get_active_turns()) == 2, "Il messaggio vecchio di 40 giorni dovrebbe essere stato eliminato."
    
    speakers = [t.speaker for t in episodic_mem.get_active_turns()]
    assert "guardian" in speakers and "user" in speakers, "I messaggi rimanenti dovrebbero essere quelli validi."
    print("    - [PASS] La memoria episodica a finestra mobile funziona correttamente.")

    # 9. TEST CASE 5: MEMORY CONSOLIDATION AND SEMANTIC VECTOR SEARCH
    print("\n[8] TEST CASE 5: Consolidamento e Ricerca Vettoriale Semantica...")
    conv_mem = EpisodicMemory(max_age_days=30.0)
    
    text_onco = "L'efficacia del trattamento oncologico e' stata provata in vitro."
    text_fold = "La simulazione di protein folding HP ha raggiunto i parametri desiderati."
    
    if use_real_embeddings:
        # Use real embeddings for dialog consolidation
        onco_emb = node.aligner.project(ollama_client.get_embedding(text_onco))
        fold_emb = node.aligner.project(ollama_client.get_embedding(text_fold))
    else:
        onco_emb = oncology_centroid
        fold_emb = folding_centroid
        
    conv_mem.add_turn("user", text_onco, onco_emb)
    conv_mem.add_turn("user", text_fold, fold_emb)
    
    semantic_store = SemanticMemory(shared_dim=D_shared)
    semantic_store.consolidate_from_episodic(conv_mem)
    
    print("    - Esecuzione sedimentazione delle soglie immunitarie dopo il consolidamento...")
    pre_threshold_before_sed = node.pre_threshold
    node.sediment_thresholds()
    print(f"      - Soglia PRE prima: {pre_threshold_before_sed:.4f} -> dopo: {node.pre_threshold:.4f}")
    
    print(f"    - Memorie consolidate nello store semantico a lungo termine: {len(semantic_store.metadata)}")
    assert len(semantic_store.metadata) == 2, "Dovrebbero esserci 2 memorie nello store semantico."
    
    # Search with Oncology query
    if use_real_embeddings:
        query_onco = node.aligner.project(ollama_client.get_embedding("tumore e oncologia medica"))
    else:
        query_onco = oncology_centroid + np.random.normal(0, 0.05, (1, D_shared))
    query_onco /= np.linalg.norm(query_onco)
    
    results_onco = semantic_store.search(query_onco, top_k=1)
    print(f"    - Ricerca per query 'Oncologia':")
    print(f"      - Trovato: '{results_onco[0][0]}'")
    print(f"      - Similarita': {results_onco[0][1]*100:.2f}%")
    
    assert results_onco[0][0] == text_onco, "La ricerca semantica avrebbe dovuto trovare il testo oncologico!"
    min_sim = 0.45 if use_real_embeddings else 0.80
    assert results_onco[0][1] >= min_sim, f"La similarita' ({results_onco[0][1]}) dovrebbe essere elevata."
    
    # Search with Folding query
    if use_real_embeddings:
        query_fold = node.aligner.project(ollama_client.get_embedding("struttura delle proteine tridimensionali"))
    else:
        query_fold = folding_centroid + np.random.normal(0, 0.05, (1, D_shared))
    query_fold /= np.linalg.norm(query_fold)
    
    results_fold = semantic_store.search(query_fold, top_k=1)
    print(f"    - Ricerca per query 'HP-Folding':")
    print(f"      - Trovato: '{results_fold[0][0]}'")
    print(f"      - Similarita': {results_fold[0][1]*100:.2f}%")
    
    assert results_fold[0][0] == text_fold, "La ricerca semantica avrebbe dovuto trovare il testo sul folding!"
    assert results_fold[0][1] >= min_sim, f"La similarita' ({results_fold[0][1]}) dovrebbe essere elevata."
    
    print("    - [PASS] Consolidamento e ricerca vettoriale semantica completati con successo.")

    # 10. TEST CASE 6: MULTI-NODE P2P KNOWLEDGE SHARING & ASSIMILATION
    print("\n[9] TEST CASE 6: Multi-Node P2P Knowledge Sharing & Assimilazione...")
    
    class SimpleFakeSantuarioClient:
        def get_public_key(self) -> bytes:
            return b"fake-p2p-public-key"
        def sign(self, payload_hash: bytes) -> bytes:
            return payload_hash[::-1] + self.get_public_key()
        def verify(self, payload_hash: bytes, signature: bytes, public_key: bytes) -> bool:
            return signature == payload_hash[::-1] + public_key
            
    fake_santuario = SimpleFakeSantuarioClient()
    
    # Create Node C with a different local dimensionality
    if use_real_embeddings:
        # For simulation, we can simulate an asymmetric local representation mapping for Node C
        # e.g., Node C is running a model with dimension d_c = 384 (like another embed model)
        d_local_c = 384
        true_transform_c = np.random.randn(D_shared, d_local_c)
        true_transform_c /= np.linalg.norm(true_transform_c, axis=0)
        
        # Node C's anchors
        local_noise_c = np.random.normal(0, 0.05, (num_anchors, d_local_c))
        local_anchors_c = np.dot(Omega_anchors, true_transform_c) + local_noise_c
    else:
        d_local_c = 128
        true_transform_c = np.random.randn(D_shared, d_local_c)
        true_transform_c /= np.linalg.norm(true_transform_c, axis=0)
        
        local_noise_c = np.random.normal(0, 0.05, (num_anchors, d_local_c))
        local_anchors_c = np.dot(Omega_anchors, true_transform_c) + local_noise_c
    
    node_c = NeuroplasticNode(
        name="Guardiano-C",
        shared_dim=D_shared,
        local_dim=d_local_c,
        true_transform=true_transform_c,
        projection_basis=projection_matrix
    )
    
    node_c.initialize_calibration(local_anchors_c, Omega_anchors)
    
    node_c.router.add_expert("Oncologia", oncology_centroid)
    node_c.router.add_expert("HP-Folding", folding_centroid)
    
    print("    - Verifica routing del concetto 'Fisica del Clima' su Guardiano-C PRIMA dell'assimilazione...")
    status_c1, result_c1, pre_c1, metric_c1 = node_c.process_input(climate_concept)
    
    print(f"      - Stato elaborazione iniziale su Guardiano-C: {status_c1}")
    print(f"      - Errore PRE iniziale: {pre_c1:.4f}")
    assert status_c1 == "SPROUTED", "Il nodo C dovrebbe rilevare novita' perche' non ha l'esperto ed e' fuori allineamento."
    
    print("    - Impacchettamento e firma crittografica del concetto 'Expert_3' da parte di Guardiano-B...")
    expert_3_centroid = node.router.experts["Expert_3"]
    
    msg = build_expert_share_message(
        expert_id="Expert_3",
        centroid_omega=expert_3_centroid,
        node_id=node.name,
        santuario_client=fake_santuario
    )
    
    print("    - Ricezione e verifica crittografica del messaggio su Guardiano-C...")
    valid, reason = verify_expert_share_message(msg, fake_santuario)
    assert valid, f"La verifica crittografica del messaggio di condivisione e' fallita: {reason}"
    print("      - Messaggio di condivisione verificato con successo!")
    
    print("    - Assimilazione di 'Expert_3' ed esecuzione ricalibrazione locale su Guardiano-C...")
    centroid_omega_recvd = np.array(msg["payload"]["centroid"])
    node_c.assimilate_expert(msg["payload"]["expert_id"], centroid_omega_recvd)
    
    print("    - Verifica routing del concetto 'Fisica del Clima' su Guardiano-C DOPO l'assimilazione...")
    status_c2, result_c2, pre_c2, metric_c2 = node_c.process_input(climate_concept)
    
    print(f"      - Nuovo Stato elaborazione su Guardiano-C: {status_c2}")
    print(f"      - Nuovo Risultato routing: {result_c2}")
    print(f"      - Nuovo Errore PRE: {pre_c2:.4f}")
    print(f"      - Similarita' Cosenuale con l'esperto assimilato: {metric_c2 * 100:.2f}%")
    
    assert status_c2 == "ROUTE_SUCCESS", "Dopo l'assimilazione, il routing avrebbe dovuto avere successo!"
    assert result_c2 == "Expert_3", "Dovrebbe essere instradato a 'Expert_3'!"
    assert pre_c2 <= node_c.pre_threshold, "L'errore PRE deve rientrare nella soglia tollerata dopo la calibrazione!"
    print("    - [PASS] Guardiano-C ha assimilato e allineato correttamente la conoscenza condivisa in modo asimmetrico!")

    print("\n======================================================================")
    print("SIMULAZIONE NEUROPLASTICA & MEMORIA & P2P COMPLETATA CON SUCCESSO!")
    print("======================================================================")

if __name__ == "__main__":
    main()
