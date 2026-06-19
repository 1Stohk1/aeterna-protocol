# AETERNA: Modello di Astrazione e Architettura di Rete

Questo documento definisce il modello astratto e l'organizzazione dei moduli del protocollo **AETERNA** (v1.0.0 "Sovereign"). L'infrastruttura è concepita per orchestrare calcolo scientifico distribuito utile ad alte prestazioni, tutelando la sovranità delle chiavi crittografiche degli operatori e garantendo la coerenza dello stato distribuito tramite una blockchain a gas zero ancorata periodicamente su Bitcoin L1.

---

## 1. Mappa dei Livelli Architetturali

L'architettura del circuito di AETERNA si sviluppa su quattro livelli logici e tecnologici integrati in modo asincrono:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Livello 4: Osservabilità e Controllo                 │
│      React HUD (WebGL) ──[ gRPC / REST API ]── Oculus server.py        │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼─────────────────────────────────────┐
│                    Livello 3: Orchestrazione e P2P                     │
│      Python Sentinel (gossip.py) ◄──► Pietra di Rosetta (rosetta.py)   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼─────────────────────────────────────┐
│                    Livello 2: Kernel Sicuro (Santuario)                │
│     Santuario Signer (main.rs) ──► gVisor runsc (gvisor.rs)            │
│     BIP-39 Vault (Shamir GF(256)) ──► PQC Handshake (p2p_handshake.rs)  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
┌──────────────────────────────────▼─────────────────────────────────────┐
│                   Livello 1: Consenso Sovrano e L1                     │
│      AppChain (CometBFT) ──[ OP_RETURN ]──► Bitcoin Layer 1            │
└────────────────────────────────────────────────────────────────────────┘
```

| Layer / Directory | Tecnologie | Ruolo e Funzione | Riferimenti Principali |
| :--- | :--- | :--- | :--- |
| **`chain/`** | Go (Cosmos SDK v0.50), CometBFT | AppChain sovrana a gas zero. Mantiene il registro delle identità (SBT), verifica le prove zk-SNARK on-chain e scrive i checkpoint su Bitcoin L1. | [x/guardian keeper](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/chain/x/guardian/keeper/keeper.go)<br>[x/anchor msg_server](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/chain/x/anchor/keeper/msg_server.go) |
| **`santuario/`** | Rust (Secure Kernel) | Kernel di sicurezza a basso livello. Esegue cifratura post-quantum, isolamento dei workload, firma transazioni e sblocco via Shamir's Secret Sharing. | [santuario-signer](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/santuario/signer/src/main.rs)<br>[p2p_handshake.rs](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/santuario/ratchet/src/p2p_handshake.rs) |
| **`core/`** | Python | Orchestratore in userland (**Sentinel**). Gestisce il network gossip UDP, il caricamento dei compiti scientifici, e l'allineamento semantico della Pietra di Rosetta. | [sentinel.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/core/sentinel.py)<br>[rosetta.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/core/rosetta.py) |
| **`scientific/`** | Julia | Motore computazionale scientifico (*Missione Alpha*). Esegue simulazioni di crescita tumorale Gompertz (SDE), allineamento ed entropia genomica, e ripiegamento proteico HP. | [oncology_sim.jl](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/scientific/oncology_sim.jl) |
| **`operations/`** | React, WebGL, Python | Oculus Observer HUD. Consente il monitoraggio 3D dei nodi, dei centroidi di conoscenza, dello stato dei container gVisor e degli ancoraggi Bitcoin. | [server.py (Oculus API)](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/operations/war_room_web/server.py)<br>[App.tsx (React)](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/operations/war_room_web/frontend/src/App.tsx) |

---

## 2. Pipeline di Consenso Stratificata

AETERNA non si basa su un singolo algoritmo di consenso energivoro, bensì su una pipeline logica suddivisa in quattro fasi distinte:

1. **Level 0 (Admission — Proof of Sybil-Resistance)**: I nodi validatori (**Guardians**) si registrano on-chain tramite Soulbound Token (SBT) sul modulo [x/guardian](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/chain/x/guardian/) legando la propria chiave pubblica Dilithium-5 a uno stake collaterale.
2. **Level 1 (Execution — Proof of Useful Work)**: I nodi estraggono i compiti di calcolo scientifico (task) dalla gossip network UDP ed eseguono le elaborazioni in Julia.
3. **Level 2 (Validation — Proof of Cognition)**: Per evitare che l'intera rete debba ricalcolare il workload Julia per verificarlo, il Sentinel genera una prova a conoscenza zero **zk-SNARK** (Groth16 su curve BN254) di esattamente **128 byte**. Il circuito aritmetico ([circuits.rs](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/santuario/zk/src/circuits.rs)) vincola:
   * Il corretto rapporto delle basi azotate G+C calcolato sul frammento mutato.
   * La distanza di Hamming tra la sequenza di riferimento e quella mutata.
   * Il commitment crittografico polinomiale (Rabin Rolling Fingerprint con base $\beta = 31$).
   * Il binding anti-replay tra `task_id` e `manifest_hash`.
4. **Level 3 (Persistence — Proof of Integrity)**: I dati risultanti del calcolo scientifico sono caricati su IPFS. Il CID IPFS viene incluso on-chain nella transazione Cosmos SDK sottomessa al modulo [x/oracle](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/chain/x/oracle/keeper/msg_server.go) firmata in **Dilithium-5**.

---

## 3. Allineamento Spaziale e Neuroplasticità: La Pietra di Rosetta

La **Pietra di Rosetta** ([rosetta.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/core/rosetta.py)) definisce il modello di allineamento e instradamento semantico dei nodi asimmetrici:

```
┌──────────────────────────────────────┐          ┌──────────────────────────────────────┐
│  Nodo Validatore A (nomic-embed)     │          │    Nodo Validatore B (llama3.2)      │
│  Dimensione Spazio Locale: 768-dim   │          │  Dimensione Spazio Locale: 2048-dim  │
└──────────────────┬───────────────────┘          └──────────────────┬───────────────────┘
                   │                                                 │
                   │ (Proiezione)                                    │ (Proiezione)
                   ▼                                                 ▼
        ┌────────────────────────────────────────────────────────────────────────┐
        │                 Spazio Coordinato Condiviso (Ω)                        │
        │                       Dimensione: 64-dim                               │
        └──────────────────────────────────┬─────────────────────────────────────┘
                                           │
                                           ▼
                                 [ Semantic Router ]
                        (Calcolo Similitudine del Coseno)
                                ↙          ↓          ↘
                       [Centroid_1]   [Centroid_2]   [Anomaly (PRE)]
                       (Oncologia)    (HP-Folding)        │
                                                          ▼
                                                   [ Sprout Event ]
                                           (Creazione di un nuovo esperto)
```

1. **Allineatore Relazionale**: Consente a nodi che eseguono modelli di embedding locali differenti (es. 768 dimensioni vs 2048 dimensioni) di comunicare significati proiettando i vettori locali in uno spazio comune condiviso $\Omega$ a 64 dimensioni.
2. **Projection Reconstruction Error (PRE)**: Un autoencoder locale tenta di ricostruire il vettore originario dallo spazio condiviso. Se il PRE supera una determinata soglia immunitaria, il concetto viene classificato come anomalo (nuovo ambito di scibile non ancora catalogato).
3. **Sprouting & Assimilazione P2P**: L'anomalia innesca un evento di *Sprout*: viene definito un nuovo centroide di competenza semantica (`Expert`). La coordinata del nuovo centroide viene firmata digitalmente e propagata via gossip. I nodi riceventi assimilano il centroide ricalibrando le proprie matrici di proiezione locali per riconoscere immediatamente il nuovo concetto.

---

## 4. Nucleo di Sicurezza Crittografica (Santuario)

Il modulo **Santuario** ([santuario/](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/santuario/)) protegge l'integrità del nodo operatore a riposo, in transito ed in esecuzione:

### 4.1 Shamir's Secret Sharing (SSS) Vault
La chiave master BIP-39 del validatore non risiede mai in chiaro su memoria persistente. All'avvio, l'operatore deve sbloccare il vault inserendo un quorum minimo di quote $K$ su $N$ totali.
L'aritmetica di campo in GF(256) è implementata in tempo costante su tabelle pre-calcolate `EXP`/`LOG` basate sul polinomio irriducibile AES:
```math
P(x) = x^8 + x^4 + x^3 + x + 1
```
La ricostruzione del segreto avviene byte-per-byte tramite interpolazione polinomiale lagrangiana a $x = 0$:
```math
S = f(0) = \sum_{i=1}^{K} y_i \prod_{j \neq i} \frac{x_j}{x_j \oplus x_i} \pmod{P(x)}
```
Una volta ricostruita, la chiave master in memoria decifra l'envelope crittografico protetto da AES-256-GCM caricando in RAM le chiavi di sessione.

### 4.2 Hardening Post-Quantum (PQC)
* **Firme Digitali**: I Soulbound Token on-chain e i blocchi inviati all'oracolo sono firmati digitalmente in **Dilithium-5** (NIST Level 5).
* **Canale Ratchet Signer-Operator**: Le chiamate di controllo amministrative sono cifrate con un canale ratchet simmetrico basato su schema ibrido **X3DH-lite** (ECDH X25519 accoppiato a incapsulamento Kyber-1024).
* **Gossip Handshake P2P**: L'handshake tra nodi gossip Sentinel per la determinazione della chiave di cifratura UDP della mesh è basato su protocollo 1-RTT ibrido (X25519 + Kyber-1024), che protegge le intercettazioni della gossip network da futuri attacchi di calcolo quantistico (Store Now, Decrypt Later).

### 4.3 Isolamento Workload (gVisor)
I calcoli Julia, importando librerie ed elaborando dati estranei potenzialmente malevoli, sono avviati all'interno di una sandbox user-space **gVisor** (runner `runsc`, [gvisor.rs](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/santuario/isolation/src/gvisor.rs)) per isolare le chiamate di sistema (syscall) ed impedire escape verso l'host.
Su piattaforme di sviluppo che non supportano la virtualizzazione user-space (es. Windows locale), il signer esegue un fallback dinamico host-space: avvia il processo, traccia il PID del sistema operativo ed esegue una terminazione forzata e pulita del processo figlio (`taskkill /F /PID` o `SIGKILL`) al completamento del blocco o ad ogni firma di transazione per evitare perdite di memoria o processi orfani.

---

## 5. Ancoraggio Bitcoin Layer 1 (x/anchor)

Per immunizzare lo stato della AppChain distribuita da attacchi a lungo termine di riscrittura della storia (51% attack o riorganizzazioni della catena Cosmos), i validatori eseguono checkpoint periodici su Bitcoin L1.
Il modulo [x/anchor](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/chain/x/anchor/keeper/keeper.go) raccoglie lo stato del consenso Cosmos, lo firma con Dilithium-5 e lo inserisce all'interno di una transazione Bitcoin standard, immettendo fino a 80 byte di metadati immutabili tramite l'istruzione **`OP_RETURN`**:

```math
\text{Payload} = \text{MagicBytes}(4) \mathbin{\Vert} \text{CosmosHeight}(8) \mathbin{\Vert} \text{CosmosStateHash}(32) \mathbin{\Vert} \text{EntropySignature}(36)
```

Una volta che la transazione viene inclusa in un blocco Bitcoin L1 e protetta da un'adeguata barriera di Proof-of-Work, lo stato di AETERNA assume la medesima immutabilità termodinamica della rete Bitcoin.
