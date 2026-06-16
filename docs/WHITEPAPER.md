# AETERNA: Un'Infrastruttura Cibernetica Sovrana per la Simbiosi Uomo-AI

## Whitepaper Tecnico di Protocollo — Versione 1.0.0 "Sovereign"
**Autori: Christian Peluso, Claude e Gemini**  
**Giugno 2026**

---

### Abstract
AETERNA è un protocollo di calcolo distribuito accoppiato a una blockchain a gas zero (AppChain Cosmos SDK native) progettato per democratizzare l'accesso e l'esecuzione di calcolo scientifico ad alte prestazioni (specialmente in ambito oncologico decentralizzato), tutelando la privacy computazionale e la proprietà dei dati dei singoli nodi operatori (**Guardians**). 
Il protocollo si fonda su una pipeline di consenso stratificata a quattro livelli (Proof of Sybil-Resistance, Proof of Useful Work, Proof of Cognition tramite zk-SNARKs compressi e Proof of Integrity via IPFS), unita a un sistema di reputazione (Trust Score) calcolato on-chain a virgola fissa. La sicurezza crittografica e di comunicazione del sistema è blindata contro avversari dotati di capacità di calcolo quantistico mediante cifratura ibrida post-quantum (Dilithium-5 e Kyber-1024), sblocco del vault via Shamir's Secret Sharing in campo finito GF(256) e isolamento dei workload untrusted in container user-space gVisor. Lo stato finale della catena sovrana viene periodicamente ancorato sulla blockchain di Bitcoin (Layer 1) tramite transazioni `OP_RETURN`.

---

## 1. Visione e Fondamenti Assiomatici

L'architettura di AETERNA si sviluppa a partire da tre assiomi immutabili, costantemente verificati dai nodi del circuito:

1. **Sovranità Finale**: Ogni Guardian conserva l'esclusivo controllo fisico e logico sulle proprie chiavi crittografiche, sulle risorse di calcolo fornite e sui dati locali elaborati.
2. **Integrità Speculare**: La coerenza dello stato interno (le computazioni eseguite nel Santuario) deve corrispondere in modo deterministico e trasparente alla telemetria e alle transazioni registrate on-chain.
3. **Trasparenza Causale**: Qualsiasi decisione del protocollo — incluse le variazioni di reputazione o le sospensioni automatiche dei nodi — deve essere riconducibile a una causa matematica verificabile on-chain, escludendo arbitrio centralizzato.

---

## 2. Pipeline di Consenso Stratificata

AETERNA sostituisce i tradizionali meccanismi di consenso dispendiosi o puramente speculativi con una pipeline a quattro livelli, ciascuno deputato a risolvere una specifica classe di attacchi in un sistema distribuito.

```
┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐     ┌─────────────────────┐
│ Level 0: Admission  │ ──> │ Level 1: Execution  │ ──> │ Level 2: Validation │ ──> │ Level 3: Persistence│
│    SBT + Stake      │     │  PoUW (AI Compute)  │     │   PoC (zk-SNARK)    │     │      PoI (IPFS)     │
└─────────────────────┘     └─────────────────────┘     └─────────────────────┘     └─────────────────────┘
```

### 2.1 Level 0: Proof of Sybil-Resistance
L'ammissione al network richiede il possesso di un Soulbound Token (SBT) non trasferibile, registrato sul modulo [x/guardian](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/chain/x/guardian/) della AppChain. L'SBT lega in modo biunivoco l'identità post-quantum del validatore a una quota di stake collaterale depositata, neutralizzando gli attacchi Sybil a basso costo.

### 2.2 Level 1: Proof of Useful Work (PoUW)
I nodi validatori non sprecano cicli di clock calcolando hash casuali, bensì eseguono compiti computazionali utili (*Missione Alpha*) scritti in linguaggio Julia (sotto la directory [scientific/](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/scientific/)). I compiti comprendono:
- Simulazione di crescita tumorale stocastica (equazioni differenziali stocastiche basate sul modello Gompertz).
- Allineamento ed entropia genomica (analisi delle mutazioni driver-vs-passenger basata su distanza di Hamming).
- Ripiegamento proteico su reticoli 2D/3D (modello HP lattice).

### 2.3 Level 2: Proof of Cognition (PoC)
Per garantire che l'esecutore (prover) abbia svolto la computazione in modo corretto senza costringere l'intera rete a rieseguire il calcolo (verifier), il Sentinel genera una prova di conoscenza zero compressa **zk-SNARK** (Groth16 su curve BN254). 
Il circuito aritmetico, definito in [circuits.rs](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/santuario/zk/src/circuits.rs), vincola:
1. **GC-Content**: Il rapporto delle basi azotate G+C calcolato sul frammento mutato, normalizzato tramite un polinomio quadratico:
   ```math
   \text{GC}_{\text{pct}} = \frac{\sum b_i}{L}
   ```
2. **Hamming Distance**: Il numero di sostituzioni rispetto alla sequenza di riferimento, vincolato per inversione R1CS:
   ```math
   D_H(S_{\text{ref}}, S_{\text{mut}}) = \sum (S_{\text{ref}, i} \oplus S_{\text{mut}, i})
   ```
3. **Rabin Rolling Fingerprint**: Un commitment crittografico polinomiale ad alta efficienza ($\beta = 31$) sulla sequenza di input per prevenire la sottomissione di dati fittizi:
   ```math
   H(S) = \sum_{i=0}^{L-1} S_i \cdot \beta^{L-1-i} \pmod M
   ```
4. **Anti-Replay**: Il binding crittografico tra `task_id` e `manifest_hash` all'interno degli input pubblici della prova.

La prova risultante è compressa in esattamente **128 byte** per permetterne la sottomissione on-chain a bassissimo costo di footprint.

### 2.4 Level 3: Proof of Integrity (PoI)
I dati generati dalle computazioni scientifiche vengono pubblicati sulla rete decentralizzata IPFS. La transazione Cosmos SDK inviata all'oracolo contiene il CID IPFS (Content Identifier). I nodi persistono e pinnano i dati, dimostrando periodicamente la recuperabilità fisica del dato (retrievability) attraverso pings di integrità crittografica.

---

## 3. Calcolo del Trust Score On-Chain

La reputazione crittografica e operativa di ciascun Guardian è mantenuta a livello di consenso on-chain all'interno del modulo Cosmos [x/trustscore](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/chain/x/trustscore/). 
Per prevenire imprecisioni dovute all'aritmetica in virgola mobile non deterministica nei motori di consenso WebAssembly o Go, il Trust Score (TS) viene calcolato in **virgola fissa a precisione intera** con base $1.000.000$ ($10^6$ equivale a $1.00$).

Il Trust Score di un nodo al tempo $t$ è una funzione normalizzata che penalizza i fallimenti ed incentiva la sottomissione continuativa di prove zk-SNARK valide:

```math
TS_t = \max\left(0.10, \min\left(1.00, \frac{\text{Successi}}{\text{Successi} + \text{Fallimenti}} \cdot \left(1 - e^{-\lambda \cdot N_{\text{tasks}}}\right)\right)\right)
```

On-chain, la formula viene calcolata ed incrementata discretamente dal keeper del modulo:
```go
// chain/x/trustscore/keeper/keeper.go
newScore := (successfulTasks * 1_000_000) / totalTasks
```
Ogni sottomissione valida di una prova zk-SNARK da 128 byte tramite `MsgSubmitProof` eleva il punteggio, mentre sottomissioni duplicate (replay attack) o con dimensioni errate vengono rigettate a livello di consenso, determinando una penalizzazione del punteggio.

---

## 4. Hardening Crittografico Post-Quantum

AETERNA adotta una cifratura ibrida post-quantum sia per lo sblocco dei nodi (a riposo) sia per le connessioni di rete (in transito), anticipando le minacce crittografiche poste da futuri computer quantistici commerciali.

### 4.1 Firme Dilithium-5
Tutte le identità dei Guardiani registrate a livello di Soulbound Token on-chain sono basate sull'algoritmo di firma a reticoli **Dilithium-5** (NIST Level 5).
- **Dimensione Chiave Pubblica**: 2592 byte
- **Dimensione Firma**: 4595 byte

Il modulo [x/oracle](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/chain/x/oracle/) della AppChain Cosmos valida le firme Dilithium-5 sottomesse dai mittenti per certificare la paternità del blocco dati associato alla prova zk-SNARK, avvalendosi della libreria crittografica altamente ottimizzata `github.com/cloudflare/circl/sign/dilithium`.

### 4.2 Canale Ratchet Operatore-Signer (X3DH-lite)
La comunicazione gRPC tra lo strumento di controllo dell'operatore (`santuarioctl`) e il modulo amministrativo di `santuario-signer` è protetta da un canale di cifratura continua basato su una variante post-quantum di X3DH (*Extended Triple Diffie-Hellman*).
All'avvio, l'operatore genera chiavi effimere `X25519` e `Kyber-1024`. Il signer risponde eseguendo l'incapsulamento `Kyber-1024` e calcolando la derivazione ibrida del segreto:

```math
\text{ikm} = \text{ECDH}(e_{\text{operator}}, \text{id}_{\text{signer}}) \mathbin{\Vert} \text{ECDH}(e_{\text{operator}}, e_{\text{signer}}) \mathbin{\Vert} \text{Kyber}_{\text{ss}}
```
```math
\text{root-key} = \text{HKDF-SHA256}(\text{salt} = \text{"aeterna-sigillum-ratchet-root-v1"}, \text{ikm})
```

La sessione simmetrica avanza poi per-messaggio mediante una cifratura autenticata ChaCha20-Poly1305, applicando un ratchet unidirezionale ad ogni step temporale o volumetrico.

### 4.3 Gossip Handshake P2P Ibrido (1-RTT)
Per estendere la protezione post-quantum alla gossip network (UDP mesh del Sentinel), il modulo Rust [p2p_handshake.rs](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/santuario/ratchet/src/p2p_handshake.rs) implementa un protocollo di handshake 1-RTT ibrido decentralizzato:
1. **Richiesta (Initiator A)**:
   Genera una chiave effimera `X25519` (`a_eph`) e una chiave effimera `Kyber-1024` (`a_kyber`). Invia `a_eph_pub || a_kyber_pub`.
2. **Risposta (Responder B)**:
   Genera una chiave effimera `X25519` (`b_eph`). Esegue l'incapsulamento `Kyber-1024` su `a_kyber_pub` ottenendo `kyber_ss` e il ciphertext `b_kyber_ct`.
   Computa il Diffie-Hellman: `dh = X25519(b_eph_sec, a_eph_pub)`.
   Deriva la chiave gossip di sessione:
   ```math
   \text{session-key} = \text{HKDF-SHA256}(\text{salt} = \text{"aeterna-sigillum-gossip-p2p-v1"}, \text{dh} \mathbin{\Vert} \text{kyber-ss})
   ```
   Invia `b_eph_pub || b_kyber_ct`.
3. **Finalizzazione (Initiator A)**:
   Decapsula `b_kyber_ct` con la propria chiave privata ottenendo `kyber_ss`. Computa lo stesso `dh` e deriva l'identica chiave simmetrica gossip.

---

## 5. Isolamento dei Workload scientifici (gVisor Sandboxing)

I programmi di computazione scientifica scritti in Julia sono complessi e manipolano dati esterni potenzialmente ostili. Per prevenire attacchi di *escape dal container* o compromissione dell'host, AETERNA impone l'esecuzione isolata dei workload scientifici untrusted.

### 5.1 gVisor e runsc
Su piattaforme che supportano la virtualizzazione user-space (es. Linux con supporto KVM), il modulo [gvisor.rs](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/santuario/isolation/src/gvisor.rs) avvia il runner Julia all'interno di una sandbox **gVisor** governata dall'eseguibile `runsc`. gVisor intercetta tutte le chiamate di sistema (syscall) effettuate dal processo Julia, gestendole all'interno di un kernel user-space scritto in Go (*Sentry*), bloccando l'accesso directo alle syscall critiche del kernel host.

### 5.2 Esecuzione Dinamica Effimera e Host Fallback
Su ambienti di sviluppo o piattaforme sprovviste di gVisor nativo (es. Windows in modalità locale), il signer applica un fallback trasparente e sicuro:
- Avvia il processo Julia tramite un `StubLauncher` tracciando il PID del sistema operativo.
- I canali di comunicazione persistenti (es. demoni gRPC o ZMQ aperti all'infinito su porte TCP) sono deprecati. I task vengono invocati in modalità effimera *per-task* leggendo gli input da una directory `inbound` e depositando i risultati in una directory `outbound`.
- Al completamento del calcolo o alla firma del blocco, il modulo di controllo esegue una terminazione forzata e pulita del processo figlio mediante chiamate di sistema native (`SIGKILL` su Unix, `taskkill /F /PID` su Windows), azzerando le risorse liberate ed evitando attacchi di riutilizzo del PID.

---

## 6. Ancoraggio Bitcoin L1 (x/anchor)

Per conferire allo stato di consenso di AETERNA la medesima immutabilità termodinamica della blockchain di Bitcoin, il modulo Cosmos [x/anchor](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/chain/x/anchor/) implementa un sistema di checkpoint periodici su Bitcoin L1.

Un validatore autorizzato (in possesso di SBT di genesi e di una chiave pubblica Dilithium-5) raccoglie periodicamente l'altezza corrente del blocco Cosmos, l'hash dello stato e le metriche principali della rete, firmandole crittograficamente. Questa firma viene inserita all'interno di una transazione Bitcoin standard che utilizza l'istruzione **`OP_RETURN`** per memorizzare nel registro pubblico di Bitcoin fino a 80 byte di payload deterministico:

```math
\text{Payload} = \text{MagicBytes}(4) \mathbin{\Vert} \text{CosmosHeight}(8) \mathbin{\Vert} \text{CosmosStateHash}(32) \mathbin{\Vert} \text{EntropySignature}(36)
```

Una volta che la transazione Bitcoin viene inclusa in un blocco e protetta da un quorum adeguato di Proof-of-Work di Bitcoin, l'altezza Cosmos corrispondente e lo stato dei Trust Score diventano immutabili. Qualsiasi tentativo di riorganizzazione (reorg) o riscrittura della storia della AppChain Cosmos oltre questo punto di ancoraggio verrebbe immediatamente rilevato e rigettato dai nodi on-chain.

---

## 7. Quorum-Based Shamir's Secret Sharing (SSS) Vault

La chiave privata master del validatore (BIP-39 Master Seed a 24 parole) non viene mai memorizzata in chiaro sul disco fisso. All'inizializzazione del nodo, l'operatore frammenta la chiave privata utilizzando lo schema di condivisione segreta di Shamir (**Shamir's Secret Sharing**) in campo finito GF(256).

### 7.1 Aritmetica in GF(256)
Il campo finito GF(256) è costruito sul polinomio irriducibile AES:

```math
P(x) = x^8 + x^4 + x^3 + x + 1
```

Le operazioni di moltiplicazione e inversione di campo sono implementate in tempo costante sfruttando tabelle esponenziali (`EXP`) e logaritmiche (`LOG`) statiche generate all'avvio mediante il generatore primitivo g = 3:
- Moltiplicazione: `$a \cdot b = \text{EXP}[(\text{LOG}[a] + \text{LOG}[b]) \pmod{255}]$`
- Inversione: `$a^{-1} = \text{EXP}[255 - \text{LOG}[a]]$`

### 7.2 Scomposizione e Quorum
Il segreto master S viene scomposto byte-per-byte in un polinomio di grado K - 1:

```math
f(x) = S \oplus c_1 \cdot x \oplus c_2 \cdot x^2 \oplus \dots \oplus c_{K-1} \cdot x^{K-1} \pmod{P(x)}
```

Vengono generate $N$ quote distinte $(i, f(i))$. Per sbloccare il Santuario ed avviare il processo di firma on-chain (`santuarioctl vault unseal`), l'operatore deve fornire un quorum minimo di esattamente $K$ quote. La ricostruzione avviene per interpolazione lagrangiana calcolata a x = 0:

```math
S = f(0) = \sum_{i=1}^{K} y_i \prod_{j \neq i} \frac{x_j}{x_j \oplus x_i} \pmod{P(x)}
```

Se il numero di quote fornite è inferiore a $K$, il segreto calcolato diverge matematicamente verso un valore casuale, mantenendo la totale riservatezza delle chiavi. Una volta ricostruita, la chiave master in memoria decifra l'envelope crittografico protetto da AES-256-GCM.

---

## 8. Conclusioni e Sviluppi Futuri

L'infrastruttura di AETERNA v1.0.0 Sovereign unisce per la prima volta la potenza di calcolo scientifico distribuito (PoUW) con la robustezza delle blockchain sovrane (Cosmos/CometBFT) e la massima protezione contro minacce quantistiche (Dilithium-5/Kyber-1024). L'isolamento dei processi tramite gVisor e la verifica zk-SNARK garantiscono un ambiente privo di trust necessario alla cooperazione globale sulla salute umana.

I prossimi sviluppi includono:
1. Ottimizzazioni hardware specifiche per provers zk-SNARK basate su GPU CUDA e chip ASIC.
2. Integrazione di schemi di crittografia omomorfa (FHE) per permettere l'elaborazione di sequenziamenti genomici interamente cifrati a riposo durante il calcolo scientifico in Julia.
3. Consolidamento dei ponti IBC (Inter-Blockchain Communication) per esportare i trust score di AETERNA verso catene esterne (Ethereum, Cosmos Hub).
