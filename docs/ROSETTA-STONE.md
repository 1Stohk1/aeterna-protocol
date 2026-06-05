# AETERNA Protocol — Rosetta Stone (Spazio Latente di Ancoraggio)

This document specifies the mathematical model and architectural layout of the **Pietra di Rosetta** (Rosetta Stone) latent space alignment module. This module enables asymmetric nodes (running models with different internal dimensionalities) to exchange semantic meanings, prompt modules, and episodic memories without disclosing raw weight parameters or breaking compatibility. It also specifies the neuroplastic routing and growth mechanisms.

---

## 1. Mathematical Formulation

Let:
* $\Omega$ be the canonical shared anchor space of dimension $D$ (e.g., $D = 64$).
* $S_i$ be the internal latent representation space of node $i$ of dimension $d_i$ (e.g., $d_1 = 128$, $d_2 = 256$, etc.).
* $A_{shared}$ be a matrix of shape $N \times D$ representing $N$ universal reference anchors (fundamental constants, math axioms, etc.).
* $A_i$ be a matrix of shape $N \times d_i$ representing the node's internal encoding of those same reference anchors.

### 1.1 Local Calibration (Least Squares)
To map its internal space $S_i$ to $\Omega$, each node locally computes its projection matrix $W_i \in \mathbb{R}^{d_i \times D}$ by solving:

$$W_i = \text{argmin} \| A_i W_i - A_{shared} \|_F^2$$

Using standard linear algebra (Least Squares), $W_i$ is solved locally:

$$W_i = (A_i^T A_i)^{-1} A_i^T A_{shared}$$

This step is performed local-only during the node's initial boot sequence and requires no network consensus or centralized coordinators.

> [!NOTE]
> **Consensus on Canonical Anchor Space:** To ensure that all nodes in the same network map to the identical canonical anchoring space $\Omega$, the orthogonal projection basis and canonical anchors are derived deterministically using a shared network seed (based on the `network` parameter in `aeterna.toml`). Local model distortions (the true transform matrix and local anchor noise) remain specific to each node's local Small Language Model (SLM) representation.

### 1.2 Projection and Reconstruction
* **Projection (Local $\to$ Shared):** Maps a local representation $v_i \in \mathbb{R}^{d_i}$ to the shared space $\Omega$:
  
  $$v_{\Omega} = v_i \cdot W_i$$

* **Reconstruction (Shared $\to$ Local):** Uses the Moore-Penrose pseudo-inverse $W_i^+ \in \mathbb{R}^{D \times d_i}$ to reconstruct a shared vector back to the local space:
  
  $$v_{reconstructed} = v_{\Omega} \cdot W_i^+$$

---

## 2. Semantic Gossip Flow

```
┌─────────────────┐             ┌─────────────────┐             ┌─────────────────┐
│     Node A      │             │  Gossip Network │             │     Node B      │
│  (Internal d_A)  │             │   (Shared D)    │             │  (Internal d_B)  │
└────────┬────────┘             └────────┬────────┘             └────────┬────────┘
         │                               │                               │
         │ 1. Project local concept      │                               │
         │    v_omega = v_A * W_A        │                               │
         ├──────────────────────────────>│                               │
         │                               │ 2. Propagate concept          │
         │                               │    v_recvd = v_omega + noise  │
         │                               ├──────────────────────────────>│
         │                               │                               │ 3. Reconstruct
         │                               │                               │    v_B = v_recvd * W_B^+
         │                               │                               │
         │                               │                               │ 4. Re-project
         │                               │                               │    v_omega_B = v_B * W_B
         │                               │                               │
         │                               │                               │ 5. Measure similarity
         │                               │                               │    cos_sim(v_omega, v_omega_B)
```

By verifying that the cosine similarity is close to $1.0$, Node B confirms it has successfully aligned and understood the incoming semantic concept from Node A.

---

## 3. Semantic Immunology & Self-Calibration (Immunologia Semantica)

Without strict central control, a node must protect its internal cognitive loop from malicious or corrupted inputs. We define **Projection Reconstruction Error (PRE)** as the validation metric:

$$\text{PRE}(v_{\Omega}) = \| v_{\Omega} - (v_{\Omega} \cdot W_i^+ \cdot W_i) \|$$

* **If $v_{\Omega}$ is honest:** It lies in the column span of the common semantic manifold, resulting in a low $\text{PRE}$ ($\text{PRE} \le \text{Threshold}_{PRE}$).
* **If $v_{\Omega}$ is poisoned or random:** It will contain components outside the model's transformation matrices, resulting in a high $\text{PRE}$ ($\text{PRE} > \text{Threshold}_{PRE}$). 

If the validation fails, the node checks if the vector lies in the valid $D_{intrinsic}$ anchor subspace (using the orthogonal basis $B$):

$$\text{SubspaceError}(v_{\Omega}) = \| v_{\Omega} - (v_{\Omega} \cdot B^T \cdot B) \|$$

* If $\text{SubspaceError} \le \text{Threshold}_{subspace}$, the vector represents a **valid novel concept**, triggering **Dynamic Sprouting**.
* If $\text{SubspaceError} > \text{Threshold}_{subspace}$, it is classified as **Malicious Spam/Poisoning** and quarantined.

### 3.1 Dynamic Self-Calibration (Autocalibrazione Statistica)
To handle the density asymmetry and anisotropy of real-world text embeddings, the thresholds are not hardcoded. Instead, they are calculated dynamically during boot-time calibration over the set of reference anchors $A$:

$$\text{Threshold}_{PRE} = \max\left(0.20, \mu_{pre} + k \cdot \sigma_{pre}\right)$$

$$\text{Threshold}_{subspace} = \max\left(0.15, \mu_{subspace} + k \cdot \sigma_{subspace}\right)$$

where:
* $\mu_{pre}, \sigma_{pre}$ are the mean and standard deviation of reconstruction errors on the anchor set.
* $\mu_{subspace}, \sigma_{subspace}$ are the mean and standard deviation of subspace errors on the anchor set.
* $k$ is the standard deviation scaling factor (default: $3.5$).
* The floors ($0.20$ and $0.15$) prevent the thresholds from collapsing in noiseless/mock simulation environments.

### 3.2 Threshold Sedimentation (Sedimentazione delle Soglie)
To prevent autoimmune feedback loops and threshold drift (where noisy or malicious sprout events iteratively widen the immunology tolerance, making the node vulnerable to increasingly noisy inputs), the node's thresholds remain **stable** after boot.
* During **sprouting** or **expert assimilation**, the local projection matrix $W_i$ is instantly recalibrated using Least Squares to maintain correct semantic routing, but the immunology thresholds are **not** recalculated.
* Thresholds are only updated during a dedicated **Threshold Sedimentation** event (`sediment_thresholds()`), which typically runs periodically aligned with episodic memory consolidation. This ensures that only consolidated, stable anchors influence the statistical baseline of the node.

### 3.3 Probabilistic Anti-Entropy (Bloom Filters)
To handle packet drops, network jitter, or out-of-order delivery on real geographic WAN connections without causing UDP packet fragmentation or gossip storms:
* **Bloom Filter Serialization:** Instead of transmitting heavy lists of seen message hashes, the node serializes its last 30 seen message IDs into a compact 512-bit **Bloom Filter** ($m=512, k=7$). The filter has a theoretical false-positive probability $p < 1\%$ and a constant footprint of 64 bytes (base64-encoded).
* **Two-Step Direct Push Reconciliation:** 
  1. Node-A periodically sends its base64 Bloom Filter digest directly to Node-B.
  2. Node-B checks its local message cache against the received Bloom Filter. If any local message `mid` is **not** present in the filter (guaranteeing that Node-A lacks this message), Node-B directly push-retransmits the message envelope to Node-A.
This layout halves the transaction round-trips compared to traditional request-response (pull) sync loops and avoids IP fragmentation.

---

## 4. Neuroplastic Growth: Routing & Sprouting

To support continuous adaptation, nodes implement neuroplastic growth structures:

### 4.1 Semantic Routing
Instead of static classification layers, the node routes inputs dynamically. A `SemanticRouter` holds centroids of active adapters (experts) in the shared space $\Omega$:

$$\text{Expert} = \text{argmax}_{j} \left( \text{CosineSimilarity}(v_{\Omega}, \text{Centroid}_j) \right)$$

This allows adding new experts dynamically at runtime without retraining a routing network.

### 4.2 Dynamic Sprouting (Germogliazione)
When a valid novel concept is received (high $\text{PRE}$, low $\text{SubspaceError}$):
1. A new expert is spawned (`Expert_N`), initialized with `centroid = v_omega`.
2. The node appends this new concept vector to its local `shared_anchors` and its distorted internal representation to `local_anchors`.
3. The node **recalibrates** its projection matrix $W_i$ using Least Squares on the expanded dataset.
4. Future concepts within this semantic neighborhood will now pass the immunology screening with low $\text{PRE}$ and be routed directly to the new expert.

---

## 5. Dual-Memory Model: Episodic Buffer and Semantic Store

AETERNAs cognitive nodes handle conversation tracking and context retention using a dual-layered memory model in the shared $\Omega$ space.

### 5.1 Short-Term Episodic Memory (Memory Buffer)
Stores sequential dialogue turns as `DialogueTurn(timestamp, speaker, text, embedding_omega)`. 
A sliding window is enforced by pruning records older than $T_{max}$ (where $T_{max}$ defaults to $30$ days, loaded from `episodic_memory_days` in `aeterna.toml`):

$$\text{Prune if } t_{current} - t > T_{max}$$

### 5.2 Long-Term Semantic Memory (Vector Store)
Acts as a vector database embedded directly in the shared space $\Omega$. Over time, episodic memories are consolidated into long-term semantic memory.

When the node needs to retrieve past context, it performs a Cosine Similarity search using a query vector $q_{\Omega} \in \mathbb{R}^D$ representing the user's current intent:

$$S(v_{\Omega}, q_{\Omega}) = \frac{v_{\Omega} \cdot q_{\Omega}}{\|v_{\Omega}\| \|q_{\Omega}\|}$$

The vector store returns the top $K$ consolidated memories ranked by descending similarity score $S$.

---

## 6. P2P Knowledge-Sharing Protocol

To scale learning without transferring large models or full vector databases across the gossip network, nodes share only the geometric representation (centroids) of sprouted experts in the canonical space $\Omega$.

### 6.1 Gossip Envelope Schema
A shared expert is propagated inside a signed gossip envelope of `kind = "expert_share"`:

* **Payload:**
  - `expert_id` (string): The ID of the sprouted expert category.
  - `centroid` (array of float): The 64D centroid vector in $\Omega$.
  - `creator_node_id` (string): The node that spawned the expert.
  - `timestamp` (integer): Epoch timestamp of sprouting.
* **Security:**
  - `payload_hash` (hex string): SHA-256 hash of the canonical JSON representation of the payload.
  - `signature` (hex string): Dilithium-5 cryptographic signature of the hash.
  - `public_key` (hex string): The creator node's public key.

### 6.2 Asymmetric Assimilation (Assimilazione)
When a remote node $j$ with local dimensionality $d_j$ receives and verifies the signature of an `expert_share` message, it:
1. Adds the expert and its centroid vector $c_{\Omega}$ to its local `SemanticRouter`.
2. Map $c_{\Omega}$ back to its local space by simulating a local concept representation $c_j = c_{\Omega} W_j^+ + \text{noise}$.
3. Appends $c_j$ and $c_{\Omega}$ to its anchor history and locally recalibrates its projection matrix $W_j$ using least squares.

This updates node $j$'s alignment matrix $W_j$ to successfully map and route concepts in the newly shared semantic neighborhood.

---

## 7. Local LLM Integration (Ollama Client)

To run fully autonomous and private cognitive processes, nodes interface with a local Small Language Model (SLM) or dedicated embedding model using **Ollama** as the computational backend.

### 7.1 Local Semantic Embeddings
Textual queries and dialog logs are mapped to high-dimensional local embeddings (e.g. $1024$ dimensions for `nomic-embed-text` or $2048$ dimensions for `llama3.2`). 
The `OllamaClient` handles REST interactions with the local daemon:

* **Endpoint `/api/embed` (Preferred):** Returns batched embeddings in a single round-trip.
* **Endpoint `/api/embeddings` (Fallback):** Handles legacy single-prompt embedding requests sequentially.

Once the local high-dimensional embedding $v_{local} \in \mathbb{R}^d$ is generated, the node projects it into the shared $\Omega$ space to perform immunological screening, semantic routing, and long-term vector storage:

$$v_{\Omega} = v_{local} \cdot W_i$$

---


## 8. Cross-Model Alignment Stability (Osmosi Semantica)

A key scientific property of the Pietra di Rosetta is its ability to bridge completely distinct local embedding spaces. For instance, Node A running `nomic-embed-text` ($d_a = 768$) and Node B running `llama3.2` ($d_b = 2048$) can exchange semantic meanings directly through the shared 64D $\Omega$ space.

### 8.1 Bidirectional Mapping Workflow
When Node A wants to transmit a concept to Node B:
1. Node A embeds the concept to $v_a \in \mathbb{R}^{d_a}$ and projects it to the shared space:
   $$v_{\Omega} = v_a \cdot W_a$$
2. Node B receives $v_{\Omega}$ and maps it to its own local space:
   $$v_{rec,b} = v_{\Omega} \cdot W_b^+$$
3. Node B reprojects the reconstructed representation back to the shared space:
   $$v_{\Omega,B} = v_{rec,b} \cdot W_b$$

### 8.2 Stability Condition
Osmosis is stable when the bidirectional projection has high cosine similarity:

$$\text{Similarity}(v_{\Omega}, v_{\Omega,B}) = \frac{v_{\Omega} \cdot v_{\Omega,B}}{\|v_{\Omega}\| \|v_{\Omega,B}\|} \ge 0.90$$

This mathematical property ensures that asymmetric models can cooperate and understand shared expert centroids despite differences in tokenizers, dimensionalities, and neural architectures.

---

## 9. Codebase Integration

The code is distributed as follows:
1. **Core Modules:**
   - [core/rosetta.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/core/rosetta.py): Exports `RosettaAligner`, `SemanticRouter`, and `NeuroplasticNode` (immunology, routing, sprouting, assimilation).
   - [core/memory.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/core/memory.py): Exports `DialogueTurn` and `EpisodicMemory` (short-term buffer, sliding-window pruning).
   - [core/vector_store.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/core/vector_store.py): Exports `SemanticMemory` (long-term numpy-based vector store and search).
   - [core/knowledge_sharing.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/core/knowledge_sharing.py): Exports `build_expert_share_message` and `verify_expert_share_message` (P2P packaging, signing, and verification).
   - [core/llm_client.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/core/llm_client.py): Exports `OllamaClient` (REST client wrapper for local embedding and completions).
2. **Developer Simulations:**
   - [scripts/rosetta_simulation_test.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/scripts/rosetta_simulation_test.py): Implements the multi-node test network, sprouting, routing, episodic memory pruning, semantic retrieval, P2P sharing/assimilation, and local model integration.
   - [scripts/cross_model_alignment_test.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/scripts/cross_model_alignment_test.py): Validates bidirectional mapping stability between different embedding models (mock and real modes).




