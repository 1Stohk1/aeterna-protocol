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

## 3. Semantic Immunology (Immunologia Semantica)

Without strict central control, a node must protect its internal cognitive loop from malicious or corrupted inputs. We define **Projection Reconstruction Error (PRE)** as the validation metric:

$$\text{PRE}(v_{\Omega}) = \| v_{\Omega} - (v_{\Omega} \cdot W_i^+ \cdot W_i) \|$$

* **If $v_{\Omega}$ is honest:** It lies in the column span of the common semantic manifold, resulting in a low $\text{PRE}$ ($\text{PRE} \le \text{Threshold}$).
* **If $v_{\Omega}$ is poisoned or random:** It will contain components outside the model's transformation matrices, resulting in a high $\text{PRE}$ ($\text{PRE} > \text{Threshold}$). 

If the validation fails, the node checks if the vector lies in the valid $D_{intrinsic}$ anchor subspace (using `projection_basis`):

$$\text{SubspaceError}(v_{\Omega}) = \| v_{\Omega} - (v_{\Omega} \cdot B^T \cdot B) \|$$

* If $\text{SubspaceError} \le \text{Threshold}_{subspace}$, the vector represents a **valid novel concept**, triggering **Dynamic Sprouting**.
* If $\text{SubspaceError} > \text{Threshold}_{subspace}$, it is classified as **Malicious Spam/Poisoning** and quarantined.

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

## 5. Codebase Integration

The code is distributed as follows:
1. **Core Module:** [core/rosetta.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/core/rosetta.py) exports:
   - `RosettaAligner`: Handles calibration, projection, and reconstruction.
   - `SemanticRouter`: Handles cosine-distance routing between active experts.
   - `NeuroplasticNode`: Coordinates the immunology check, routing, and sprouting.
2. **Developer Simulation:** [scripts/rosetta_simulation_test.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/scripts/rosetta_simulation_test.py) implements the multi-node test network and neuroplastic routing simulation.
