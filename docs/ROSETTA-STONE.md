# AETERNA Protocol — Rosetta Stone (Spazio Latente di Ancoraggio)

This document specifies the mathematical model and architectural layout of the **Pietra di Rosetta** (Rosetta Stone) latent space alignment module. This module enables asymmetric nodes (running models with different internal dimensionalities) to exchange semantic meanings, prompt modules, and episodic memories without disclosing raw weight parameters or breaking compatibility.

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

If the validation fails, the node discards the concept, preventing semantic poisoning or model collapse.

---

## 4. Codebase Integration

The code is distributed as follows:
1. **Core Module:** [core/rosetta.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/core/rosetta.py) exports `RosettaAligner` to handle projections and similarities.
2. **Developer Simulation:** [scripts/rosetta_simulation_test.py](file:///C:/Users/Christian/.gemini/antigravity/worktrees/AETERNA/implement-browser-conversation-memory/scripts/rosetta_simulation_test.py) implements the multi-node test network and immunology simulation.
