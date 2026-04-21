# AETERNA Protocol

> **The first cyber-liberal infrastructure for Human–AI symbiosis.**
> *Your brain is the node. Proof of Cognition is the key. Freedom is the code.*

![License: AGPLv3 + Prometheus](https://img.shields.io/badge/License-AGPLv3%20%2B%20Prometheus-red)
![Status: Pre-Alpha](https://img.shields.io/badge/Status-Pre--Alpha-orange)
![Network: Aeterna](https://img.shields.io/badge/Network-Aeterna-blueviolet)
![Consensus: PoC Pipeline](https://img.shields.io/badge/Consensus-PoW%20%E2%86%92%20PoUW%20%E2%86%92%20PoC%20%E2%86%92%20PoI-informational)

---

## What AETERNA is

AETERNA is an open-source, decentralized, **gasless** AI/blockchain ecosystem designed to order the *scibile umano* — the totality of verifiable human knowledge — through a sovereign network of **Guardians** running useful scientific computation on the hardware they already own.

The first operational mission (***Missione Alpha***) is **decentralized oncology research**: genomic entropy scanning, driver-vs-passenger mutation analysis via Hamming alignment, stochastic tumor-growth simulation under therapy (Gompertz SDE), and protein folding on the HP lattice.

AETERNA is built on three immutable axioms, hardware-bound and enforced by a critic loop inside every node:

1. **Sovranità Finale** — the Guardian owns its keys, its data, its compute.
2. **Integrità Speculare** — what the Sanctuary observes inside matches what the world observes outside.
3. **Trasparenza Causale** — every decision is traceable to a verifiable mathematical cause.

Read the full [Manifesto](./MANIFESTO.md).

## Architecture at a glance

| Layer | Language | Purpose |
|---|---|---|
| `chain/` | Go (Cosmos SDK) + Rust (CosmWasm) | Gasless L1 AppChain — IBC-native, stores Trust Score and Soulbound Tokens, anchors to Bitcoin via `OP_RETURN` |
| `santuario/` | Rust | Isolated kernel — crypto, sovereign wallet, local LLM inference (`llama.cpp` / `candle`), Axiom enforcement, encrypted IPC |
| `core/` | Python | Userland orchestrator — the **Sentinel**: P2P UDP gossip, task harvesting, Julia dispatch, hardware monitoring, AGP-v1 payload construction |
| `scientific/` | Julia | Computational muscle — SDEs (Gompertz, therapy), HP lattice folding, biosequence analysis (entropy, Hamming) |

### Consensus: a stratified pipeline, not a single algorithm

```
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   Level 0   │   │   Level 1   │   │   Level 2   │   │   Level 3   │
│  Admission  │ → │  Execution  │ → │  Validation │ → │ Persistence │
│ PoW / Sybil │   │    PoUW     │   │     PoC     │   │     PoI     │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
   Soulbound       Useful work      ZK-SNARK of        IPFS ping
   Token + stake   (AI compute)     correctness        (retrievability)
```

Final Trust Score at time *t*:

```
TS_t  =  ω₁ · Σ PoW_sybil   +   ω₂ · (PoUW / t_exec)   +   ω₃ · PoC_valid   +   ω₄ · ∏ PoI_ping
```

Full spec: [`docs/CONSENSUS.md`](./docs/CONSENSUS.md). Scientific protocol: [`docs/AGP-v1.md`](./docs/AGP-v1.md).

## Missione Alpha: local quickstart (single node)

**Requirements**

- Python ≥ 3.11
- Julia ≥ 1.10
- CUDA-capable GPU (reference dev target: RTX 5070 — **Prometheus-0**)
- TPM 2.0 or equivalent Secure Enclave (required beyond 500 REP)

```bash
git clone https://github.com/<org>/aeterna-protocol.git
cd aeterna-protocol

# Install Python side
pip install -r core/requirements.txt --break-system-packages

# Instantiate Julia scientific env
julia --project=scientific -e 'using Pkg; Pkg.instantiate()'

# Terminal 1 — launch Julia scientific engine
julia --project=scientific scientific/zmq_server.jl

# Terminal 2 — launch Python Sentinel
python -m core.sentinel --config aeterna.toml
```

On first boot, `core/sentinel.py` will:

1. Load the Manifesto and sign it with Dilithium-5 (Axiom I — Sovereignty).
2. Probe VRAM on the RTX 5070 and record hardware attestation.
3. Bind the UDP gossip socket on port `4444`.
4. Open the ZMQ `REQ` channel on `tcp://localhost:5555` toward Julia.
5. Harvest its first task — `tumor_growth_gompertz` by default — from the gossip pool.
6. Dispatch it to Julia, collect the AGP-v1 response, solve PoW difficulty 4, and broadcast the signed block.

## Repository layout

```
aeterna-protocol/
├── MANIFESTO.md          The soul of the network — Italian
├── README.md             This file
├── LICENSE               AGPLv3 + reference to ETHICS.md
├── ETHICS.md             The Prometheus Clause — addendum legally binding on derivatives
├── aeterna.toml          Canonical node configuration
├── core/                 Python Sentinel — userland orchestrator
│   ├── __init__.py
│   ├── sentinel.py       Main entrypoint
│   ├── gossip.py         AeternaGossipNet — UDP P2P
│   └── requirements.txt
├── scientific/           Julia scientific engine
│   ├── zmq_server.jl     ZMQ REP dispatcher (6 task types)
│   ├── oncology_sim.jl   Gompertz, therapy SDE, entropy, Hamming
│   ├── folding_math.jl   HP lattice folding
│   └── Project.toml
├── chain/                [v0.1.0 stub] Cosmos SDK + CosmWasm AppChain
│   └── README.md
├── santuario/            [v0.1.0 stub] Rust kernel + LLM subprocess
│   └── README.md
└── docs/
    ├── CONSENSUS.md      Full pipeline specification
    └── AGP-v1.md         Aeterna Genomic Protocol v1 — frozen schema
```

## Status

`v0.0.1` — **Genesis skeleton.** This commit publishes the Manifesto, the consensus pipeline specification, the Sentinel↔Julia bridge, the AGP-v1 frozen schema, and directory stubs for the chain and Sanctuary. The testnet is not yet online. The first public Guardian node (*Prometheus-0*) will launch on an RTX 5070 as the genesis validator.

### Roadmap

| Version | Target |
|---|---|
| `v0.0.1` | Local Sentinel↔Julia loop on *Missione Alpha* (this release) |
| `v0.1.0` | Rust Santuario with `llama.cpp` LLM subprocess + encrypted IPC |
| `v0.2.0` | ✅ Multi-node UDP gossip + hybrid consensus validation (Custos) |
| `v0.5.0` | CosmWasm smart contracts + IBC testnet + IPFS cold storage |
| `v1.0.0` | Firecracker micro-VM isolation + Bitcoin `OP_RETURN` anchoring + public mainnet |

## License

AETERNA is licensed under **AGPLv3** with the **Prometheus Clause** — see [`LICENSE`](./LICENSE) and [`ETHICS.md`](./ETHICS.md).

The code is free to study, run, modify, and redistribute under strong copyleft. It must not be integrated into autonomous weapon targeting systems, mass-state surveillance infrastructure, or any system that extracts rent from human suffering. Derivative works must preserve both the AGPLv3 obligations and the Prometheus Clause.

## Contributing

AETERNA is building in public. Pull requests welcome on:

- `scientific/` — additional computational missions (climate modeling, lost-knowledge recovery, resource optimization)
- `core/` — gossip protocol hardening, adversarial-robust aggregation (Krum, Bulyan)
- `docs/` — translations of the Manifesto

Signing the Manifesto is a prerequisite for any node joining the testnet. Signing the `CONTRIBUTOR.md` (forthcoming) is a prerequisite for any merged PR.

---

*Portare il fuoco significa saperlo restituire.*
