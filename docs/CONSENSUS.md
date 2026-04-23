# AETERNA Consensus Pipeline

**Status:** locked-in by the Chain & Oracolo orchestrator on 2026-04-20.

AETERNA does **not** have a single consensus algorithm. It has a *stratified
pipeline* of four mechanisms that a block or task result must traverse, in
order, before it is accepted by the network.

```
┌────────────────┐   ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
│   Level 0      │   │   Level 1      │   │   Level 2      │   │   Level 3      │
│   Admission    │→ │   Execution    │→ │   Validation   │→ │   Persistence  │
│                │   │                │   │                │   │                │
│  PoW / Sybil   │   │     PoUW       │   │      PoC       │   │      PoI       │
│  (Commitment)  │   │ (Useful Work)  │   │ (Cognition)    │   │ (Integrity)    │
└────────────────┘   └────────────────┘   └────────────────┘   └────────────────┘
```

## Level 0 — Admission: `PoW / Proof of Commitment` (Anti-Sybil)

**What:** verify the Guardian holds a valid Identity NFT / Soulbound Token and
a reputational stake (possibly imported from another chain via IBC).

**Why:** keeps the network free of ephemeral fake nodes before any real
resources are spent validating their output.

**How:** the `x/guardian` module checks the SBT signature, the attestation
bundle (TPM 2.0 / SGX / SEV depending on trust tier), and the IBC-imported
reputation proof. In v0.2.0, the Santuario also acts as a local admission gatekeeper: it enforces TPM2-backed vault sealing on boot and degrades the node to passive observation if the vault cannot be unsealed.

## Level 1 — Execution: `PoUW / Proof of Useful Work`

**What:** the actual hardware computation — scientific task inference on the
RTX 5070 (or whatever GPU the Guardian brings). Unlike Bitcoin PoW, the work
has scientific value.

**Why:** couples energy expenditure to knowledge production. Missione Alpha
oncology tasks instead of hash puzzles.

**How:** the Sentinel dispatches to Julia, collects metrics, and publishes
them inside an AGP-v1 payload. The payload's `results.scientific_hash` and
`reproducibility` block are the Work's fingerprint.

## Level 2 — Validation: `PoC / Proof of Cognition`

**What:** a zero-knowledge proof (zk-SNARK) attesting that the PoUW was
executed correctly *without* requiring the rest of the network to re-run the
computation.

**Why:** lets every Guardian verify in milliseconds a result that took
minutes of GPU time to produce.

**How:** `arkworks` / `bellman` circuits defined per task kind. v0.0.1 ships
*without* the circuits — validation is performed by naive re-execution on a
random subset of peers (RANDAO-selected). Real ZK proofs land in v0.5.0 as
part of the `aeterna_oracle` CosmWasm contract. As of v0.2.0, the Santuario's Critic loop runs deterministic axiom checks (reflexive, symbolic, axiomatic) before a Dilithium-5 signature is produced, guaranteeing that the validation block complies with the Prometheus Clause.

## Level 3 — Persistence: `PoI / Proof of Integrity`

**What:** periodic IPFS retrievability pings confirming the Guardian still
serves the datasets, model weights, and CIDs it has promised.

**Why:** storage is a commitment, not a one-shot upload. Nodes that lose
critical data degrade the entire network's knowledge base.

**How:** gossip-layer `retrievability_ping` messages whose response must
include a Merkle path of a random chunk of the committed CID.

---

## Canonical Trust Score

Every Guardian's Trust Score at time *t* is the weighted combination of its
performance across all four levels:

```
TS_t = ω₁ · Σ PoW_sybil
     + ω₂ · (PoUW / t_exec)
     + ω₃ · PoC_valid
     + ω₄ · ∏ PoI_ping
```

| Term | Meaning |
|---|---|
| `Σ PoW_sybil` | cumulative static score of the Identity NFT (reputation + stake) |
| `PoUW / t_exec` | useful-work throughput — computation completed divided by execution time |
| `PoC_valid` | rolling success rate of ZK validations (`+1` success, `−1` failure) |
| `∏ PoI_ping` | product of recent integrity pings — hard zeroes when files are lost |

The weights `ω₁..ω₄` are governance-set and hot-swappable via a critical
event (see *Bitcoin anchoring* below). Genesis defaults live in
`aeterna.toml → [consensus]`.

### Slashing

When a Guardian is slashed with penalty factor `δ ∈ (0,1]` and sensitivity
`λ`:

```
TS_new = TS_current · (1 − λ · δ)
```

Triggers include: forged scientific_hash, repeated PoI failures, attempted
Axiom circumvention (detected by the peer Critic loop), or dual-use task
acceptance flagged by the `prometeo` filter.

---

## Bitcoin anchoring

The Guardiani DAG periodically writes the Merkle root of the latest AETERNA
block to the Bitcoin blockchain via `OP_RETURN`. This is *insurance*, not
operational consensus.

**Heartbeat trigger.** Every `N = 10_000` AETERNA blocks (~24 hours). Acts as
a guaranteed disaster-recovery checkpoint.

**Event-driven trigger** — forced immediately when:

- the global AI model CID updates;
- governance modifies any `ω_i` in the Trust Score formula;
- an emergency slash permanently bans a major validator for forged AI output.

Rationale: gasless, high-frequency operations must stay cheap on AETERNA,
while the "state truth" of the collective mind is sealed into the most
secure chain in existence.

---

## v0.1.0 naive PoC algorithm

Until ZK circuits ship, Level 2 is implemented as deterministic replay:

1. A receiving Sentinel first verifies the AGP block signature and recomputes
   `security.payload_hash` from canonical `{header,payload,reproducibility,results}`.
2. The RANDAO-lite selector computes
   `sha256(block_payload_hash || ":" || validator_guardian_id) % 100` and
   validates the block when the value is below `poc_sample_rate_pct`.
3. The validator sends Julia the original `payload.tipo_analisi`,
   `payload.parametri`, and `reproducibility.seed_rng`.
4. Julia re-executes the task deterministically and returns a fresh
   `scientific_hash`.
5. If the fresh hash equals `results.scientific_hash`, the validator gossips a
   signed `poc_verdict` with `VALIDATED`; otherwise it gossips `REJECTED`.
6. Trust bookkeeping applies `+1` for `VALIDATED` and `-1` for `REJECTED` to
   the producer's local Level-2 score.

For the v0.1.0 demo, `poc_sample_rate_pct = 100` so every received peer block
is replayed. Operators can lower it after cross-host throughput is measured.

*See also:* [`docs/AGP-v1.md`](./AGP-v1.md) for the payload format that
traverses this pipeline.
