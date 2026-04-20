# `chain/` — AETERNA AppChain (stub)

Target release: **v0.5.0**.

This directory will host the AETERNA gasless L1 AppChain, built on
**Cosmos SDK (Go)** with CosmWasm smart contracts written in **Rust**. The
choice of Cosmos over Substrate was locked in by the Chain & Oracolo
orchestrator chat on 2026-04-20, on the strength of native IBC for
cross-chain Soulbound Token reputation reads.

## Planned contents

```
chain/
├── app/                          Cosmos app-entrypoint
├── x/                            Custom Cosmos SDK modules
│   ├── guardian/                  Identity NFT + Soulbound Token (SBT)
│   ├── oracle/                    AGP block submission + consensus pipeline
│   ├── trustscore/                TS aggregation (PoW + PoUW + PoC + PoI)
│   └── anchor/                    Bitcoin OP_RETURN heartbeat + critical events
├── contracts/                    CosmWasm (Rust) smart contracts
│   └── aeterna_oracle/
│       ├── src/
│       │   ├── state.rs
│       │   ├── msg.rs
│       │   └── contract.rs       ExecuteMsg: RequestReEntryChallenge
│       │                         SubmitProof, UpdateGlobalModel
│       └── Cargo.toml
├── proto/                        Protobuf definitions
└── scripts/                      Devnet + testnet bootstrap
```

## Design locks (from the orchestrator chats)

1. **L1 monolithic AppChain.** No L2, no Substrate/Cosmos hybrid. Justification:
   a gasless network cannot afford to ask validators to maintain two separate
   nodes. Scrapped hybrid proposal on 2026-04-20.
2. **IBC-native SBT.** The Guardian Identity Token reads reputation attestations
   from other Cosmos zones; no custom bridges.
3. **Consensus pipeline is stratified**, not flat — see `docs/CONSENSUS.md`.
   Levels 0–3 are enforced *in order* inside `x/oracle`, and a block only
   finalizes if all four layers accept.
4. **Bitcoin anchoring** via `OP_RETURN` every `N = 10_000` AETERNA blocks
   (heartbeat) plus event-driven triggers (global model CID update, governance
   omega change, emergency slash). See `x/anchor`.

## Not yet built

None of this code exists in the v0.0.1 commit. The stub is here to claim the
architectural territory and let contributors start drafting proto definitions
and module skeletons in PRs.

## How to start contributing

1. Read `docs/CONSENSUS.md` end-to-end.
2. Sign `MANIFESTO.md`.
3. Open an issue proposing a single module (`x/guardian`, `x/oracle`,
   `x/trustscore`, or `x/anchor`).
4. Submit a PR with a CosmosSDK scaffold generated via `ignite scaffold module`.

All chain contributors must respect the Prometheus Clause (`ETHICS.md`) —
particularly the Axiomatic Circumvention prohibition (Section 2.4).
