# Sprint Plan — AETERNA v0.1.0 "Echelon"

**Status:** proposed by the Terminale di Comando on 2026-04-20.
**Predecessor:** v0.0.1 "Genesis" — single-node, localhost-only, unsigned.
**Successor target:** v0.2.0 "Custos" — full Santuario with seccomp, vault, critic loop.

---

## 1. Sprint goal (one sentence)

> **Two Prometheus Guardians running on different physical hosts exchange
> cryptographically-signed AGP-v1 blocks and validate each other's results
> via naive re-execution.**

If at the end of this sprint you cannot sit at two laptops on two different
residential ISPs, run `./bootstrap.sh` on each, and see blocks flow A→B→A
with signatures verified on both ends, the sprint has failed regardless of
how much code was written.

## 2. Scope rationale

v0.0.1 proved the *engine*. v0.1.0 proves the *protocol*. The two
non-negotiable pieces that have to land together are:

1. **Peer-to-peer connectivity** (the *why* we're decentralized).
2. **Post-quantum signatures on every block** (the *because unsigned P2P
   is forgeable by anyone*).

Everything else the Santuario was supposed to do — sandboxing, vault
encryption, critic loop, migration thresholds — is deferred to v0.2.0.
Reason: the armor exists to protect a network that until now does not
exist. Building the armor first means calibrating against a threat model
that materializes only when traffic starts flowing.

## 3. Phased deliverables

The sprint is divided into five phases. Each phase ends with a binary
pass/fail demo. Do not start phase N+1 until phase N's demo is green.

### Phase A — Santuario signer MVP (Rust)

The minimum slice of the Rust kernel needed to make the network
unforgeable. Everything else Rust-side waits for v0.2.0.

| Deliverable | Path | Owner |
|---|---|---|
| Cargo crate skeleton (`santuario-core` workspace) | `santuario/Cargo.toml` | Rust |
| gRPC/UDS server — Dilithium-5 sign + verify | `santuario/signer/src/main.rs` | Rust |
| Protobuf definitions for the signer RPC | `santuario/proto/signer.proto` | Rust |
| Keygen CLI — generates the node keypair at first boot | `santuario/signer/src/bin/keygen.rs` | Rust |
| File-backed keystore (TPM sealing deferred) | `santuario/signer/src/keystore.rs` | Rust |
| Unit tests — keygen roundtrip, sign-then-verify | `santuario/signer/tests/` | Rust |

**Phase A demo:** `cargo run --bin santuario-signer` starts listening on
`/run/aeterna/santuario.sock`; a Python client can round-trip a
sign→verify on a test payload. No Python-side integration yet.

### Phase B — Python↔Rust bridge

| Deliverable | Path | Owner |
|---|---|---|
| Generated Python gRPC stubs | `core/santuario_pb2*.py` | Python |
| `SantuarioClient` wrapper with reconnect logic | `core/santuario_client.py` | Python |
| `Sentinel._sign_block()` — swaps in for the TODO in `build_agp_payload` | `core/sentinel.py` | Python |
| `Sentinel._verify_peer_block()` — rejects blocks with bad signatures | `core/sentinel.py` | Python |
| `bootstrap.sh` launches Rust signer as third child process | `bootstrap.sh` | Ops |
| Integration test — Python signs, Python verifies, all via UDS | `scripts/santuario_test.py` | Test |

**Phase B demo:** `./bootstrap.sh` now starts three processes (Rust
signer + Julia engine + Python Sentinel). Local smoke test produces
blocks that carry a valid `signature` field and the Sentinel refuses to
gossip any block whose signature doesn't verify.

### Phase C — Peer discovery

| Deliverable | Path | Owner |
|---|---|---|
| `peer_announce` gossip message kind with signed peer identity | `core/gossip.py` | Python |
| LRU peer table with `last_seen_ts` and liveness decay | `core/peer_table.py` | Python |
| Bootstrap list loader from `aeterna.toml` + `aeterna.local.toml` | `core/sentinel.py` | Python |
| Startup handshake — exchange public keys + Manifesto digest | `core/handshake.py` | Python |

**Phase C demo:** two Sentinels running on the same LAN auto-discover
each other from a shared bootstrap list and print each other's
`guardian_id` within 30 seconds.

### Phase D — NAT traversal

NAT is the hardest part of the sprint and the most likely to slip.
**Two-track strategy** — start both tracks, keep whichever ships first.

| Track | Deliverable | Effort |
|---|---|---|
| Primary: UDP hole-punching | `core/nat_udp.py` using a rendezvous hint | Medium–High |
| Fallback: Rendezvous VPS | `ops/rendezvous/` — stateless Python relay on a 5€/month VPS | Low |

The rendezvous fallback is intentionally dumb (it only relays the
initial handshake; subsequent gossip is direct or degrades to
rendezvous-relayed UDP). It buys a working demo if hole-punching stalls.

**Phase D demo:** Prometheus-0 on residential ISP *A* and Prometheus-1
on residential ISP *B* exchange at least one gossip message in either
direction.

### Phase E — Proof of Cognition, naive mode

Level 2 of the consensus pipeline in its v0.1 form: peers re-execute a
random subset of received blocks and gossip a VALIDATED/REJECTED
verdict.

| Deliverable | Path | Owner |
|---|---|---|
| RANDAO-lite selector — deterministically picks X% of incoming blocks | `core/poc.py` | Python |
| Re-execution: replay the block's task with the same seed, compare `scientific_hash` | `core/poc.py` | Python |
| `poc_verdict` gossip message kind (signed) | `core/gossip.py` | Python |
| Trust Score bookkeeping — `+1` success, `−1` failure per `CONSENSUS.md` §Level 2 | `core/trust_score.py` | Python |

**Phase E demo:** Prometheus-0 produces a tumor_growth_gompertz block;
Prometheus-1 re-executes it deterministically and gossips a VALIDATED
verdict; Prometheus-0 logs the trust-score delta. Flip a bit on
Prometheus-0 on purpose (e.g. return a random metric instead of the
real one); Prometheus-1 must gossip REJECTED.

## 4. Acceptance criteria (sprint-level)

All of the following must hold simultaneously for v0.1.0 to ship:

1. `bootstrap.sh` starts Rust signer + Julia engine + Python Sentinel and
   all three are healthy within 60 seconds.
2. Two Guardians on two different residential ISPs exchange at least
   one AGP block each way.
3. Every block in flight carries a Dilithium-5 signature; a block with
   a bad signature is dropped at the receiver and logged.
4. At least one genuine block is VALIDATED via naive PoC re-execution.
5. At least one forged block (produced by a test harness) is REJECTED
   via naive PoC re-execution.
6. `python3 scripts/smoke_test.py` still passes locally on each node.
7. `docs/CONSENSUS.md` is updated with the concrete Level-2 naive
   algorithm.
8. `docs/AGP-v1.md` is extended with the `signature` field schema.

## 5. Out of scope — deferred to v0.2.0

State this in every sprint standup so the periphery chats stop
proposing it:

- Seccomp-bpf process isolation around the LLM subprocess.
- AES-256-GCM vault with TPM2-sealed keys (file-backed keystore is fine
  for v0.1.0).
- Critic loop and axiom-violation refusal at signing time.
- Hourly integrity audit (α threshold).
- CPU stress soft-migration (β threshold).
- Port-scan stealth migration (γ threshold).
- Streamlit "War Room" dashboard.
- Telegram bot + encrypted audit log.
- ChaCha20 structured log encryption.
- HKDF key rotation / Ratchet.
- Chain integration (Cosmos SDK modules).
- IPFS cold storage for checkpoints.
- zk-SNARK circuits for PoC.

Anything on this list that *feels* urgent this sprint is a sign of
scope drift — push back.

## 6. Risks and mitigations

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| NAT hole-punching fails on common ISPs | Medium | High | Rendezvous VPS fallback in Phase D track 2 |
| `pqcrypto-dilithium` crate ABI surprises | Low | Medium | Wrap behind a `traits::Signer` interface so the impl is swappable |
| gRPC/UDS portability (Windows) | Medium | Low | v0.1.0 is Linux-only; Windows support is v1.0.0 |
| Julia/Python determinism breaks across OS | Low | High | Pin `Manifest.toml` aggressively; smoke test `scientific_hash` across Ubuntu LTS versions before Phase E |
| Solo developer bandwidth | High | High | Phases are independent demos — partial sprint (A+B+C) is still a meaningful release |

## 7. Executive decisions — RATIFIED 2026-04-21

The three micro-questions that gate Phase A are closed. Project standard.
Reopening requires a documented architectural change request.

1. **Rust toolchain pin — MSRV 1.75.** `rust-toolchain.toml` pinned at
   1.75.0. Stable channel only; no nightly features. Rationale: covers
   `pqcrypto-dilithium` 0.5.x and gives cryptographic reproducibility
   starting from the compiler itself.
2. **gRPC library — `tonic` + `prost`.** Pure-Rust stack; no C/C++
   toolchain dependency. First-class UDS support, which is non-
   negotiable for the local IPC bridge between Python Sentinel and
   Rust Santuario.
3. **Signature scope — `security.payload_hash` only.** Already the
   SHA-256 canonical fingerprint of the payload body, so signing it is
   equivalent to signing the entire content. Keeps the signed object
   at 32 bytes. Dilithium-5 produces a 4595-byte signature; avoiding
   unnecessary payload duplication is vital for UDP gossip fluidity.

## 8. Release checklist

When all phase demos are green:

- [ ] Bump `aeterna.toml → sentinel_version` to `0.1.0`.
- [ ] Flip `aeterna.toml → [santuario] enabled = true`.
- [ ] Tag `v0.1.0-echelon` on the main branch.
- [ ] Update `README.md` roadmap table — v0.1.0 row to ✅.
- [ ] Run final cross-host smoke on two machines; attach log to the
      release notes.
- [ ] Sign the release commit with the newly-deployed Dilithium-5 key.

## 9. What comes after

v0.2.0 "Custos" opens with *all* the security work that was explicitly
deferred here: seccomp isolation, AES-256-GCM vault with TPM2-sealed
keys, critic loop, integrity audit, migration thresholds, Streamlit
dashboard, Telegram operator bot, encrypted audit log. It assumes that
by then there is already real peer traffic on the wire to protect.

---

*See also:* [`docs/AGP-v1.md`](./AGP-v1.md) for the payload format,
[`docs/CONSENSUS.md`](./CONSENSUS.md) for the stratified pipeline this
sprint operationalizes at Levels 0–2.
