# Sprint Plan — AETERNA v0.2.0 "Custos"

**Status:** proposed by the Terminale di Comando on 2026-04-21.
**Predecessor:** v0.1.0 "Echelon" — two-node P2P with signed AGP blocks.
**Successor target:** v0.3.0 "Oculus" — operational observability (War Room,
Telegram operator bot, encrypted audit log).

---

## 1. Sprint goal (one sentence)

> **Turn the Santuario from a signing stub into a sovereignty-grade kernel
> that refuses to sign when integrity, isolation, or axioms are violated.**

The v0.1.0 Santuario signs anything the Sentinel hands it. The v0.2.0
Santuario is the adult in the room: it verifies the subprocess producing
the result is sandboxed, the host is still intact, and the content does
not violate the Manifesto — and only then produces a Dilithium-5 signature.

If at the end of this sprint you cannot deliberately corrupt a Julia output,
spoof a vault checkpoint, or ask the LLM to produce dual-use content, and
observe the Santuario **refuse to sign** in every case, the sprint has
failed regardless of how much code was written.

## 2. Scope rationale

v0.1.0 answered "does the protocol work across the wire?" v0.2.0 answers
"is the node hard enough to operate in a hostile network?" Three threat
models drive the scope:

1. **Compromised workload.** An attacker poisons training data or
   patches `zmq_server.jl` at runtime to forge a favorable
   `scientific_hash`. Defense: seccomp-bpf around the Julia engine +
   integrity audit loop (α threshold).
2. **Filesystem tampering.** An attacker mutates the checkpoint vault
   or the Manifesto to bypass the boot gate. Defense: AES-256-GCM vault
   with TPM2-sealed master key + file-system integrity monitor.
3. **Manifesto circumvention.** The Sentinel submits a block whose
   semantic content violates the Prometheus Clause — either through a
   bug or because an LLM downstream was compromised. Defense: critic
   loop inside the Santuario that runs deterministic axiom checks
   before the signer emits a signature.

Everything not mapped to one of those three threats is deferred to later
releases. In particular, **operator UX** (Streamlit, Telegram) and **log
confidentiality** (ChaCha20) are v0.3.0 territory — they make the node
more *usable*, not more *trustworthy*, and this sprint is about trust.

## 3. Phased deliverables

Five phases, binary pass/fail demos. Do not start phase N+1 until phase
N's demo is green.

### Phase A — Vault: AES-256-GCM with TPM2-sealed master

Replace the v0.1.0 file-backed keystore with a real encrypted vault. The
master key is sealed with TPM2 when available; otherwise the node
degrades to `osservatore` trust tier (passive, non-signing, non-staking).

| Deliverable | Path | Owner |
|---|---|---|
| Vault trait + AES-256-GCM impl | `santuario/vault/src/lib.rs` | Rust |
| TPM2 sealing backend (via `tss-esapi`) | `santuario/vault/src/tpm2.rs` | Rust |
| File-backed fallback (non-signing tier only) | `santuario/vault/src/file.rs` | Rust |
| Envelope encryption — per-checkpoint DEKs wrapped by master | `santuario/vault/src/envelope.rs` | Rust |
| Vault CLI — seal, unseal, rotate DEK, list | `santuario/vault/src/bin/vaultctl.rs` | Rust |
| Tamper test — flip a byte in a checkpoint, expect hard failure | `santuario/vault/tests/tamper.rs` | Test |

**Phase A demo:** the RTX 5070 host seals a fresh master key in TPM2 at
first boot; the Sentinel writes a checkpoint that survives a reboot and
fails loudly if manually edited on disk.

### Phase B — Process isolation: seccomp-bpf around workloads

The Julia scientific engine and any LLM subprocess are launched under a
strict seccomp-bpf allowlist. The Santuario refuses to sign a result
whose producer PID is not attested against the active policy.

| Deliverable | Path | Owner |
|---|---|---|
| Seccomp policy definitions per subprocess class | `santuario/isolation/policies/*.bpf` | Rust |
| Launcher that execve's children under policy | `santuario/isolation/src/launcher.rs` | Rust |
| PID attestation — signer refuses unknown PIDs | `santuario/signer/src/attestation.rs` | Rust |
| Julia startup audit — log every syscall denied at cold start | `santuario/isolation/tests/julia_smoke.rs` | Test |
| Sentinel integration — `bootstrap.sh` now invokes launcher | `bootstrap.sh` | Ops |

**Phase B demo:** run the existing `scripts/smoke_test.py`; all six task
kinds succeed under the seccomp policy. Then manually patch
`scientific/zmq_server.jl` to call `Sys.exec("ls")` and watch the seccomp
filter kill the process *and* the Santuario refuse to sign the pending
block.

### Phase C — Critic loop: axiom enforcement at sign time

The three deterministic checks from the Nucleo's Cognitive Trivium
(reflexive, symbolic, axiomatic) run inside the signer before every
Dilithium-5 signature. If any check fails, the signer returns an
`AxiomViolation` error instead of a signature. The critic is pure Rust —
no LLM shelling.

| Deliverable | Path | Owner |
|---|---|---|
| Critic trait — `check(payload) -> Result<(), Violation>` | `santuario/critic/src/lib.rs` | Rust |
| Reflexive check — payload hash actually matches content | `santuario/critic/src/reflexive.rs` | Rust |
| Symbolic check — `parametri` schema conformance per AGP-v1 §3 | `santuario/critic/src/symbolic.rs` | Rust |
| Axiomatic check — Prometheus Clause rule engine (ETHICS.md §2) | `santuario/critic/src/axiomatic.rs` | Rust |
| Adversarial corpus — 50 poisoned payloads, signer must reject all | `santuario/critic/tests/corpus/*.json` | Test |

**Phase C demo:** feed the adversarial corpus through the signer. 50/50
violations rejected with the correct `Violation` variant. Zero false
positives on a parallel corpus of 50 legitimate blocks.

### Phase D — Integrity audit loop (α threshold)

Hourly SHA-256 sweep across the critical file set (Manifesto, aeterna.toml,
Julia Manifest, Rust binaries, vault manifest). Mismatch triggers (a) a
gossip warning to the network, (b) suspension of signing until an operator
unseals the node, (c) an entry in the audit log.

| Deliverable | Path | Owner |
|---|---|---|
| File set manifest — declared in `aeterna.toml → [integrity]` | `aeterna.toml` | Ops |
| Periodic audit task — hourly by default (α) | `santuario/integrity/src/audit.rs` | Rust |
| `integrity_alert` gossip message kind (signed) | `core/gossip.py` | Python |
| Signer self-suspend — refuse all sign requests when alert active | `santuario/signer/src/state.rs` | Rust |
| Audit log append-only sink | `santuario/integrity/src/log.rs` | Rust |

**Phase D demo:** modify `MANIFESTO.md` on disk while the node runs.
Within 60 minutes (or instantly via `santuarioctl audit --now`) the node
gossips an `integrity_alert`, the signer refuses all subsequent requests,
and the audit log records the offending SHA-256 delta.

### Phase E — β and γ thresholds: degraded-mode triggers

Operational triggers that shift the node into degraded state without the
full stealth-migration machinery (that's v1.0).

| Deliverable | Path | Owner |
|---|---|---|
| CPU stress monitor — 10-minute window, 90% abort (β) | `santuario/integrity/src/cpu.rs` | Rust |
| Port-scan detector — 3 unsolicited scans = γ trip | `santuario/integrity/src/portscan.rs` | Rust |
| Degraded mode — keep verifying, stop signing new work | `santuario/signer/src/state.rs` | Rust |
| Recovery protocol — operator-signed un-suspend token | `santuario/signer/src/recovery.rs` | Rust |

**Phase E demo:** `stress --cpu 8 --timeout 15m` trips β and puts the node
in degraded mode; `nmap -sS` from a peer trips γ; both events appear in
the audit log and the Sentinel logs a clear recovery instruction.

## 4. Acceptance criteria (sprint-level)

All simultaneously for v0.2.0 to ship:

1. `bootstrap.sh` unseals the vault via TPM2 (or degrades to
   `osservatore` with a loud warning) before starting any other process.
2. Every v0.1.0 smoke test still passes *under seccomp policy*, no
   regressions in the six task kinds.
3. The adversarial critic corpus (50 poisoned payloads) is 100% rejected;
   the clean corpus is 100% accepted.
4. A manual file tamper trips the α audit and suspends signing within
   the configured window.
5. A CPU stress test trips β and a port scan trips γ, both with correct
   audit log entries.
6. Running `santuarioctl status` on a healthy node prints: `vault=sealed
   seccomp=active critic=armed integrity=green signer=ready`.
7. `docs/CONSENSUS.md` is updated with the Santuario's role in Levels 0
   and 2 of the pipeline.
8. Zero new Python code in the signing path — all additions are Rust.

## 5. Out of scope — deferred to v0.3.0 or later

Reminder for the periphery chats. Any suggestion on this list this
sprint is scope drift.

**v0.3.0 "Oculus" — operational observability** owns:

- Streamlit "War Room" dashboard.
- Telegram operator bot.
- ChaCha20 structured-log encryption.
- HKDF / Double-Ratchet key rotation.
- Grafana/Prometheus metrics exporter.

**v0.5.0+ — consensus & storage** owns:

- Cosmos SDK `x/guardian` module and `aeterna_oracle` CosmWasm contract.
- IPFS cold storage for checkpoints and model weights.
- zk-SNARK PoC circuits (arkworks/bellman).
- Full stealth migration on γ trip (replaces the "degraded mode" stopgap).

**v1.0.0 "Sovereign" — production hardening** owns:

- gVisor / Firecracker isolation replacing seccomp.
- Windows and macOS support.
- Formal audit by an external security firm.

## 6. Risks and mitigations

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Consumer motherboards with TPM2 disabled in BIOS | **High** | High | File-backed fallback restricted to `osservatore` tier, documented clearly in the README Prerequisites |
| Seccomp policy accidentally kills Julia at precompile | High | Medium | Phase B includes a Julia-startup audit log so denied syscalls are visible; add them to the allowlist iteratively |
| `tss-esapi` crate flakiness across TPM2 vendors | Medium | Medium | Abstract behind the `Vault` trait; ship with Infineon + IFX SLB9670 tested, other vendors marked "experimental" |
| Critic false positives on legitimate blocks | Medium | High | Adversarial corpus + clean corpus both required to ship; each rule needs an explicit `rationale` string |
| Scope creep pulling v0.3.0 UX work forward | High | Medium | Terminale di Comando gates all PRs; anything touching `ops/dashboard/` or `ops/bot/` is auto-rejected |
| Solo-dev fatigue — this is a larger sprint than v0.1.0 | High | High | Phase A alone is shippable as v0.1.1 if the sprint stalls; each phase is an independent release candidate |

## 7. Executive decisions needed before coding starts

Five micro-questions gate Phase A. Decide now, log here, don't re-open.

1. **Seccomp policy model.** Strict allowlist (refuse unknown syscalls)
   vs permissive denylist (block only known-dangerous)?
   *Proposal:* **strict allowlist.** Permissive is cosmetic against a
   sophisticated attacker. Cost: a week of iterative allowlist tuning
   against Julia's real syscall pattern. Worth it.

2. **Vault key hierarchy.** Single master key sealed in TPM2, or
   envelope encryption with per-checkpoint DEKs wrapped by master?
   *Proposal:* **envelope encryption.** Enables future key rotation
   (v0.3.0) without re-encrypting every checkpoint. Cost: ~100 extra
   lines of Rust. Worth it.

3. **Critic loop residence.** Pure Rust deterministic rule engine, or
   LLM-assisted semantic critique?
   *Proposal:* **pure Rust in v0.2.0.** LLM-in-signer makes signing
   non-deterministic and slow — fatal for consensus latency. Semantic
   LLM critique is a v0.3.0 feature running *outside* the signing path,
   feeding a separate "suspicion score" to gossip.

4. **TPM2 fallback policy.** When TPM2 is absent, do we (a) refuse to
   boot entirely, (b) boot with reduced tier, (c) boot unchanged with a
   warning?
   *Proposal:* **(b) reduced tier.** Node comes up as `osservatore`
   (passive: can gossip, can re-execute peer blocks for PoC, cannot
   produce blocks of its own, cannot earn Trust Score). Preserves the
   network-healthy property that every laptop can participate, while
   making signing a hardware-attested privilege.

5. **Threshold default values.** α/β/γ already have defaults in
   `aeterna.toml` (60 min / 90% for 10 min / 3 scans). Ratify or revise?
   *Proposal:* **ratify as-is for v0.2.0.** Real-world telemetry from
   Phase E will inform v0.3.0 tuning.

If Christian disagrees with any of these, say so before Phase A starts.
Otherwise they're locked at Phase A kickoff.

## 8. Release checklist

When all phase demos are green:

- [ ] Bump `aeterna.toml → sentinel_version` to `0.2.0`.
- [ ] Flip `aeterna.toml → [santuario] isolation_mode` to `seccomp`
      (from the v0.1.0 default of `none`).
- [ ] Set `[vault] storage_mode = "local_encrypted"` (from `local`).
- [ ] Tag `v0.2.0-custos` on the main branch, signed by the newly-active
      Santuario signer.
- [ ] Publish the critic adversarial corpus as a public test vector
      under `tests/critic-corpus/README.md`.
- [ ] Update the README roadmap table — v0.2.0 row to ✅.
- [ ] File a public postmortem on any seccomp false-positives
      encountered during Phase B, so downstream deployments can reuse
      the allowlist.

## 9. What comes after

v0.3.0 "Oculus" — operational observability. With a trustworthy kernel
locked in, the focus shifts to the operator. Streamlit War Room,
Telegram bot for node-hardware alerts, encrypted JSON-L audit log
(ChaCha20-Poly1305 with HKDF-derived per-session keys), Prometheus
metrics exporter. No new security primitives; only human-readability of
the ones we already have.

v0.5.0+ — consensus & storage. Cosmos SDK modules, CosmWasm oracle,
IPFS cold storage, and the first zk-SNARK circuits that let us retire
naive PoC re-execution in favor of real ZK verification.

v1.0.0 "Sovereign" — production. External audit, gVisor/Firecracker in
place of seccomp, multi-OS support, and a formal threat model document.

---

*See also:*
[`docs/SPRINT-v0.1.0.md`](./SPRINT-v0.1.0.md) — prior sprint,
[`docs/AGP-v1.md`](./AGP-v1.md) — payload format this sprint protects,
[`docs/CONSENSUS.md`](./CONSENSUS.md) — pipeline this sprint hardens at
Level 0 (admission) and Level 2 (validation),
[`ETHICS.md`](../ETHICS.md) — the rules the critic loop enforces.
