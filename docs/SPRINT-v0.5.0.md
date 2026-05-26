# Sprint Plan -- AETERNA v0.5.0 "Consensus"

> **"The trail has been protected; now it must travel."**

Companion to [`SPRINT-v0.4.0.md`](./SPRINT-v0.4.0.md). Read that first --
this sprint takes the confidentiality envelope Sigillum closed and
lifts it onto a federated substrate, so a single Guardian's verdicts
can be cross-checked against, and ratified by, the network.

---

## 1. Sprint goal (one sentence)

Stand up the AETERNA AppChain skeleton (Cosmos SDK + CosmWasm) so a
Guardian can mint an Identity Soulbound Token, submit a Dilithium-5
signed AGP-v1 block to an on-chain oracle, and ship its encrypted
audit log off-host -- without weakening any v0.4.0 confidentiality
invariant.

---

## 2. Scope rationale

Custos (v0.2.0) made the node self-defending. Oculus (v0.3.0) made it
self-observable. Sigillum (v0.4.0) made it self-confidential. All
three succeed at the *single-node* boundary -- and as a consequence,
the AETERNA Guardian now produces a clean, signed, time-ordered
stream of verdicts that no peer can yet read, dispute, or ratify.

That stream is the chain's input. Consensus is the layer that turns
a single Guardian's *opinion* (Dilithium-5 signed AGP-v1 block) into
a federated *fact* (CosmWasm-validated, on-chain Trust Score
contribution). The Sentinel has been ready for this since v0.0.1;
the chain stub at `chain/README.md` has been ready since the same
day. v0.5.0 finally builds it.

The scope is deliberately narrow: chain *skeleton*, not chain
*complete*. The four-level consensus pipeline of
[`CONSENSUS.md`](./CONSENSUS.md) is implemented at Levels 0 and 1
only -- Sybil-resistant admission via Identity SBT plus signature
verification of the PoUW payload. Level 2 (zk-SNARK Proof of
Cognition) and Level 3 (PoI retrievability pings) are pushed to
v0.6 "Probatio" because each requires a dedicated cryptographic
engineering pass that does not fit alongside chain bring-up.

The remote log shipper (Phase D) is the v0.5.0 mirror of the v0.4
Phase A audit-log encryption: same envelope format, same per-segment
HKDF subkeys, but the segments live on an operator-controlled
endpoint instead of the local disk. This is the v0.5.0 piece that
finally satisfies the v0.4 §5 deferred item "Remote log shipper".

Consensus does not introduce new attack surfaces on the signing
path. The signer continues to refuse to sign until vault is
unsealed, the critic accepts, and Custos is green. The chain merely
ratifies what the signer already produced; if the signer is
suspended, the chain sees no new blocks from this node, and that is
the correct behaviour. Same Custos invariant as Sigillum.

---

## 3. Phased deliverables

### Phase A -- Cosmos SDK `x/guardian` module (Identity SBT)

`chain/` ceases to be a stub. From v0.5.0 it hosts a real Cosmos SDK
v0.50 ("Eden") application binary, `aeternad`, with one custom
module: **`x/guardian`**.

**Identity SBT mint flow**:

1. Operator runs `santuarioctl chain register` on a Guardian node.
2. The CLI fetches the signer's Dilithium-5 public key
   (`santuarioctl identity show` analogue, but for the Dilithium-5
   keystore rather than the v0.4 X25519 ratchet identity).
3. The CLI assembles a `MsgMintGuardianSBT` message containing:
   - the Dilithium-5 pubkey
   - the SHA-256 of the locally-pinned `MANIFESTO.md`
   - the TPM2 attestation bundle from the Custos vault
   - the operator's accepted-clauses bitset (AGPLv3 + Prometeo)
4. The chain validator on the other end (`x/guardian.MsgServer`)
   verifies the Dilithium-5 signature over the manifesto hash,
   validates the attestation bundle if `min_trust_level_boot >=
   guardiano`, and mints a non-transferrable token bound to the
   Guardian's Cosmos address.

**Why Soulbound (non-transferrable)**: a reputation token that can
be sold to a malicious operator is worthless. The `x/guardian`
module rejects every `MsgTransfer` against the SBT collection at
the keeper layer.

**Genesis bootstrap**: the genesis file (`chain/scripts/genesis.json`)
pre-mints two SBTs -- one for Prometheus-1, one for Prometheus-2 --
so the network has a quorum at block 0 and a single-validator chain
can pass governance proposals during devnet bring-up.

**Custos extension**: the integrity baseline in
`santuario/integrity/baseline.json` is extended to include the
chain's genesis hash. A drift between the local pinned genesis and
the chain's actual genesis is an alpha alert.

### Phase B -- CosmWasm `aeterna_oracle` contract

Sitting on top of `x/guardian` is a single CosmWasm contract,
**`aeterna_oracle`**, that owns the AGP-v1 block submission /
validation flow. Path: `chain/contracts/aeterna_oracle/`.

**`ExecuteMsg`** surface:

```rust
#[cw_serde]
pub enum ExecuteMsg {
    /// Submit a Dilithium-5 signed AGP-v1 block. The contract
    /// verifies (Level 0 admission, Level 1 PoUW signature) and on
    /// success updates the submitter's Trust Score state. Failed
    /// submissions are silently dropped at the contract layer;
    /// repeated failures from the same SBT trip a registry-level
    /// rate-limit (5 failed submits per 1024 blocks).
    SubmitBlock { block_b64: String, signature_b64: String },

    /// Operator-initiated recovery: requests a fresh challenge that
    /// the operator then signs with their Dilithium-5 key, mirroring
    /// the v0.2.0 `santuarioctl resume` flow but on-chain so a
    /// peer-observed compromise can be cleared without trusting the
    /// suspended node's own ledger.
    RequestReEntryChallenge {},
}
```

**`QueryMsg`** surface:

```rust
#[cw_serde]
pub enum QueryMsg {
    /// Returns the validator's current Trust Score per the formula
    /// in CONSENSUS.md, computed from the on-chain submission
    /// history. v0.5 weights only the ω₁ (Sybil) and ω₂ (PoUW)
    /// terms; ω₃ (PoC) and ω₄ (PoI) are zeroed and explicitly
    /// labelled "Probatio" in the contract source.
    TrustScore { guardian: String },

    /// Lists the n most recent blocks accepted by the contract,
    /// for War Room rendering and observer UIs.
    RecentBlocks { limit: u32 },
}
```

**Validation pipeline** inside `aeterna_oracle.SubmitBlock`:

1. Lookup the submitter's Identity SBT via `x/guardian.QueryServer`.
   No SBT → reject with `Err::NotAGuardian`.
2. Deserialize the AGP-v1 block; check `protocol_version == "AGP-v1"`.
3. Verify the Dilithium-5 signature over the canonical block hash
   (same input the signer fed into Dilithium-5 in v0.2.0).
4. Reject if `block.timestamp_utc` is more than ±300 s from the
   chain's BFT clock (anti-replay across long-stalled nodes).
5. On success, increment the submitter's `pouw_blocks_accepted_total`
   counter in the contract's state, and emit an `Event::BlockAccepted`
   that downstream IBC consumers can subscribe to.

**zk-SNARK fallback**: the Level 2 PoC verification slot in the
contract is filled with a `naive_reverify` placeholder that simply
trusts the signature for v0.5.0. The placeholder is gated behind a
feature flag `pow_naive_reverify` so v0.6's zk-SNARK circuits can
swap in without contract migration.

### Phase C -- Two-validator local devnet + IBC scaffold

`chain/scripts/devnet.sh` brings up a 2-node local chain
(Prometheus-1 + Prometheus-2 each as Cosmos SDK validators) and
opens an IBC channel against the cosmoshub Theta testnet.

**Devnet contents**:

```
chain/scripts/
├── devnet.sh                # 2-validator local cluster
├── genesis.json             # pre-minted SBTs for the two validators
├── config-prometheus-1.yaml # validator key paths, peer list
├── config-prometheus-2.yaml # mirror of the above
└── ibc-channel.sh           # opens IBC channel + transmits an SBT-attestation packet
```

The IBC scope is *intentionally minimal*: a single channel to a
mock hub that responds with a fixed acknowledgement, sufficient to
prove the channel handshake completes and the `Event::BlockAccepted`
emitted by the oracle contract on chain A is observable as an IBC
packet on chain B. Full cross-chain SBT reputation reads (the v0.0.1
README's "IBC-native SBT" feature) are v0.6 work.

**Operator path** for the devnet:

```powershell
.\bootstrap.ps1 -ChainEnabled       # new flag, see Phase F
santuarioctl chain register         # mint our own SBT
santuarioctl chain status           # 2 validators, height > 0
santuarioctl chain submit-block ./agp-test.json
santuarioctl chain trust-score      # rendered TS, ω₁+ω₂ terms
```

### Phase D -- Remote log shipper (`santuario-shipper`)

New workspace member 9: **`santuario-shipper`**. Pushes encrypted
`.sigillum` segments from the local audit-log directory to an
operator-controlled remote endpoint.

**Architecture**:

```text
santuario-integrity  ──► .sigillum segments (local, Phase A)
                              │
                              ▼
                  santuario-shipper (this crate)
                              │  HTTP POST, ratchet-wrapped
                              ▼
       operator-controlled remote endpoint
       (e.g. S3-compatible bucket, self-hosted Caddy)
```

**Transport**: HTTP POST over TLS to a single URL. The shipper's
sole responsibility is to deliver bytes; the remote endpoint's
authentication and storage policy are operator concerns. The HTTP
body is the raw `.sigillum` segment wrapped in a v0.4 ratchet
session frame for an additional confidentiality layer above TLS.

**State machine**:

```text
              ┌───────────────┐
              │  Idle (no     │
              │  pending      │◀──── poll dir every 30 s
              │  segments)    │
              └───────────────┘
                      │ new finalized .sigillum detected
                      ▼
              ┌───────────────┐
              │  Pushing      │── HTTP POST → 2xx ─► mark .pushed
              │  segment N    │── HTTP error  ─► back-off (exp)
              └───────────────┘
                      │
                      ▼
              ┌───────────────┐
              │  Verifying    │── HEAD on remote URL, compare
              │  remote       │   sha256 → match: success
              │               │   mismatch: re-push N times then alert
              └───────────────┘
```

**Cesura netta with Sigillum local logs**:

- Local segments remain the source of truth. The shipper NEVER
  deletes a local segment on push success -- operator-controlled
  rotation/archival is a separate concern.
- A shipper failure does NOT suspend the signer. The signer's
  signing-path invariant is untouched; the audit log continues
  to write locally.
- The shipper authenticates the remote endpoint via a separate
  X.509 cert pin (configured in `aeterna.toml [shipper]`). A
  pin mismatch is an alpha alert (it implies someone is MITMing
  the operator's chosen endpoint).

**Cargo.toml** (new workspace member):

```toml
[package]
name        = "santuario-shipper"
description = "v0.5 Sigillum remote log shipper -- encrypted .sigillum segment push to operator-controlled off-host storage."

[dependencies]
santuario-cipher   = { path = "../cipher" }
santuario-ratchet  = { path = "../ratchet" }
reqwest            = { workspace = true, features = ["rustls-tls"] }
tokio              = { workspace = true, features = ["full"] }
# ... other shared deps
```

### (Phase E -- explicitly cut)

Consistent with the v0.4 convention: Phase E is skipped. The next
phase letter is F.

The cut item this sprint is the **`x/oracle` Cosmos SDK module**
(distinct from the `aeterna_oracle` CosmWasm contract). The
SDK-module version would have given us native chain-state access
patterns but would also have required a much bigger Go codebase.
The CosmWasm contract path delivers the same operator-facing
acceptance (Level 0+1 block validation) with one-fifth the lines
of code. `x/oracle` becomes a v0.6 "Probatio" item where the
zk-SNARK PoC circuit verification can be plugged into native
chain state more cleanly.

### Phase F -- Operator UX polish + runbook update

**`santuarioctl` extensions**:

- `santuarioctl chain status` -- chain reachable, current height,
  validator set, this node's SBT id (if minted).
- `santuarioctl chain register` -- mint the local node's Identity
  SBT and wait for the next epoch to be admitted to the validator
  set.
- `santuarioctl chain submit-block <path>` -- submit a local
  AGP-v1 block (read from disk) via the `aeterna_oracle` contract.
- `santuarioctl chain trust-score [--guardian <id>]` -- query the
  contract for this node's (or another's) current TS.
- `santuarioctl ship status` -- show pending segments, last push
  time, remote endpoint URL + pin fingerprint.
- `santuarioctl ship deploy [--url <url>] [--pin <sha256>]` --
  one-shot push (operator manual flush) or persist config to
  `aeterna.toml [shipper]`.
- `santuarioctl ship verify <segment-id>` -- HEAD the remote URL
  for a given segment and compare the SHA-256 against the local
  copy; success means the segment has durable off-host storage.

**War Room sidebar** gains a "Chain" widget: height, validator
count, last block accepted ts, plus a "Shipper" widget with the
last push status and pending count.

**Telegram bot** gets two new alert kinds:
`chain_disconnected` (chain reachable for > 10 min returns to
unreachable) and `shipper_push_failed` (3 consecutive push failures
on the same segment).

**`docs/OPERATOR-RUNBOOK.md` additions**:

- New section: **§14 Chain operator basics** -- bringing up the
  devnet, minting your SBT, joining as a validator, submitting your
  first block, reading your TS.
- New section: **§15 Remote log shipper** -- configuring an endpoint,
  verifying a pushed segment, recovering from a push backlog,
  rotating the pin on cert renewal.
- Update **Pre-flight commands** in §1 to include `santuarioctl
  chain status` and `santuarioctl ship status`.
- Update **Severity legend** in §2 with two new entries:
  `chain_disconnected`, `shipper_push_failed`.

**`bootstrap.ps1`**:

- New parameter `-ChainEnabled` -- when set, launches `aeternad`
  alongside the rest of the Tripod. Otherwise the bootstrap is
  identical to v0.4 (so existing dev flows are not disrupted).
- New parameter `-ShipperEndpoint <url>` -- sets
  `AETERNA_SHIPPER_ENDPOINT` in the child env before launching the
  signer; the signer's shipper companion thread reads it.
- Banner additions: `chain: connected (h=<height>) / disconnected`
  and `shipper: pushing (N pending) / idle`.

**`aeterna.toml`** new sections:

```toml
[chain]
enabled                 = true
node_endpoint           = "tcp://127.0.0.1:26657"       # Cosmos RPC
validator_key_path      = "./chain/keys/validator.pqc"  # Dilithium-5
trust_level_min         = "guardiano"                    # for SBT mint
ibc_hub_endpoint        = "tcp://theta-testnet:26657"   # IBC channel target
ibc_channel_id          = "channel-0"                    # populated after handshake

[shipper]
enabled                 = false                          # opt-in, AC #4
endpoint_url            = ""                             # e.g. "https://archive.example.com/segments"
endpoint_pin_sha256     = ""                             # cert pin (64 hex chars)
poll_interval_seconds   = 30
back_off_seconds        = 60
max_retries_per_segment = 5
```

`[chain].enabled = true` is the default for new installs; existing
v0.4 nodes can keep it false and run Sigillum-only.
`[shipper].enabled = false` is the default (opt-in -- the
operator must explicitly point at a remote endpoint and pin it
before any bytes leave the host).

**Custos integrity baseline** is extended to include the chain
genesis hash and (when `[shipper].enabled`) the
`endpoint_pin_sha256`. Drift on either triggers an alpha alert.

---

## 4. Acceptance criteria (sprint-level)

All simultaneously for v0.5.0 to ship:

1. `aeternad` (the new Cosmos SDK binary) compiles, starts, mines
   blocks at 6 s per block, and exposes the standard Cosmos RPC
   surface on `:26657`.

2. `santuarioctl chain register` mints an Identity SBT for the
   local Guardian and the SBT is observable via
   `aeternad query guardian sbt <address>`.

3. `santuarioctl chain submit-block <agp-v1.json>` posts a
   Dilithium-5 signed block to the `aeterna_oracle` contract; the
   contract emits an `Event::BlockAccepted` and the submitter's
   `pouw_blocks_accepted_total` increments.

4. Two `aeternad` validators (Prometheus-1, Prometheus-2) run
   simultaneously on `chain/scripts/devnet.sh` and reach IBC
   handshake completion against a mock hub (`channel-0` state =
   `OPEN`).

5. `santuarioctl ship deploy --url https://...` pushes the latest
   finalized `.sigillum` segment to the configured endpoint; a
   subsequent `santuarioctl ship verify <segment-id>` succeeds.

6. A shipper push failure does NOT suspend the signer or block
   signing -- verified by injecting a 503 from the remote endpoint
   while issuing `santuarioctl audit --accept` in parallel.

7. The OPERATOR-RUNBOOK has new §14 (Chain operator basics) and
   §15 (Remote log shipper), each following the
   Signal -> Diagnosis -> Recovery -> SLO template.

8. `promtool check metrics` against the exporter still passes; two
   new metrics are present: `santuario_chain_block_height` (gauge)
   and `santuario_shipper_segments_pushed_total` (counter).

9. `aeterna.toml [chain] enabled = true` is the default for new
   installs but existing v0.4 nodes upgrade cleanly with
   `[chain] enabled = false`; either path passes the Custos
   integrity baseline.

10. No new code in the *signing* path. `Sign / Verify / Resume`
    handlers untouched. No changes to Sigillum envelopes -- the
    ratchet, the audit log, and the gossip session keys are
    bit-identical to v0.4.0.

---

## 5. Out of scope -- deferred to v0.6 or later

Reminder for the periphery chats. Any suggestion on this list this
sprint is scope drift.

**v0.6.0 "Probatio" -- consensus completeness** owns:

- `x/oracle` native Cosmos SDK module (replaces the v0.5 CosmWasm
  contract on the hot path)
- Level 2 zk-SNARK Proof of Cognition circuits via `arkworks`
- Level 3 PoI retrievability ping protocol + Merkle proofs
- IPFS cold storage for checkpoints and model weights
- Multi-operator quorum (Shamir's Secret Sharing for the BIP-39
  master seed)
- Full stealth migration on gamma trip (depends on isolation
  hardening; gVisor is v1.0)
- `x/trustscore` module: replaces the contract-side TS computation
  with a chain-native module so cross-chain TS reads via IBC are
  trivial

**v1.0.0 "Sovereign" -- production hardening** owns (unchanged
from v0.4):

- gVisor / Firecracker isolation replacing seccomp
- Hardware key support (YubiKey, WebAuthn) replacing the BIP-39 file
- Post-quantum re-key channel (Kyber-1024 in the handshake too)
- Bitcoin `OP_RETURN` anchoring via `x/anchor` (the module skeleton
  may land in v0.6 but the actual Bitcoin transport is v1.0)
- Windows and macOS first-class support
- Formal external security audit
- Public mainnet

---

## 6. Risks and mitigations

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Cosmos SDK v0.50 churn between sprint start and end | medium | medium | Pin the exact tag (`v0.50.x`) in `chain/go.mod`; document upgrade path in §14 of the runbook. |
| CosmWasm contract panics in production -> stuck chain | low | catastrophic | Property-based tests on `aeterna_oracle.SubmitBlock` covering all `Err` variants; mandatory `Result<T, ContractError>` returns; the contract NEVER calls `panic!` or `unwrap()` on user input. |
| IBC handshake against the mock hub fails -> devnet stalls | medium | low | The mock hub is itself part of `chain/scripts/devnet.sh` and uses a fixed scripted response; if the real Theta testnet is unavailable, the mock keeps the devnet self-contained. |
| Shipper remote endpoint compromise leaks ciphertext | low | medium | Cert pin in `aeterna.toml [shipper]`; pin drift is an alpha alert; ciphertext alone (without the BIP-39 seed) reveals nothing per Sigillum Phase A invariant. |
| Shipper backlog grows unbounded if endpoint stays down | medium | low | `max_retries_per_segment = 5` then mark as `.failed` and alert; the local segments remain readable on disk, so a multi-day outage costs durability, not visibility. |
| Genesis pre-mint of SBTs creates a network governance attack vector | low | high | Hard-code the two genesis SBTs as `revocable_by_governance = false`; the chain can issue NEW SBTs to new operators but cannot un-mint Prometheus-1/2; documented in §14 runbook. |
| `santuarioctl chain register` fails silently if signer keystore is sealed | medium | low | Same gate as the v0.2 signing path: refuse to call register until vault is unsealed; surface as `chain=blocked_vault_sealed` in `santuarioctl status`. |
| Operator confuses Dilithium-5 keystore with v0.4 X25519 ratchet identity | medium | low | `santuarioctl chain register` documents the key file used (`./santuario/vault/keystore.dilithium`) and the runbook §14 calls out the distinction explicitly. |
| Trust-Score computation drift between contract version and CONSENSUS.md spec | low | medium | The contract pins the spec hash in a `pub const CONSENSUS_SPEC_SHA256: &str` constant; CI fails if `docs/CONSENSUS.md` is modified without bumping the constant. |

---

## 7. Executive decisions (resolved)

These were the open design questions before sprint kickoff. All
five are now closed:

1. **Cosmos SDK vs Substrate vs custom chain**: Cosmos SDK v0.50.
   Lock-in confirmed by `chain/README.md` (2026-04-20). IBC support
   is the deciding factor for v0.6 cross-chain SBT reads.

2. **CosmWasm contract vs Cosmos SDK module for `aeterna_oracle`**:
   CosmWasm contract for v0.5.0. The native SDK module
   (`x/oracle`) becomes a v0.6 "Probatio" item once the zk-SNARK
   circuits land -- the CosmWasm path lets us iterate the
   validation pipeline without recompiling the chain.

3. **IBC hub for v0.5.0 testnet**: cosmoshub Theta testnet for the
   public flavour, plus a local mock hub baked into `devnet.sh` so
   the sprint demos are reproducible regardless of Theta availability.

4. **Remote log shipper transport**: HTTP POST over TLS, with a
   v0.4 ratchet-wrapped body for defence in depth. S3-compatible
   buckets work; the operator can also self-host a Caddy reverse
   proxy. Cesura netta with the gossip layer -- the shipper does
   not relay through other Guardians.

5. **Gasless network funding model**: Identity SBT holders submit
   blocks without paying gas. The chain enforces this at the
   antehandler level: a `MsgExecuteContract` against `aeterna_oracle`
   from an SBT-holding address is exempted from the gas meter.
   Future spam mitigation is rate-limiting at the contract layer
   (5 failed submits per 1024 blocks per SBT), NOT gas fees.

---

## 8. Release checklist

When all phase demos are green:

- [ ] Bump `aeterna.toml -> sentinel.sentinel_version` to `0.5.0`.
- [ ] Add `[chain]` and `[shipper]` sections to `aeterna.toml` with
      safe defaults populated.
- [ ] Tag `v0.5.0-consensus` on the main branch (signing flow per
      v0.4-era tagging convention; signed via `aeternad keys`
      becomes meaningful once the chain is up).
- [ ] Update `docs/OPERATOR-RUNBOOK.md` with §14 "Chain operator
      basics" and §15 "Remote log shipper".
- [ ] Update README roadmap table -- v0.5.0 row to ✅, add v0.6.0
      "Probatio" row.
- [ ] Update Grafana dashboard (`operations/grafana/aeterna-overview.json`
      if it now exists) with two new panels: chain block height,
      shipper push rate.
- [ ] Update Prometheus exporter catalog with the two new metrics.
- [ ] Update `bootstrap.ps1` banner to include `chain:` and
      `shipper:` fields.
- [ ] File a public postmortem on operator-UX surprises encountered
      during the first SBT mint + IBC handshake flow.

---

## 9. What comes after

**v0.6.0 "Probatio"** -- consensus completeness. Native
`x/oracle` SDK module with zk-SNARK PoC verification (`arkworks`
circuits), Level 3 PoI retrievability pings, IPFS cold storage,
multi-operator Shamir SSS, `x/trustscore` for cross-chain reads.
The chain ratifies; this sprint makes it *prove*.

**v1.0.0 "Sovereign"** -- production hardening. Unchanged from
v0.4's after-list: external audit, gVisor/Firecracker, hardware
keys (YubiKey + WebAuthn) replacing the BIP-39 file, post-quantum
re-key channel (Kyber-1024 in the handshake), multi-OS, formal
threat model, Bitcoin `OP_RETURN` anchoring, public mainnet.

---

*See also:*

- [`docs/SPRINT-v0.4.0.md`](./SPRINT-v0.4.0.md) -- prior sprint
  whose Sigillum envelope this sprint federates
- [`docs/CONSENSUS.md`](./CONSENSUS.md) -- the four-level pipeline
  whose Levels 0+1 v0.5 implements
- [`docs/AGP-v1.md`](./AGP-v1.md) -- block payload format the
  `aeterna_oracle` contract validates
- [`docs/OPERATOR-RUNBOOK.md`](./OPERATOR-RUNBOOK.md) -- runbook
  Phase F extends with chain + shipper sections
- [`chain/README.md`](../chain/README.md) -- chain stub with the
  architectural lock-ins from the 2026-04-20 orchestrator chat
- [`ETHICS.md`](../ETHICS.md) -- Prometheus Clause that the
  `aeterna_oracle` contract refuses to ratify any block against
