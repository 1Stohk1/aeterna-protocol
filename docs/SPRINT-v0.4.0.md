# Sprint Plan -- AETERNA v0.4.0 "Sigillum"

> **"Now that the operator can read the trail, the trail itself becomes
> an attack surface."**

Companion to [`SPRINT-v0.3.0.md`](./SPRINT-v0.3.0.md). Read that first --
this sprint takes the visibility primitives Oculus exposed and wraps
them in confidentiality.

---

## 1. Sprint goal (one sentence)

Make the audit log on disk, the gossip channel between Guardians, and
the operator-endpoint communications unreadable to anyone who is not
the holder of the corresponding key, without weakening any v0.3.0
visibility primitive.

---

## 2. Scope rationale

Custos (v0.2.0) gave the node the ability to detect tampering. Oculus
(v0.3.0) gave the operator the ability to see the node's full state.
Both succeeded -- and as a consequence, the AETERNA Guardian now
generates an asset that did not exist before: a continuous, structured,
time-ordered narrative of every signing decision, every alert, every
peer interaction, every operator command.

That asset is valuable to the operator. By symmetric logic, it is
valuable to the attacker. An adversary who breaches the host -- even
read-only -- can today reconstruct the operator's incident history,
correlate Telegram chats, and replay gossip cleartext. None of that
violates Oculus's visibility contract; all of it violates the
operator's confidentiality expectation.

Sigillum closes the gap. The contract is simple: every byte that
leaves the signer's RAM and lands either on disk, on the wire, or on
the operator's terminal is encrypted, and the keys never leave the
operator's control. The Custos integrity sweep continues to verify
that the encrypted bytes are intact; Oculus continues to expose the
metadata; the difference is that an attacker with the bytes but
without the keys learns nothing.

Sigillum does not introduce new attack surfaces (no new RPCs, no new
network listeners). It re-frames existing ones with cryptographic
envelopes. The signing path is untouched -- same Custos invariant as
Oculus.

---

## 3. Phased deliverables

### Phase A -- ChaCha20-Poly1305 audit log + segment rotation

The audit log is today an append-only JSONL file at
`./logs/audit.jsonl`. From v0.4.0 it becomes a sequence of encrypted
segments under `./logs/audit/<segment-id>.sigillum`, each capped at
10 MB plaintext-equivalent.

**New crate `santuario-cipher`** (workspace member 7). Wraps the
RustCrypto stack:

- `chacha20poly1305 = "0.10"` for AEAD
- `hkdf = "0.12"` for per-segment subkey derivation
- `zeroize = "1"` (already in workspace) for key material hygiene

Public API surface:

```rust
pub struct LogSegmentWriter { /* ... */ }
impl LogSegmentWriter {
    pub fn new(dir: &Path, master_key: &MasterLogKey, segment_id: u64) -> Result<Self>;
    pub fn append(&mut self, record: &[u8]) -> Result<()>;
    pub fn rotate_if_needed(self) -> Result<Option<Self>>;
}

pub struct LogSegmentReader { /* ... */ }
impl LogSegmentReader {
    pub fn open(path: &Path, master_key: &MasterLogKey) -> Result<Self>;
    pub fn records(&mut self) -> impl Iterator<Item = Result<Vec<u8>>>;
}
```

**Per-segment subkey derivation** (HKDF-SHA256):
- `info = b"aeterna-sigillum-log-segment-v1" || segment_id_le_bytes`
- `salt = master_key_id_hash` (16-byte tag identifying which master key)
- `okm = subkey || nonce_prefix` (32 + 8 bytes)

**Per-record nonce**: `nonce_prefix || record_counter_le_bytes` (12 bytes
total). Counter is monotonic within the segment, asserted at write
time -- the writer panics on counter overflow long before crypto
catastrophe (2^32 records per segment is far above the 10 MB cap).

**Magic header** (16 bytes at every segment start):

```
SIGILLUM-v1\0\0\0\0\0
```

The reader rejects any file without this header. Plaintext
`audit.jsonl` files from v0.3.0 produce `Err(InvalidMagic)` -- cesura
netta, no auto-conversion (per executive decision §7.1).

**Custos sweep** is updated: the `[integrity] files` list now also
hashes the master_key_id of the active log writer, so a key swap is
detected as drift.

**Modify `santuario-integrity`** to write through `LogSegmentWriter`,
**modify `admin.rs`** so `Admin.TailAuditLog` decrypts on read.

### Phase B -- HKDF gossip session keys

Gossip is today plaintext UDP. From v0.4.0, every gossip frame is
sealed under a session key, and sessions rotate.

**Frame format change** (header + ciphertext):

```
0  1  2     3      4..15           16..N        N..N+16
+--+--+-----+------+---------------+-----------+--------+
|ver|kind|session_id|nonce_seq|encrypted_payload|tag(16)|
+--+--+-----+------+---------------+-----------+--------+
```

- `ver = 0x04` (Sigillum)
- `kind` = block / verdict / heartbeat / recovery_token
- `session_id` (4 bytes) = current epoch since gossip root key install
- `nonce_seq` (12 bytes) = monotonic counter per session_id
- `tag` = ChaCha20-Poly1305 authentication tag

**Session lifecycle**:

- `gossip_root_key` (256 bits) is provisioned at bootstrap, derived
  from BIP-39 seed via the same KDF as the log key (Phase C).
- A session is the tuple `(session_id, session_key)` where
  `session_key = HKDF(salt=root_key_id, ikm=gossip_root_key,
  info=b"aeterna-sigillum-gossip" || session_id_le_bytes)`.
- Sessions rotate every `session_max_seconds` (default 3600) OR every
  `session_max_messages` (default 65_535), whichever comes first.
- The receiver maintains `active_sessions: HashMap<session_id, key>`
  with a small LRU (4 entries) so out-of-order packets across a
  rotation boundary still decrypt.

**Forward secrecy property**: a captured session_key cannot decrypt
prior or subsequent sessions, because each session_key is HKDF-derived
from the root with a session-unique `info` parameter, and HKDF is
one-way.

**Mirror Rust + Python**: the Rust gossip layer (where it exists) and
the Python gossip layer in `core/gossip*.py` both read from a shared
spec doc to keep wire-level interop guaranteed.

### Phase C -- Double-Ratchet (simplified) operator endpoints

The War Room, the Telegram bot, and `santuarioctl` all talk to the
signer over loopback gRPC. Today that channel is plaintext (the
`santuario_admin_requests_total` counter is the sum of all of them).
From v0.4.0, the operator-endpoint channel runs through a simplified
ratchet.

**New crate `santuario-ratchet`** (workspace member 8). Implements
**one-way ratchet with periodic rekey** -- not the full Signal
Double-Ratchet. The reduced threat model:

- The endpoints are local or VPN'd, not asynchronous internet
- There is one operator, not a federation
- Out-of-order delivery is bounded by the loopback transport
- We accept the cost of a re-handshake on desync rather than
  implement skipped-message-key tracking

**Handshake (X3DH-lite)**:

1. Operator imports the signer's long-term identity public key
   out-of-band (one-time, at first run, via `santuarioctl identity
   import`).
2. Operator generates a one-time ephemeral keypair, sends pubkey to
   signer.
3. Signer generates a one-time ephemeral keypair, sends pubkey back.
4. Both derive `root_key = HKDF(ECDH(operator_eph, signer_id)
   || ECDH(operator_eph, signer_eph))`.
5. From `root_key`, derive an initial `session_key` via HKDF.

**Ratchet step**:

- Every `ratchet_max_seconds` (default 600) OR every
  `ratchet_max_messages` (default 1024), whichever first.
- Both ends derive `next_session_key = HKDF(salt=current_session_key,
  ikm=b"sigillum-ratchet-step", info=step_counter_le_bytes)`.
- Old key is `zeroize`'d.

**Re-handshake**:

- Either end can request a fresh handshake (e.g., after operator
  device replacement).
- During re-handshake the prior session continues to serve in-flight
  messages; new messages use the new session.
- `santuarioctl ratchet rehandshake` is the explicit operator command.

**No skipped-key tracking, no fork resolution**: if a packet arrives
out-of-order across a ratchet step, the receiver returns
`SessionDesync` and the sender must re-handshake. This is acceptable
because the loopback transport delivers in order; over real LAN the
desync window is small and recoverable.

### Phase D -- Tooling

Tooling extensions across `santuarioctl`, the War Room, and the
Telegram bot to make Phase A/B/C usable by a human.

**`santuarioctl` extensions**:

- `santuarioctl tail [--decrypt | --raw]` -- default decrypt,
  `--raw` dumps ciphertext for forensic export.
- `santuarioctl key import <bip39-phrase-file>` -- imports the 24-word
  seed and derives the master log + ratchet identity keys.
- `santuarioctl key export [--qr]` -- emits the active master key
  identifier (NEVER the key itself); `--qr` renders it as a QR for
  paper backup of the IDENTIFIER (the key bytes stay sealed).
- `santuarioctl key status` -- shows active master key id, derivation
  date, last rotation.
- `santuarioctl ratchet status` -- prints session_id, message_count,
  seconds_until_step, last_handshake_utc.
- `santuarioctl ratchet step` -- forces an immediate ratchet step.
- `santuarioctl ratchet rehandshake` -- triggers a fresh X3DH.
- `santuarioctl identity import <pub-key-file>` -- one-time import
  of the signer's long-term pubkey.

**War Room sidebar** gets a "Master Key" widget: shows key id, button
"import seed" that opens a file picker. Once imported, all subsequent
gRPC traffic from the War Room runs through the ratchet.

**Telegram bot** gets an `encrypted_payload` mode: when enabled in
`aeterna.toml`, the bot encrypts message bodies with a session key
derived from a separate Telegram-only seed. The `chat_id` in cleartext
remains visible to Telegram, but the alert content does not.
**Note**: this is *defense in depth*, not full confidentiality from
Telegram itself -- the ultimate solution is to move alerts off
Telegram (v0.5+ remote log shipper).

### (Phase E -- explicitly cut)

The remote log shipper (encrypted, append-only off-host) is **deferred
to v0.5.0 "Consensus"**. Local log confidentiality is the v0.4
contract; off-host shipping requires a different threat model
(remote operator-trusted endpoint) which is itself a v0.5 concern.

The phase letters `A B C D F` carry the gap intentionally. Future
readers seeing the missing E in this sprint should jump to v0.5's
remote-shipper section.

### Phase F -- Operator UX polish + runbook update

**`docs/OPERATOR-RUNBOOK.md` additions**:

- New section: **Key rotation** -- when to rotate the BIP-39 master
  seed, how to re-derive log + ratchet keys, how to migrate old
  segments, SLO of the rotation procedure.
- New section: **Operator key compromise recovery** -- the
  operator-side analog of the signer's `recovery_token_issued` flow.
  Pattern: how the operator notices key compromise (suspicious
  Telegram pushes from a foreign chat_id, decryption failures on
  expected segments, ratchet desync without operator action), what
  to do (revoke at signer side via santuarioctl, generate new seed,
  re-handshake).
- Update **Pre-flight commands** in section 1 to include `santuarioctl
  key status` and `santuarioctl ratchet status`.
- Update **Severity legend** in section 2 with two new entries:
  `key_rotation_due`, `ratchet_desync`.

**`bootstrap.ps1`**:

- Banner mentions `encrypted_log: yes/no`, `ratchet: active/inactive`.
- New parameter `-SeedFile <path>` -- on first launch the operator
  passes the seed file once; subsequent launches re-derive keys
  from a `key_envelope` cached at `santuario/vault/keys.envelope`.

**`aeterna.toml`** new section:

```toml
[sigillum]
log_segment_max_bytes      = 10_485_760   # 10 MiB plaintext-equivalent
log_segment_dir            = "./logs/audit/"
gossip_session_max_seconds = 3600
gossip_session_max_messages = 65_535
ratchet_max_seconds        = 600
ratchet_max_messages       = 1024
seed_file_path             = "./santuario/vault/seed.bip39"  # operator-managed
key_envelope_path          = "./santuario/vault/keys.envelope"
require_encrypted_log      = true   # cesura netta -- false is forbidden in prod
```

**Custos integrity baseline** is extended to include the
`[sigillum]` section of `aeterna.toml`, the `key_envelope` file path
content hash (not the plaintext), and the active master_key_id
fingerprint. Drift on any of these triggers an alpha alert.

---

## 4. Acceptance criteria (sprint-level)

All simultaneously for v0.4.0 to ship:

1. The audit log on disk is unreadable without the master log key.
   Verified: `head -c 16 logs/audit/000001.sigillum` shows the
   `SIGILLUM-v1` magic header followed by ciphertext entropy
   (Shannon > 7.5 bits/byte over the next 1 KiB).

2. Each gossip frame carries a `session_id` and a unique nonce; an
   integration test that captures a session at time T cannot decrypt
   any frame from session T+1, given only the captured key material.

3. The operator imports a 24-word BIP-39 seed phrase via `santuarioctl
   key import`, derives the master log + ratchet identity keys, and
   subsequently runs `santuarioctl tail --decrypt` to read the full
   audit log non-interactively.

4. The signer rejects any plaintext gossip frame (version byte != 0x04)
   with an `IncompatibleVersion` error increment on the
   `aeterna_gossip_rejected_unencrypted_total` counter.

5. `santuarioctl tail --raw` dumps ciphertext (operator can pipe to
   `xxd` and read entropy); `santuarioctl tail` (no flag) dumps
   plaintext records same as v0.3.0.

6. A ratchet step at any operator endpoint completes in < 2s and the
   transition is invisible to the application layer (the next gRPC
   call simply uses the new session_key without retry).

7. The OPERATOR-RUNBOOK has a new section "Key rotation" and a new
   section "Operator key compromise recovery", each following the
   Signal -> Diagnosis -> Recovery -> SLO template.

8. `promtool check metrics` against the exporter still passes; three
   new metrics are present: `santuario_log_segments_total`,
   `santuario_log_bytes_encrypted_total`,
   `santuario_ratchet_steps_total`.

9. `aeterna.toml [sigillum] require_encrypted_log = true` is the
   default and the only operator-supported value (`false` errors out
   at sentinel boot with a `ConfigForbidden` message; existence of
   the value as a setting is purely for test harnesses).

10. No new code in the *signing* path. `Sign / Verify / Resume`
    handlers untouched. Same Custos invariant as v0.3.0.

---

## 5. Out of scope -- deferred to v0.5.0 or later

Reminder for the periphery chats. Any suggestion on this list this
sprint is scope drift.

**v0.5.0 "Consensus" -- chain & federation** owns:

- Cosmos SDK `x/guardian` module and `aeterna_oracle` CosmWasm contract
- IBC testnet
- IPFS cold storage for checkpoints and model weights
- Remote log shipper (encrypted, append-only off-host)
- Multi-operator quorum (Shamir's Secret Sharing for the master seed)
- Full stealth migration on gamma trip
- zk-SNARK PoC circuits

**v1.0.0 "Sovereign" -- production hardening** owns:

- gVisor / Firecracker isolation replacing seccomp
- Hardware key support (YubiKey, WebAuthn) replacing the BIP-39 file
- Post-quantum re-key channel (replace classic ECDH in the ratchet
  with a PQ KEM such as Kyber-1024 used in handshake too)
- Bitcoin `OP_RETURN` anchoring
- Windows and macOS first-class support
- Formal external security audit
- Public mainnet

---

## 6. Risks and mitigations

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Operator loses BIP-39 seed -> permanent log loss | medium | high | Document mandatory paper backup at `santuarioctl key import` time; refuse to proceed without a typed "I have written down 24 words on paper" confirmation. |
| Nonce reuse from a buggy segment manager -> ChaCha20 catastrophic failure | low | catastrophic | Property-based test on `LogSegmentWriter`; runtime `assert_ne!` on every emitted nonce against the previous one in the segment; refuse to write past `2^32 - 1024` records per segment. |
| Ratchet desync between operator and signer | medium | medium | Re-handshake fallback documented in runbook; `santuarioctl ratchet status` exposes the desync condition; auto-rehandshake after 3 consecutive `SessionDesync` errors. |
| Config drift: `[sigillum]` settings vary across nodes -> mixed-mode crashes | low | medium | Custos integrity sweep covers `[sigillum]` block; baseline diff is an alpha alert. |
| Operator imports wrong seed -> reads garbage | low | low | `LogSegmentReader` returns `Err(InvalidTag)` immediately on the first record; `santuarioctl tail --decrypt` refuses to proceed past one tag failure with a clear "wrong key?" message. |
| ChaCha20 ciphertext bloat the on-disk log -> rotation storm | low | low | 16-byte tag + 12-byte nonce + 8-byte counter = 36 bytes per record overhead. Negligible vs typical record size (~250 bytes). |
| BIP-39 wordlist locale assumption -> operator confusion | low | low | Hard-pin English wordlist; document explicitly; accept the v1.0 cost of internationalization. |
| Telegram `encrypted_payload` mode confuses operator who sees ciphertext on phone | medium | low | Default `false`; flip on per-operator basis; document the trade-off in runbook. |

---

## 7. Executive decisions (resolved)

These were the open design questions before sprint kickoff. All five
are now closed:

1. **Backward compatibility (plaintext vs encrypted logs)**: cesura
   netta. Plaintext logs from v0.3.0 are not auto-converted. Operator
   archives or deletes them out-of-band before upgrading.

2. **Double-Ratchet scope**: simplified one-way with periodic rekey.
   No skipped-message-key tracking, no asynchronous-network
   tolerance, no multi-device sync.

3. **Key derivation root**: BIP-39 24-word seed phrase, English
   wordlist, paper-backup mandatory at first run. Hardware key
   support deferred to v1.0.0.

4. **Multi-operator quorum (Shamir M-of-N)**: out of scope. Single
   operator only. Quorum belongs to v0.5.0 as part of the
   federation work.

5. **Audit log rotation**: mandatory per-volume segmentation.
   `log_segment_max_bytes = 10_485_760` (10 MiB) default.
   ChaCha20-Poly1305 nonce-reuse risk is the technical driver.

---

## 8. Release checklist

When all phase demos are green:

- [ ] Bump `aeterna.toml -> sentinel.sentinel_version` to `0.4.0`.
- [ ] Add `[sigillum]` section to `aeterna.toml` with all rotation,
      rekey, and seed-file thresholds populated to safe defaults.
- [ ] Tag `v0.4.0-sigillum` on the main branch, signed by the active
      Santuario signer.
- [ ] Update `docs/OPERATOR-RUNBOOK.md` with "Key rotation" and
      "Operator key compromise recovery" sections.
- [ ] Update README roadmap table -- v0.4.0 row to ✅, add v0.5.0
      "Consensus" row.
- [ ] Update Grafana dashboard `aeterna-overview.json` with three new
      panels: encrypted-log segments, ratchet step rate, gossip
      rejected-unencrypted counter.
- [ ] Update Prometheus exporter catalog with the three new metrics.
- [ ] Update `bootstrap.ps1` banner to mention encrypted-log mode and
      ratchet status.
- [ ] File a public postmortem on any operator-UX surprises
      encountered during seed-import and first-rotation flows.

---

## 9. What comes after

**v0.5.0 "Consensus"** -- chain & federation. Cosmos SDK + CosmWasm
oracle, IBC testnet, IPFS cold storage, the first zk-SNARK circuits,
multi-operator quorum (Shamir for the master seed), remote log
shipper. The trail has been protected; now it must travel.

**v1.0.0 "Sovereign"** -- production hardening. External audit,
gVisor/Firecracker, hardware keys (YubiKey + WebAuthn) replacing the
BIP-39 file, post-quantum re-key channel (Kyber-1024 in the
handshake), multi-OS, formal threat model, Bitcoin `OP_RETURN`
anchoring, public mainnet.

---

*See also:*

- [`docs/SPRINT-v0.3.0.md`](./SPRINT-v0.3.0.md) -- prior sprint, the
  Oculus visibility this sprint protects
- [`docs/AGP-v1.md`](./AGP-v1.md) -- payload format whose audit
  records the encrypted log carries
- [`docs/CONSENSUS.md`](./CONSENSUS.md) -- pipeline whose health the
  encrypted gossip protects
- [`docs/OPERATOR-RUNBOOK.md`](./OPERATOR-RUNBOOK.md) -- runbook that
  Phase F extends with key-rotation and operator-key-compromise
  sections
- [`ETHICS.md`](../ETHICS.md) -- the rules the critic enforces and the
  operator surveys
