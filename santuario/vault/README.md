# santuario-vault

Encrypted keystore for the AETERNA Santuario. Phase A of the v0.2.0 "Custos"
sprint. See `docs/sprint-v0.2.0.md §4.A` for the acceptance criteria this
crate targets.

## Trust tiers

| Tier         | Backend required | Signing allowed? |
|--------------|------------------|------------------|
| `osservatore`| file             | no               |
| `guardiano`  | TPM2             | yes              |
| `saggio`     | TPM2 + governance| yes              |
| `architetto` | TPM2 + governance| yes              |

On a host without TPM2, `select_backend` downgrades the tier to `osservatore`
and the signer refuses `Sign` RPCs. This is deliberate — network-healthy
participation for laptops without lying about hardware guarantees.

## Envelope encryption

Every vault write goes through a per-record DEK:

```
 plaintext ──AES-256-GCM─▶ payload_ct  (AAD = label)
     ▲
     │
   DEK  ──AES-256-GCM─▶ wrapped_dek   (AAD = label + "/dek")
     ▲
     │
  master  (sealed by TPM2 on guardiano+, by HKDF(salt) on osservatore)
```

Master rotation (planned for v0.3.0) only rewraps `wrapped_dek`; the bulk
ciphertext is immutable.

## CLI

```shell
cargo run --bin vaultctl -- --tier guardiano seal
cargo run --bin vaultctl -- --tier guardiano unseal
echo 'state' | cargo run --bin vaultctl -- put checkpoint-1 -
cargo run --bin vaultctl -- list
cargo run --bin vaultctl -- rotate checkpoint-1
cargo run --bin vaultctl -- status
```

## Phase A demo

```shell
cargo test -p santuario-vault --test tamper
```

Three tamper scenarios are asserted: flipping a byte in the checkpoint file,
flipping a byte in the wrapped DEK, and flipping a byte in the manifest
master. All three MUST surface `VaultError::Tamper` (or `::Crypto`) instead
of returning corrupted plaintext.
