# `santuario/` — Rust Sanctuary (stub)

Target release: **v0.1.0**.

The Santuario is AETERNA's sovereignty kernel. It is **not** the same process
as the Python Sentinel. The Sentinel is the "trusted-but-compromisable"
userland orchestrator; the Santuario is the hardened kernel that holds the
secrets the Sentinel is not allowed to touch.

## Separation of concerns (locked in by the Santuario chat, 2026-04-20)

| Process | Runs as | Responsibility |
|---|---|---|
| **Sentinel** (`core/`, Python) | normal user | gossip, task harvest, Julia dispatch, GPU talk, AGP-v1 payload assembly |
| **Santuario** (`santuario/`, Rust) | privileged / sandboxed | Dilithium-5/Kyber-1024 key material, consensus block signing, local LLM inference, Axiom critic loop |

IPC between them is **gRPC over an encrypted Unix Domain Socket** (see
`aeterna.toml` → `[santuario] ipc_transport = "grpc_uds"`). Schema files will
live in `santuario/proto/`.

## Planned layout

```
santuario/
├── santuario-core/               Rust crate — crypto, axioms, critic loop
│   ├── src/
│   │   ├── main.rs
│   │   ├── ipc.rs                gRPC server (tonic + tokio)
│   │   ├── wallet.rs             Dilithium-5 / Kyber-1024 keyring
│   │   ├── axioms.rs             The three Immutable Axioms — enforced here
│   │   └── critic.rs             Loop that compares internal vs external state
│   └── Cargo.toml
├── santuario-runtime/            LLM inference subprocess (llama.cpp / candle)
│   ├── src/
│   │   └── inference.rs
│   └── models/                   (gitignored — weights pulled at install)
├── proto/
│   └── santuario.proto           gRPC schema Sentinel↔Santuario
├── vault/                        (gitignored — encrypted NVMe checkpoints)
└── tpm/                          Platform-specific attestation glue
```

## Design locks

1. **Subprocess Rust with bindings** (`llama.cpp` or `candle`). Firecracker
   micro-VM isolation is a v1.0 target; v0.1.0 uses `seccomp-bpf` on Linux.
2. **Unix Domain Sockets + gRPC/Protobuf** for Sentinel↔Santuario IPC. Typed
   schemas win over raw binary optimization at this stage.
3. **Default checkpoint storage = LOCAL** (`./santuario/vault/checkpoints/`,
   AES-256-GCM with a TPM-derived key). IPFS cold storage lands in v0.5.0.
4. **Trust level gates**:
   - Guardiano (500 REP) = software SBT + TPM 2.0 baseline attestation.
   - Saggio (2000 REP) = hardware-obligatory remote attestation
     (Intel SGX or AMD SEV).
5. **Migration thresholds** (`α`, `β`, `γ`) are enforced in `critic.rs`:
   - α: hourly checksum fail → Phoenix Protocol reset.
   - β: host CPU > 90% for > 10 min → soft migration to a peer within 50 ms RTT.
   - γ: > 3 unauthorized port-scan attempts → stealth migration and local
     Santuario shutdown.

## Not yet built

Nothing here compiles in v0.0.1. The Sentinel tolerates an absent Santuario
by skipping Dilithium-5 signing and flagging the block with
`consensus_status: "PENDING"`. This is intentional — it lets the full
Sentinel↔Julia loop run on the genesis node before the Rust kernel is ready.

## Contributor priorities (v0.1.0)

1. Define `santuario.proto` — signing, attestation, config readback.
2. Implement `wallet.rs` with `liboqs` bindings for Dilithium-5 and Kyber-1024.
3. Wire `seccomp-bpf` jail around `santuario-runtime` inference processes.
4. Write the `critic.rs` loop against the three Axioms from `MANIFESTO.md`.
