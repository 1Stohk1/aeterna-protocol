//! santuarioctl — operator-side control CLI for the Santuario signer.
//!
//! v0.2.0 "Custos" acceptance criterion #6:
//!
//! > Running `santuarioctl status` on a healthy node prints:
//! > `vault=sealed seccomp=active critic=armed integrity=green signer=ready`.
//!
//! v0.3.0 "Oculus" extends the CLI with read-only observability:
//!
//!   metrics      — snapshot the Admin metrics registry (counters,
//!                  gauges, p50/p90/p99 quantiles).
//!   tail         — print the last N audit log records (raw JSONL).
//!   peers        — snapshot the gossip peer view.
//!
//! v0.4.0 "Sigillum" Phase D extends the CLI with key + ratchet tooling:
//!
//!   key import <bip39-file>  — import 24-word BIP-39 seed phrase.
//!   key export               — print the active master key id fingerprint.
//!   key status               — show key id, derivation date, last rotation.
//!   ratchet status           — print the signer's ratchet session state.
//!   ratchet step             — force an immediate ratchet step.
//!   ratchet rehandshake      — trigger a fresh X3DH handshake.
//!   identity import <file>   — import the signer's X25519 public key.
//!   identity show            — query the signer's identity via gRPC.
//!
//! This binary is a thin gRPC client against the santuario-signer process.
//! It respects the same environment variables as the server:
//!
//!   * `SANTUARIO_SOCKET` — Unix Domain Socket path (default
//!     `/run/aeterna/santuario.sock`). Unix only.
//!   * `SANTUARIO_PORT`   — if set, use TCP on 127.0.0.1:$PORT instead.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tonic::transport::{Channel, Endpoint};

use santuario_ratchet::{
    bip39_derive, HandshakeResponse, OperatorEndpoint, SignerIdentityPublic,
    SignerIdentityKey,
};
use santuario_signer::keystore::KeyStore;

pub mod santuario {
    pub mod signer {
        pub mod v1 {
            tonic::include_proto!("santuario.signer.v1");
        }
    }
    pub mod admin {
        pub mod v1 {
            tonic::include_proto!("santuario.admin.v1");
        }
    }
}

use santuario::admin::v1::admin_client::AdminClient;
use santuario::admin::v1::{
    GetMetricsRequest, GetRatchetStatusRequest, GetSignerIdentityRequest,
    ListPeersRequest, RehandshakeRequest, StepRatchetRequest, TailAuditLogRequest,
};
use santuario::signer::v1::signer_client::SignerClient;
use santuario::signer::v1::{GetStatusRequest, ResumeRequest, TriggerAuditRequest, SignRequest};

#[derive(Parser, Debug)]
#[command(
    name = "santuarioctl",
    version,
    about = "Operator control plane for santuario-signer (Custos + Oculus)",
    long_about = None
)]
struct Cli {
    /// Override the UDS path (default: $SANTUARIO_SOCKET or /run/aeterna/santuario.sock).
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    /// Override the TCP port; if set, TCP is used instead of UDS.
    #[arg(long, global = true)]
    port: Option<u16>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print the one-line health banner required by sprint criterion #6.
    Status,
    /// Trigger an α integrity sweep now.
    Audit {
        /// If given, accept the current state as the new baseline.
        #[arg(long)]
        accept: bool,
    },
    /// Present an operator-signed recovery token to clear a suspension.
    Resume {
        /// Hex-encoded Dilithium-5 SignedMessage or DetachedSignature
        /// over the outstanding recovery challenge.
        #[arg(long)]
        token: String,
        /// Free-form operator label written to the audit log.
        #[arg(long, default_value = "operator")]
        operator: String,
    },
    /// v0.3.0 — snapshot the Admin metrics registry.
    Metrics,
    /// v0.3.0 / v0.4.0 — print the last N audit log records.
    ///
    /// Without flags: gRPC fetch + decrypted, human-friendly output.
    /// `--raw`: dump raw .sigillum ciphertext from local segment files
    /// (forensic export — operator can pipe to `xxd` and read entropy).
    /// `--json`: gRPC fetch but emit only the canonical JSON lines (jq-friendly).
    Tail {
        /// Number of records from the tail (server-capped at 1000).
        /// Ignored when `--raw` is set (raw mode dumps full segments).
        #[arg(long, default_value_t = 20)]
        limit: u32,
        /// Dump raw ciphertext from local .sigillum segment files.
        /// Implies forensic export — output is binary, pipe to `xxd`
        /// or redirect to a file. Mutually exclusive with `--json`.
        #[arg(long, conflicts_with = "json")]
        raw: bool,
        /// Emit only the canonical JSON lines (no header, jq-friendly).
        /// Decrypted via the same gRPC path as the default tail.
        #[arg(long, conflicts_with = "raw")]
        json: bool,
        /// Override the segment directory used by `--raw`. Defaults to
        /// `<AETERNA_REPO_ROOT>/santuario/integrity/audit/`.
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// v0.3.0 — snapshot the gossip peer view.
    Peers,

    // v0.4.0 "Sigillum" ---------------------------------------------------

    /// BIP-39 master key management.
    #[command(subcommand)]
    Key(KeyCmd),

    /// Operator-endpoint ratchet control.
    #[command(subcommand)]
    Ratchet(RatchetCmd),

    /// Signer X25519 identity management.
    #[command(subcommand)]
    Identity(IdentityCmd),

    /// AppChain consensus tools.
    #[command(subcommand)]
    Chain(ChainCmd),

    /// Remote log shipper tools.
    #[command(subcommand)]
    Ship(ShipCmd),

    /// SSS Vault control tools.
    #[command(subcommand)]
    Vault(VaultCmd),
}

/// `santuarioctl vault <subcmd>`
#[derive(Subcommand, Debug)]
enum VaultCmd {
    /// Submit a Shamir secret share to unseal the vault.
    Unseal {
        /// The share in index:hex format (e.g. "1:0a4fbc...").
        share: String,
    },
}

/// `santuarioctl ship <subcmd>`
#[derive(Subcommand, Debug)]
enum ShipCmd {
    /// Show pending segments, last push time, remote endpoint URL + pin fingerprint.
    Status {
        /// Path to aeterna.toml configuration file
        #[arg(long, default_value = "aeterna.toml")]
        config: String,
    },
    /// One-shot push (operator manual flush) or persist config to aeterna.toml [shipper].
    Deploy {
        /// Optional remote endpoint URL to push to.
        #[arg(long)]
        url: Option<String>,
        /// Optional TLS cert pin SHA-256 (64 hex chars).
        #[arg(long)]
        pin: Option<String>,
        /// Path to aeterna.toml configuration file
        #[arg(long, default_value = "aeterna.toml")]
        config: String,
    },
    /// HEAD/GET the remote URL for a given segment and compare SHA-256 against local copy.
    Verify {
        /// The segment ID to verify.
        segment_id: u64,
        /// Path to aeterna.toml configuration file
        #[arg(long, default_value = "aeterna.toml")]
        config: String,
    },
}

/// `santuarioctl key <subcmd>`
#[derive(Subcommand, Debug)]
enum KeyCmd {
    /// Import a BIP-39 24-word seed phrase from a file, derive the
    /// master log key + ratchet identity, and write the key envelope.
    /// The seed file is copied to santuario/vault/seed.bip39 (chmod 0600).
    Import {
        /// Path to the file containing the 24 BIP-39 English words,
        /// separated by spaces or newlines.
        file: PathBuf,
        /// Path of the key envelope output (default:
        /// santuario/vault/keys.envelope relative to AETERNA_REPO_ROOT
        /// or the current directory).
        #[arg(long)]
        envelope: Option<PathBuf>,
        /// Number of Shamir shares to generate. If set, --threshold must also be set.
        #[arg(long)]
        shares: Option<u8>,
        /// Threshold K of shares required to unseal the vault.
        #[arg(long)]
        threshold: Option<u8>,
    },
    /// Print the active master key id (fingerprint only — never the key bytes).
    Export,
    /// Show key id, derivation date, last rotation from the key envelope.
    Status,
}

/// `santuarioctl ratchet <subcmd>`
#[derive(Subcommand, Debug)]
enum RatchetCmd {
    /// Print the signer's current ratchet session state via gRPC.
    Status,
    /// Force an immediate ratchet step on the signer.
    Step,
    /// Trigger a fresh X3DH-lite handshake with the signer.
    /// Requires that the signer's identity pubkey was already imported
    /// via `santuarioctl identity import`.
    Rehandshake {
        /// Path to the file containing the operator's imported signer
        /// identity public key. Default:
        /// $HOME/.aeterna/signer_identity.pub
        #[arg(long)]
        identity_file: Option<PathBuf>,
    },
}

/// `santuarioctl identity <subcmd>`
#[derive(Subcommand, Debug)]
enum IdentityCmd {
    /// Import the signer's X25519 long-term public key from a file.
    /// Store it at $HOME/.aeterna/signer_identity.pub for future
    /// ratchet handshakes.
    Import {
        /// File containing the signer's X25519 pubkey: either a
        /// 32-byte binary file or a 64-char hex string.
        file: PathBuf,
    },
    /// Query the signer's X25519 identity public key via gRPC and
    /// print it (hex). Does NOT require a prior `identity import`.
    Show,
}

/// `santuarioctl chain <subcmd>`
#[derive(Subcommand, Debug)]
enum ChainCmd {
    /// Query the status of the local Cosmos node.
    Status {
        /// URL of the node REST endpoint.
        #[arg(long, default_value = "http://127.0.0.1:1317")]
        rest_url: String,
    },
    /// Register the guardian SBT identity on-chain.
    Register {
        /// URL of the node REST endpoint.
        #[arg(long, default_value = "http://127.0.0.1:1317")]
        rest_url: String,
        /// Guardian public key or address.
        #[arg(long)]
        address: String,
        /// TPM public key hex representation.
        #[arg(long, default_value = "0102030405")]
        tpm_pubkey: String,
        /// Path to the manifesto file to sign.
        #[arg(long, default_value = "MANIFESTO.md")]
        manifesto: PathBuf,
    },
    /// Sign and submit a validated AGP block to the oracle contract.
    SubmitBlock {
        /// URL of the node REST endpoint.
        #[arg(long, default_value = "http://127.0.0.1:1317")]
        rest_url: String,
        /// Submitter guardian address.
        #[arg(long)]
        address: String,
        /// Hash of the AGP block (hex).
        #[arg(long)]
        hash: String,
        /// Height of the AGP block.
        #[arg(long)]
        height: u64,
        /// Calculated trust score to submit.
        #[arg(long, default_value = "1.000000000000000000")]
        trust_score: String,
    },
    /// Fetch the trust score of a guardian address from the oracle contract.
    TrustScore {
        /// URL of the node REST endpoint.
        #[arg(long, default_value = "http://127.0.0.1:1317")]
        rest_url: String,
        /// Guardian address to query.
        #[arg(long)]
        address: String,
        /// Oracle CosmWasm contract address.
        #[arg(long, default_value = "aeterna_oracle_contract")]
        contract: String,
    },
    /// Sign and submit a Bitcoin anchor to the Cosmos module.
    SubmitAnchor {
        /// URL of the node REST endpoint.
        #[arg(long, default_value = "http://127.0.0.1:1317")]
        rest_url: String,
        /// Submitter guardian address.
        #[arg(long)]
        address: String,
        /// Hash of the Cosmos block (hex).
        #[arg(long)]
        hash: String,
        /// Height of the Cosmos block.
        #[arg(long)]
        height: u64,
        /// Bitcoin transaction hash.
        #[arg(long)]
        btc_tx: String,
        /// Name of the anchoring event.
        #[arg(long, default_value = "heartbeat")]
        event: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let channel = connect(&cli).await?;
    let mut client = SignerClient::new(channel.clone());
    let mut admin = AdminClient::new(channel);

    match cli.cmd {
        Cmd::Status => {
            let resp = client.get_status(GetStatusRequest {}).await?.into_inner();
            // Acceptance banner — single line, space-separated key=value.
            let vault = if resp.vault_sealed {
                "sealed"
            } else {
                "unsealed"
            };
            let seccomp = if resp.seccomp_active {
                "active"
            } else {
                "inactive"
            };
            let critic = if resp.critic_armed { "armed" } else { "off" };
            let integrity = if resp.integrity_ok { "green" } else { "red" };
            let signer = if resp.verdict == "ready" {
                "ready".to_string()
            } else {
                format!(
                    "suspended({}/{})",
                    if resp.suspension_kind.is_empty() {
                        "?"
                    } else {
                        resp.suspension_kind.as_str()
                    },
                    if resp.suspension_reason.is_empty() {
                        "?"
                    } else {
                        resp.suspension_reason.as_str()
                    }
                )
            };
            println!(
                "vault={} seccomp={} critic={} integrity={} signer={}",
                vault, seccomp, critic, integrity, signer
            );
            if resp.verdict != "ready" {
                std::process::exit(2);
            }
        }
        Cmd::Audit { accept } => {
            let resp = client
                .trigger_audit(TriggerAuditRequest {
                    accept_new_baseline: accept,
                })
                .await?
                .into_inner();
            println!("mismatches={}", resp.mismatches);
            if !resp.mismatched_paths.is_empty() {
                println!("paths:");
                for p in &resp.mismatched_paths {
                    println!("  - {}", p);
                }
                // Non-zero exit so shell scripts can detect the condition.
                std::process::exit(1);
            }
        }
        Cmd::Resume { token, operator } => {
            let resp = client
                .resume(ResumeRequest {
                    token_hex: token,
                    operator,
                })
                .await?
                .into_inner();
            if resp.resumed {
                println!("resumed=true");
            } else {
                eprintln!("resumed=false error={}", resp.error);
                std::process::exit(3);
            }
        }
        Cmd::Metrics => {
            let resp = admin.get_metrics(GetMetricsRequest {}).await?.into_inner();
            println!(
                "node={} ts_utc={} schema={} window={}s",
                resp.node_id, resp.ts_utc, resp.schema_version, resp.metric_window_seconds
            );

            let mut counters: Vec<_> = resp.counters.into_iter().collect();
            counters.sort_by(|a, b| a.0.cmp(&b.0));
            if !counters.is_empty() {
                println!("counters:");
                for (k, v) in &counters {
                    println!("  {k:40} {v}");
                }
            }

            let mut gauges: Vec<_> = resp.gauges.into_iter().collect();
            gauges.sort_by(|a, b| a.0.cmp(&b.0));
            if !gauges.is_empty() {
                println!("gauges:");
                for (k, v) in &gauges {
                    println!("  {k:40} {v}");
                }
            }

            let mut quantiles: Vec<_> = resp.quantiles.into_iter().collect();
            quantiles.sort_by(|a, b| a.0.cmp(&b.0));
            if !quantiles.is_empty() {
                println!("quantiles (p50 / p90 / p99):");
                for (k, q) in &quantiles {
                    println!("  {k:40} {:.6} {:.6} {:.6}", q.p50, q.p90, q.p99);
                }
            }
        }
        Cmd::Tail { limit, raw, json, dir } => {
            if raw {
                // v0.4 AC #5: forensic ciphertext dump from local segment files.
                let seg_dir = dir.unwrap_or_else(default_segment_dir);
                dump_segments_raw(&seg_dir)?;
            } else {
                let resp = admin
                    .tail_audit_log(TailAuditLogRequest { limit })
                    .await?
                    .into_inner();
                if json {
                    for line in &resp.lines {
                        println!("{}", line.json);
                    }
                } else {
                    println!("# {} record(s)", resp.lines.len());
                    for line in &resp.lines {
                        println!("[{}] {} {}", line.ts_utc, line.record, line.json);
                    }
                }
            }
        }
        Cmd::Peers => {
            let resp = admin.list_peers(ListPeersRequest {}).await?.into_inner();
            println!(
                "# {} peer(s) snapshot_utc={}",
                resp.peers.len(),
                resp.snapshot_utc
            );
            for p in &resp.peers {
                let freshness = if p.last_seen_utc == 0 {
                    "never".to_string()
                } else {
                    let age = resp.snapshot_utc.saturating_sub(p.last_seen_utc);
                    format!("{}s ago", age)
                };
                let node = if p.node_id.is_empty() {
                    "?"
                } else {
                    p.node_id.as_str()
                };
                let bs = if p.is_bootstrap { " [bootstrap]" } else { "" };
                println!(
                    "  {:30} node={:20} last_seen={} rx={} tx={}{}",
                    p.address, node, freshness, p.rx_count, p.tx_count, bs
                );
            }
        }

        // v0.4.0 "Sigillum" -----------------------------------------------

        Cmd::Key(sub) => handle_key(sub)?,

        Cmd::Ratchet(sub) => handle_ratchet(sub, &mut admin).await?,

        Cmd::Identity(sub) => handle_identity(sub, &mut admin).await?,

        Cmd::Chain(sub) => handle_chain(sub, &mut client).await?,

        Cmd::Ship(sub) => handle_ship(sub).await?,

        Cmd::Vault(sub) => handle_vault(sub, &mut client).await?,
    }
    Ok(())
}

// =============================================================================
// Phase D helpers
// =============================================================================

/// Default directory holding `.sigillum` encrypted audit segments,
/// resolved the same way the signer does: `AETERNA_REPO_ROOT` if set,
/// else CWD, joined with `santuario/integrity/audit/`.
fn default_segment_dir() -> PathBuf {
    std::env::var_os("AETERNA_REPO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("santuario/integrity/audit")
}

/// v0.4 AC #5 — dump raw ciphertext bytes from every `.sigillum` file
/// in `dir`, oldest-first by filename. Output is binary; intended for
/// redirection or pipelines into `xxd`/`hexdump`/forensic tooling.
fn dump_segments_raw(dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let read = std::fs::read_dir(dir).map_err(|e| {
        format!(
            "cannot read segment dir {} ({e}). Override with --dir or set AETERNA_REPO_ROOT.",
            dir.display()
        )
    })?;
    let mut files: Vec<PathBuf> = read
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| ext == "sigillum")
        })
        .collect();
    if files.is_empty() {
        return Err(format!(
            "no .sigillum segments in {} — has the signer ever appended to the audit log?",
            dir.display()
        )
        .into());
    }
    files.sort();

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    for path in &files {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("read {} failed: {e}", path.display()))?;
        handle.write_all(&bytes)?;
    }
    handle.flush()?;
    Ok(())
}

/// Canonical path for the operator's imported signer identity pubkey.
fn default_identity_pub_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".aeterna")
        .join("signer_identity.pub")
}

/// Canonical path for the key envelope (keys.envelope metadata file).
fn default_envelope_path() -> PathBuf {
    // Honour AETERNA_REPO_ROOT if set, else use CWD.
    std::env::var_os("AETERNA_REPO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("santuario/vault/keys.envelope")
}

// --- vault subcommand --------------------------------------------------------

async fn handle_vault(
    cmd: VaultCmd,
    client: &mut SignerClient<Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        VaultCmd::Unseal { share } => {
            let resp = client
                .unseal(santuario::signer::v1::UnsealRequest { share_hex: share })
                .await?
                .into_inner();
            if resp.unsealed {
                println!(
                    "vault unsealed successfully! (shares collected: {}, threshold: {})",
                    resp.shares_collected, resp.threshold
                );
            } else if !resp.error.is_empty() {
                eprintln!("unseal failed: {}", resp.error);
                std::process::exit(1);
            } else {
                println!(
                    "share accepted. (shares collected: {}/{})",
                    resp.shares_collected, resp.threshold
                );
            }
        }
    }
    Ok(())
}

// --- key subcommand ----------------------------------------------------------

fn handle_key(cmd: KeyCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        KeyCmd::Import { file, envelope, shares, threshold } => cmd_key_import(file, envelope, shares, threshold),
        KeyCmd::Export => cmd_key_export(),
        KeyCmd::Status => cmd_key_status(),
    }
}

fn cmd_key_import(
    file: PathBuf,
    envelope: Option<PathBuf>,
    shares: Option<u8>,
    threshold: Option<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let phrase = std::fs::read_to_string(&file)
        .map_err(|e| format!("cannot read seed file {}: {e}", file.display()))?;

    let mnemonic = bip39_derive::parse_mnemonic(&phrase)
        .map_err(|e| format!("BIP-39 parse error: {e}"))?;

    let keys = bip39_derive::derive_from_mnemonic(&mnemonic)
        .map_err(|e| format!("key derivation failed: {e}"))?;

    // Compute the master key id fingerprint (first 16 bytes of SHA-256).
    let master_key_id = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(keys.master_log_key);
        hex::encode(&digest[..16])
    };

    // Mandatory paper-backup confirmation.
    println!("Master key id (fingerprint): {}", master_key_id);
    println!();
    println!("IMPORTANT: you must have written down all 24 BIP-39 words on paper.");
    println!("Loss of the seed phrase means permanent loss of the encrypted audit log.");
    println!();
    print!("I have written down 24 words on paper [y/N]: ");
    use std::io::Write;
    std::io::stdout().flush()?;
    let mut confirmation = String::new();
    std::io::stdin().read_line(&mut confirmation)?;
    if confirmation.trim().to_lowercase() != "y" {
        eprintln!("Aborted. Key NOT imported.");
        std::process::exit(1);
    }

    // Write key envelope (metadata only — no key material).
    let envelope_path = envelope.unwrap_or_else(default_envelope_path);
    if let Some(parent) = envelope_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if let (Some(n), Some(k)) = (shares, threshold) {
        if k == 0 || k > n {
            return Err("invalid shares/threshold parameters".into());
        }

        // 1. Generate master key M
        let mut m_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut m_bytes);

        // 2. Split master key M using SSS
        let shares_vec = santuario_sss::split_secret(&m_bytes, k, n)
            .map_err(|e| format!("Shamir split failed: {e}"))?;

        // 3. Load or generate Dilithium-5 keys
        let keys_dir = std::env::var_os("SANTUARIO_KEYS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
                home_dir.join(".santuario").join("keys")
            });
        let keystore = KeyStore::load_or_generate(&keys_dir)?;

        // 4. Load or generate X25519 identity key
        let signer_identity_path = default_identity_pub_path().parent().unwrap().join("signer_identity.x25519");
        let signer_identity = SignerIdentityKey::load_or_generate(&signer_identity_path)?;

        // 5. Serialize key material into JSON
        let key_material = serde_json::json!({
            "dilithium_priv_hex": hex::encode(pqcrypto_traits::sign::SecretKey::as_bytes(&keystore.secret_key)),
            "dilithium_pub_hex": hex::encode(pqcrypto_traits::sign::PublicKey::as_bytes(&keystore.public_key)),
            "master_log_key_hex": hex::encode(keys.master_log_key),
            "ratchet_identity_hex": hex::encode(signer_identity.to_bytes()),
        });
        let plaintext = serde_json::to_vec(&key_material)?;

        // 6. Encrypt key material under M using AES-256-GCM
        let vault_m = santuario_vault::MasterKey::from_bytes(m_bytes);
        let sealed_envelope = santuario_vault::gcm_encrypt(&vault_m, &plaintext, "santuario-sss-vault-v1")
            .map_err(|e| format!("encryption failed: {e}"))?;

        // 7. Write keys.sealed
        let sealed_json = serde_json::json!({
            "version": 1,
            "threshold": k,
            "num_shares": n,
            "envelope": sealed_envelope,
        });
        let sealed_path = envelope_path.parent().unwrap().join("keys.sealed");
        std::fs::write(&sealed_path, serde_json::to_string_pretty(&sealed_json)?)?;
        println!("Created SSS encrypted vault envelope at {}", sealed_path.display());

        // 8. Delete plaintext keys from disk for security hygiene
        let priv_path = keys_dir.join("key.priv");
        if priv_path.exists() {
            std::fs::remove_file(&priv_path).ok();
        }
        if signer_identity_path.exists() {
            std::fs::remove_file(&signer_identity_path).ok();
        }
        let log_master_key_path = envelope_path.parent().unwrap().join("log_master.key");
        if log_master_key_path.exists() {
            std::fs::remove_file(&log_master_key_path).ok();
        }

        // 9. Display Shamir shares
        println!("\n==================================================");
        println!("SHAMIR SECRET SHARING (SSS) KEY REPRESENTATION");
        println!("==================================================");
        println!("Threshold K = {}, Total Shares N = {}", k, n);
        println!("Save the following shares in secure, separate locations:\n");
        for (idx, share) in shares_vec {
            println!("Share {}: {}:{}", idx, idx, hex::encode(share));
        }
        println!("==================================================\n");

    } else {
        let now = chrono::Utc::now().timestamp();
        let env_json = serde_json::json!({
            "version": 1,
            "master_key_id": master_key_id,
            "derivation_utc": now,
            "last_rotation_utc": now,
        });
        let tmp = envelope_path.with_extension("envelope.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&env_json)?)?;
        std::fs::rename(&tmp, &envelope_path)?;

        println!("Key envelope written: {}", envelope_path.display());
        println!("master_key_id={}", master_key_id);
        println!("Run `santuarioctl key status` to verify.");
    }
    Ok(())
}

fn cmd_key_export() -> Result<(), Box<dyn std::error::Error>> {
    let env = read_envelope()?;
    println!(
        "master_key_id={} derivation_utc={}",
        env["master_key_id"].as_str().unwrap_or("?"),
        env["derivation_utc"].as_i64().unwrap_or(0)
    );
    Ok(())
}

fn cmd_key_status() -> Result<(), Box<dyn std::error::Error>> {
    let env = read_envelope()?;
    let id = env["master_key_id"].as_str().unwrap_or("?");
    let der = env["derivation_utc"].as_i64().unwrap_or(0);
    let rot = env["last_rotation_utc"].as_i64().unwrap_or(der);
    let ver = env["version"].as_u64().unwrap_or(0);
    println!("version:          {ver}");
    println!("master_key_id:    {id}");
    println!("derivation_utc:   {} ({})", der, utc_to_rfc3339(der));
    println!("last_rotation:    {} ({})", rot, utc_to_rfc3339(rot));
    Ok(())
}

fn read_envelope() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let path = default_envelope_path();
    let text = std::fs::read_to_string(&path)
        .map_err(|_| format!("key envelope not found at {}. Run `santuarioctl key import` first.", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&text)?;
    Ok(v)
}

fn utc_to_rfc3339(ts: i64) -> String {
    if ts == 0 {
        return "never".to_string();
    }
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| "invalid".to_string())
}

// --- ratchet subcommand ------------------------------------------------------

async fn handle_ratchet(
    cmd: RatchetCmd,
    admin: &mut AdminClient<Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        RatchetCmd::Status => cmd_ratchet_status(admin).await,
        RatchetCmd::Step => cmd_ratchet_step(admin).await,
        RatchetCmd::Rehandshake { identity_file } => {
            cmd_ratchet_rehandshake(admin, identity_file).await
        }
    }
}

async fn cmd_ratchet_status(
    admin: &mut AdminClient<Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let s = admin
        .get_ratchet_status(GetRatchetStatusRequest {})
        .await?
        .into_inner();

    let established = if s.established { "yes" } else { "no" };
    let tombstoned = if s.tombstoned { "yes" } else { "no" };
    println!("established:      {established}");
    println!("tombstoned:       {tombstoned}");
    if s.established {
        println!("step:             {}", s.step);
        println!("msgs_in_step:     {}", s.msgs_sent_in_step);
        println!("age_seconds:      {:.1}", s.age_seconds);
        let secs_left = (s.step_max_seconds as f64 - s.age_seconds).max(0.0);
        println!("step_in:          {:.1}s or {} msgs",
            secs_left,
            s.step_max_messages.saturating_sub(s.msgs_sent_in_step));
    }
    println!("last_handshake:   {}", utc_to_rfc3339(s.last_handshake_utc));

    if !s.established && !s.tombstoned {
        eprintln!("hint: no session active — run `santuarioctl ratchet rehandshake`");
    }
    if s.tombstoned {
        eprintln!("error: session tombstoned — run `santuarioctl ratchet rehandshake`");
        std::process::exit(4);
    }
    Ok(())
}

async fn cmd_ratchet_step(
    admin: &mut AdminClient<Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let r = admin
        .step_ratchet(StepRatchetRequest {})
        .await?
        .into_inner();
    if r.ok {
        println!("ok=true new_step={}", r.new_step);
    } else {
        eprintln!("step failed: {}", r.error);
        std::process::exit(4);
    }
    Ok(())
}

async fn cmd_ratchet_rehandshake(
    admin: &mut AdminClient<Channel>,
    identity_file: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load the signer's imported identity pubkey.
    let id_path = identity_file.unwrap_or_else(default_identity_pub_path);
    let id_bytes = load_identity_pub(&id_path)?;

    // Generate operator ephemeral.
    let signer_pub = SignerIdentityPublic::from_bytes(id_bytes);
    let operator_ep = OperatorEndpoint::new(signer_pub);
    let hs_req = operator_ep.handshake_request();

    // Send to signer.
    let hs_resp = admin
        .rehandshake(RehandshakeRequest {
            operator_eph_pub: hs_req.operator_eph_pub.to_vec(),
            operator_kyber_pub: hs_req.operator_kyber_pub.to_vec(),
        })
        .await?
        .into_inner();

    // Finalise on operator side (derives root_key, builds Session).
    let mut signer_eph = [0u8; 32];
    if hs_resp.signer_eph_pub.len() != 32 {
        return Err("signer returned invalid ephemeral pub key length".into());
    }
    signer_eph.copy_from_slice(&hs_resp.signer_eph_pub);

    let mut kyber_ct = [0u8; 1568];
    if hs_resp.kyber_ciphertext.len() != 1568 {
        return Err("signer returned invalid kyber ciphertext length".into());
    }
    kyber_ct.copy_from_slice(&hs_resp.kyber_ciphertext);

    let _root_key = operator_ep
        .finalize(HandshakeResponse {
            signer_eph_pub: signer_eph,
            kyber_ciphertext: kyber_ct,
        })
        .map_err(|e| format!("handshake finalise failed: {e}"))?;

    println!("rehandshake=ok");
    println!("Run `santuarioctl ratchet status` to verify the new session.");
    Ok(())
}

// --- identity subcommand -----------------------------------------------------

async fn handle_identity(
    cmd: IdentityCmd,
    admin: &mut AdminClient<Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        IdentityCmd::Import { file } => cmd_identity_import(file),
        IdentityCmd::Show => cmd_identity_show(admin).await,
    }
}

fn cmd_identity_import(file: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::fs::read(&file)
        .map_err(|e| format!("cannot read {}: {e}", file.display()))?;

    // Accept either a 32-byte binary file or a 64-char hex string.
    let pub_bytes = if raw.len() == 32 {
        let mut b = [0u8; 32];
        b.copy_from_slice(&raw);
        b
    } else {
        let hex_str = String::from_utf8(raw)
            .map_err(|_| "file is not 32-byte binary nor valid UTF-8 hex")?;
        let decoded = hex::decode(hex_str.trim())
            .map_err(|e| format!("hex decode failed: {e}"))?;
        if decoded.len() != 32 {
            return Err(format!(
                "expected 32 bytes, got {} after hex decode",
                decoded.len()
            )
            .into());
        }
        let mut b = [0u8; 32];
        b.copy_from_slice(&decoded);
        b
    };

    let dest = default_identity_pub_path();
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = dest.with_extension("pub.tmp");
    std::fs::write(&tmp, &pub_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp, perms)?;
    }
    std::fs::rename(&tmp, &dest)?;

    println!("signer identity imported: {}", dest.display());
    println!("identity_pub_hex={}", hex::encode(&pub_bytes));
    println!("Run `santuarioctl ratchet rehandshake` to open the encrypted channel.");
    Ok(())
}

async fn cmd_identity_show(
    admin: &mut AdminClient<Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = admin
        .get_signer_identity(GetSignerIdentityRequest {})
        .await?
        .into_inner();
    println!("identity_pub_hex={}", resp.identity_pub_hex);
    println!("identity_id_hex={}", resp.identity_id_hex);
    Ok(())
}

fn load_identity_pub(path: &PathBuf) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let raw = std::fs::read(path)
        .map_err(|_| format!(
            "signer identity not found at {}. Run `santuarioctl identity import` first.",
            path.display()
        ))?;
    if raw.len() == 32 {
        let mut b = [0u8; 32];
        b.copy_from_slice(&raw);
        return Ok(b);
    }
    let hex_str = String::from_utf8(raw).map_err(|_| "identity file is not binary nor UTF-8")?;
    let decoded = hex::decode(hex_str.trim()).map_err(|e| format!("hex decode: {e}"))?;
    if decoded.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", decoded.len()).into());
    }
    let mut b = [0u8; 32];
    b.copy_from_slice(&decoded);
    Ok(b)
}

/// Connect to the running signer. Preference order:
///   1. --port or SANTUARIO_PORT  → TCP on 127.0.0.1:$PORT
///   2. --socket or SANTUARIO_SOCKET on unix → UDS
///   3. Default UDS path `/run/aeterna/santuario.sock` on unix
async fn connect(cli: &Cli) -> Result<Channel, Box<dyn std::error::Error>> {
    // TCP path.
    let tcp_port = cli.port.or_else(|| {
        std::env::var("SANTUARIO_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
    });
    if let Some(p) = tcp_port {
        let url = format!("http://127.0.0.1:{}", p);
        let ch = Endpoint::from_shared(url)?
            .timeout(Duration::from_secs(5))
            .connect()
            .await?;
        return Ok(ch);
    }

    // UDS path (unix only).
    #[cfg(unix)]
    {
        use tonic::transport::Uri;
        let path = cli
            .socket
            .clone()
            .or_else(|| std::env::var_os("SANTUARIO_SOCKET").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/run/aeterna/santuario.sock"));

        let path_for_connector = path.clone();
        // The URL here is a dummy; the connector provides the real transport.
        let ch = Endpoint::try_from("http://[::]:50051")?
            .timeout(Duration::from_secs(5))
            .connect_with_connector(tower::service_fn(move |_: Uri| {
                let p = path_for_connector.clone();
                async move { tokio::net::UnixStream::connect(p).await }
            }))
            .await?;
        Ok(ch)
    }

    #[cfg(not(unix))]
    {
        Err("on non-unix platforms, pass --port or set SANTUARIO_PORT".into())
    }
}

async fn handle_chain(
    cmd: ChainCmd,
    client: &mut SignerClient<tonic::transport::Channel>,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        ChainCmd::Status { rest_url } => {
            let resp = reqwest::get(&format!("{}/status", rest_url.trim_end_matches('/'))).await?;
            let json: serde_json::Value = resp.json().await?;
            let result = &json["result"];
            let moniker = result["node_info"]["moniker"].as_str().unwrap_or("unknown");
            let height = result["sync_info"]["latest_block_height"].as_str().unwrap_or("unknown");
            println!("node={} height={}", moniker, height);
        }
        ChainCmd::Register {
            rest_url,
            address,
            tpm_pubkey,
            manifesto,
        } => {
            let content = std::fs::read(&manifesto).map_err(|e| {
                format!("Failed to read manifesto file {}: {}", manifesto.display(), e)
            })?;
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&content);
            let hash = hasher.finalize().to_vec();

            let sign_resp = client
                .sign(SignRequest {
                    payload_hash: hash.clone(),
                    agp_block_json: Vec::new(),
                    producer_pid: None,
                    producer_policy: None,
                })
                .await?
                .into_inner();

            let signature_hex = hex::encode(sign_resp.signature);
            let hash_hex = hex::encode(hash);

            let payload = serde_json::json!({
                "guardian_address": address,
                "tpm_pubkey": tpm_pubkey,
                "manifesto_hash": hash_hex,
                "signature": signature_hex,
            });

            let http_client = reqwest::Client::new();
            let resp = http_client
                .post(&format!("{}/aeterna/guardian/v1/register", rest_url.trim_end_matches('/')))
                .json(&payload)
                .send()
                .await?;

            if resp.status().is_success() {
                let json: serde_json::Value = resp.json().await?;
                println!("Registration successful: {}", serde_json::to_string_pretty(&json)?);
            } else {
                let status = resp.status();
                let body = resp.text().await?;
                eprintln!("Registration failed: status={} body={}", status, body);
                std::process::exit(1);
            }
        }
        ChainCmd::SubmitBlock {
            rest_url,
            address,
            hash,
            height,
            trust_score,
        } => {
            let hash_bytes = hex::decode(&hash).map_err(|e| {
                format!("Invalid hex block hash '{}': {}", hash, e)
            })?;

            let sign_resp = client
                .sign(SignRequest {
                    payload_hash: hash_bytes,
                    agp_block_json: Vec::new(),
                    producer_pid: None,
                    producer_policy: None,
                })
                .await?
                .into_inner();

            let signature_hex = hex::encode(sign_resp.signature);

            let payload = serde_json::json!({
                "guardian_address": address,
                "block_hash": hash,
                "block_height": height,
                "trust_score": trust_score,
                "signature": signature_hex,
            });

            let http_client = reqwest::Client::new();
            let resp = http_client
                .post(&format!(
                    "{}/cosmwasm/wasm/v1/contract/aeterna_oracle_contract/submit_block",
                    rest_url.trim_end_matches('/')
                ))
                .json(&payload)
                .send()
                .await?;

            if resp.status().is_success() {
                let json: serde_json::Value = resp.json().await?;
                println!(
                    "Block submitted successfully. New trust score: {}",
                    json["trust_score"].as_str().unwrap_or("unknown")
                );
            } else {
                let status = resp.status();
                let body = resp.text().await?;
                eprintln!("Block submission failed: status={} body={}", status, body);
                std::process::exit(1);
            }
        }
        ChainCmd::TrustScore {
            rest_url,
            address,
            contract,
        } => {
            let query_json = serde_json::json!({
                "get_trust_score": {
                    "address": address,
                }
            });
            let query_bytes = serde_json::to_vec(&query_json)?;
            use base64::Engine as _;
            let query_b64 = base64::engine::general_purpose::STANDARD.encode(&query_bytes);

            let url = format!(
                "{}/cosmwasm/wasm/v1/contract/{}/smart/{}",
                rest_url.trim_end_matches('/'),
                contract,
                query_b64
            );
            let resp = reqwest::get(&url).await?;

            if resp.status().is_success() {
                let json: serde_json::Value = resp.json().await?;
                let score = json["data"]["score"].as_str().unwrap_or("unknown");
                println!("trust_score={}", score);
            } else {
                let status = resp.status();
                let body = resp.text().await?;
                eprintln!("Query failed: status={} body={}", status, body);
                std::process::exit(1);
            }
        }
        ChainCmd::SubmitAnchor {
            rest_url,
            address,
            hash,
            height,
            btc_tx,
            event,
        } => {
            // Construct signature payload: creator + block_hash + block_height + btc_tx_hash + event_name
            let mut payload = Vec::new();
            payload.extend_from_slice(address.as_bytes());
            payload.extend_from_slice(hash.as_bytes());
            payload.extend_from_slice(height.to_string().as_bytes());
            payload.extend_from_slice(btc_tx.as_bytes());
            payload.extend_from_slice(event.as_bytes());

            let sign_resp = client
                .sign(SignRequest {
                    payload_hash: payload,
                    agp_block_json: Vec::new(),
                    producer_pid: None,
                    producer_policy: None,
                })
                .await?
                .into_inner();

            let signature_hex = hex::encode(sign_resp.signature);

            let payload_json = serde_json::json!({
                "creator": address,
                "block_hash": hash,
                "block_height": height,
                "btc_tx_hash": btc_tx,
                "event_name": event,
                "signature": signature_hex,
            });

            let http_client = reqwest::Client::new();
            let resp = http_client
                .post(&format!(
                    "{}/aeterna/anchor/v1/submit",
                    rest_url.trim_end_matches('/')
                ))
                .json(&payload_json)
                .send()
                .await?;

            if resp.status().is_success() {
                let json: serde_json::Value = resp.json().await?;
                println!(
                    "Anchor submitted successfully: {}",
                    serde_json::to_string_pretty(&json)?
                );
            } else {
                let status = resp.status();
                let body = resp.text().await?;
                eprintln!("Anchor submission failed: status={} body={}", status, body);
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct AeternaConfig {
    #[serde(default)]
    log_segment_dir: Option<String>,
    #[serde(default)]
    shipper: Option<santuario_shipper::ShipperConfig>,
}

fn read_aeterna_config(path: &str) -> Result<AeternaConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let cfg: AeternaConfig = toml::from_str(&content)?;
    Ok(cfg)
}

fn resolve_segment_dir(cfg: &AeternaConfig) -> PathBuf {
    if let Some(ref dir) = cfg.log_segment_dir {
        let base = std::env::var_os("AETERNA_REPO_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        base.join(dir)
    } else {
        default_segment_dir()
    }
}

async fn handle_ship(cmd: ShipCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        ShipCmd::Status { config } => {
            let cfg = match read_aeterna_config(&config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to read config file '{}': {}", config, e);
                    std::process::exit(1);
                }
            };
            let shipper = cfg.shipper.clone().unwrap_or_default();
            if !shipper.enabled {
                println!("shipper: disabled");
                return Ok(());
            }

            println!("enabled:             true");
            println!("endpoint_url:        {}", shipper.endpoint_url);
            println!("endpoint_pin_sha256: {}", shipper.endpoint_pin_sha256);

            let seg_dir = resolve_segment_dir(&cfg);
            let segments = match santuario_shipper::find_finalized(&seg_dir) {
                Ok(segs) => segs,
                Err(e) => {
                    eprintln!("Error scanning segment directory {}: {}", seg_dir.display(), e);
                    std::process::exit(1);
                }
            };

            let total = segments.len();
            let mut pending = 0;
            let mut last_pushed_time = "never".to_string();
            let mut latest_ts: Option<chrono::DateTime<chrono::Utc>> = None;

            for seg in &segments {
                let pushed_path = seg.path.clone();
                let mut os_str = pushed_path.into_os_string();
                os_str.push(".pushed");
                let pushed_path = PathBuf::from(os_str);

                if !pushed_path.exists() {
                    pending += 1;
                } else if let Ok(content) = std::fs::read_to_string(&pushed_path) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(pushed_at_str) = json["pushed_at"].as_str() {
                            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(pushed_at_str) {
                                let dt_utc = dt.with_timezone(&chrono::Utc);
                                if latest_ts.is_none() || dt_utc > latest_ts.unwrap() {
                                    latest_ts = Some(dt_utc);
                                    last_pushed_time = pushed_at_str.to_string();
                                }
                            }
                        }
                    }
                }
            }

            println!("total_segments:      {}", total);
            println!("pending_segments:    {}", pending);
            println!("last_push_time:      {}", last_pushed_time);
        }
        ShipCmd::Deploy { url, pin, config } => {
            if let (Some(url_val), Some(pin_val)) = (url, pin) {
                let toml_content = match std::fs::read_to_string(&config) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Failed to read config file '{}': {}", config, e);
                        std::process::exit(1);
                    }
                };

                let updated_toml = if toml_content.contains("[shipper]") {
                    let new_shipper_block = format!(
                        "[shipper]\nenabled                 = true\nendpoint_url            = \"{}\"\nendpoint_pin_sha256     = \"{}\"\npoll_interval_seconds   = 30\nback_off_seconds        = 60\nmax_retries_per_segment = 5\n",
                        url_val, pin_val
                    );
                    
                    let mut lines = toml_content.lines().collect::<Vec<_>>();
                    let mut start_idx = None;
                    let mut end_idx = None;
                    for (i, line) in lines.iter().enumerate() {
                        if line.trim() == "[shipper]" {
                            start_idx = Some(i);
                        } else if start_idx.is_some() && line.trim().starts_with('[') {
                            end_idx = Some(i);
                            break;
                        }
                    }

                    if let Some(start) = start_idx {
                        let end = end_idx.unwrap_or(lines.len());
                        lines.drain(start..end);
                        lines.insert(start, &new_shipper_block);
                        lines.join("\n")
                    } else {
                        format!("{}\n{}", toml_content.trim_end(), new_shipper_block)
                    }
                } else {
                    let new_shipper_block = format!(
                        "\n[shipper]\nenabled                 = true\nendpoint_url            = \"{}\"\nendpoint_pin_sha256     = \"{}\"\npoll_interval_seconds   = 30\nback_off_seconds        = 60\nmax_retries_per_segment = 5\n",
                        url_val, pin_val
                    );
                    format!("{}{}", toml_content.trim_end(), new_shipper_block)
                };

                if let Err(e) = std::fs::write(&config, updated_toml) {
                    eprintln!("Failed to write config file '{}': {}", config, e);
                    std::process::exit(1);
                }
                println!("Persisted shipper configuration to {}.", config);
            } else {
                let cfg = match read_aeterna_config(&config) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Failed to read config file '{}': {}", config, e);
                        std::process::exit(1);
                    }
                };
                let shipper = cfg.shipper.clone().unwrap_or_default();
                if !shipper.enabled {
                    eprintln!("Shipper is disabled in config. Cannot perform manual flush.");
                    std::process::exit(1);
                }
                if shipper.endpoint_url.is_empty() || shipper.endpoint_pin_sha256.is_empty() {
                    eprintln!("Shipper URL or pin is empty. Configure it first via --url and --pin.");
                    std::process::exit(1);
                }

                println!("Initiating manual shipper push flush to {}...", shipper.endpoint_url);
                let client = match santuario_shipper::build_pinned_client(&shipper.endpoint_pin_sha256) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Failed to initialize TLS client with cert pin: {}", e);
                        std::process::exit(1);
                    }
                };

                let seg_dir = resolve_segment_dir(&cfg);
                let segments = match santuario_shipper::find_finalized(&seg_dir) {
                    Ok(segs) => segs,
                    Err(e) => {
                        eprintln!("Error scanning segment directory: {}", e);
                        std::process::exit(1);
                    }
                };

                let mut pushed_count = 0;
                for seg in &segments {
                    let segment_id = seg.segment_id;
                    let pushed_path = seg.path.clone();
                    let mut os_str = pushed_path.into_os_string();
                    os_str.push(".pushed");
                    let pushed_path = PathBuf::from(os_str);

                    if pushed_path.exists() {
                        continue;
                    }

                    println!("Pushing segment {}...", segment_id);
                    let data = match std::fs::read(&seg.path) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            eprintln!("Failed to read segment {}: {}", segment_id, e);
                            continue;
                        }
                    };

                    match santuario_shipper::client::push_segment(&client, &shipper.endpoint_url, segment_id, data).await {
                        Ok(_) => {
                            println!("Segment {} pushed successfully.", segment_id);
                            use sha2::Digest as _;
                            let metadata = serde_json::json!({
                                "pushed_at": chrono::Utc::now().to_rfc3339(),
                                "size_bytes": seg.size_bytes,
                                "sha256": hex::encode(sha2::Sha256::digest(&std::fs::read(&seg.path).unwrap_or_default())),
                            });
                            let _ = std::fs::write(&pushed_path, metadata.to_string());
                            pushed_count += 1;
                        }
                        Err(e) => {
                            eprintln!("Failed to push segment {}: {}", segment_id, e);
                            std::process::exit(1);
                        }
                    }
                }
                println!("Manual flush complete. Pushed {} segment(s).", pushed_count);
            }
        }
        ShipCmd::Verify { segment_id, config } => {
            let cfg = match read_aeterna_config(&config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to read config file '{}': {}", config, e);
                    std::process::exit(1);
                }
            };
            let shipper = cfg.shipper.clone().unwrap_or_default();
            if !shipper.enabled {
                eprintln!("Shipper is disabled in config.");
                std::process::exit(1);
            }
            if shipper.endpoint_url.is_empty() || shipper.endpoint_pin_sha256.is_empty() {
                eprintln!("Shipper is not configured with URL/pin.");
                std::process::exit(1);
            }

            let seg_dir = resolve_segment_dir(&cfg);
            let segments = match santuario_shipper::find_finalized(&seg_dir) {
                Ok(segs) => segs,
                Err(e) => {
                    eprintln!("Error scanning segment directory: {}", e);
                    std::process::exit(1);
                }
            };

            let matching_seg = segments.into_iter().find(|s| s.segment_id == segment_id);
            if matching_seg.is_none() {
                eprintln!("Segment {} not found locally in directory {}", segment_id, seg_dir.display());
                std::process::exit(1);
            }
            let seg = matching_seg.unwrap();
            let local_bytes = match std::fs::read(&seg.path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("Failed to read local segment file {}: {}", seg.path.display(), e);
                    std::process::exit(1);
                }
            };
            use sha2::Digest as _;
            let local_hash = hex::encode(sha2::Sha256::digest(&local_bytes));

            let client = match santuario_shipper::build_pinned_client(&shipper.endpoint_pin_sha256) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to build pinned TLS client: {}", e);
                    std::process::exit(1);
                }
            };

            let remote_url = format!("{}/{:06}.sigillum", shipper.endpoint_url.trim_end_matches('/'), segment_id);
            println!("Querying remote segment at {}...", remote_url);
            
            let resp = match client.get(&remote_url).send().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Failed to connect to remote: {}", e);
                    std::process::exit(1);
                }
            };

            if !resp.status().is_success() {
                eprintln!("Remote returned error status: {}", resp.status());
                std::process::exit(1);
            }

            let remote_bytes = match resp.bytes().await {
                Ok(b) => b.to_vec(),
                Err(e) => {
                    eprintln!("Failed to read remote response bytes: {}", e);
                    std::process::exit(1);
                }
            };

            let remote_hash = hex::encode(sha2::Sha256::digest(&remote_bytes));
            if local_hash == remote_hash {
                println!("Verification successful! SHA-256 matches: {}", local_hash);
            } else {
                eprintln!("Verification failed! Hash mismatch.");
                eprintln!("  Local:  {}", local_hash);
                eprintln!("  Remote: {}", remote_hash);
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
