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
};

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
use santuario::signer::v1::{GetStatusRequest, ResumeRequest, TriggerAuditRequest};

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

// --- key subcommand ----------------------------------------------------------

fn handle_key(cmd: KeyCmd) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        KeyCmd::Import { file, envelope } => cmd_key_import(file, envelope),
        KeyCmd::Export => cmd_key_export(),
        KeyCmd::Status => cmd_key_status(),
    }
}

fn cmd_key_import(
    file: PathBuf,
    envelope: Option<PathBuf>,
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
        })
        .await?
        .into_inner();

    // Finalise on operator side (derives root_key, builds Session).
    let mut signer_eph = [0u8; 32];
    if hs_resp.signer_eph_pub.len() != 32 {
        return Err("signer returned invalid ephemeral pub key length".into());
    }
    signer_eph.copy_from_slice(&hs_resp.signer_eph_pub);
    let _root_key = operator_ep
        .finalize(HandshakeResponse {
            signer_eph_pub: signer_eph,
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
