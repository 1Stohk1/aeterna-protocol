//! santuarioctl — operator-side control CLI for the Santuario v0.2.0 signer.
//!
//! Sprint v0.2.0 "Custos" acceptance criterion #6:
//!
//! > Running `santuarioctl status` on a healthy node prints:
//! > `vault=sealed seccomp=active critic=armed integrity=green signer=ready`.
//!
//! This binary is a thin gRPC client against the santuario-signer process.
//! It respects the same environment variables as the server:
//!
//!   * `SANTUARIO_SOCKET` — Unix Domain Socket path (default
//!     `/run/aeterna/santuario.sock`). Unix only.
//!   * `SANTUARIO_PORT`   — if set, use TCP on 127.0.0.1:$PORT instead.
//!
//! Subcommands:
//!
//!   status       — fetch `GetStatus` and print the single-line banner.
//!   audit        — trigger the α sweep now; optional `--accept` reseals.
//!   resume       — present a Dilithium-5 signed challenge to clear
//!                  a suspension. `--token <hex> --operator <label>`.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tonic::transport::{Channel, Endpoint};

pub mod santuario {
    pub mod signer {
        pub mod v1 {
            tonic::include_proto!("santuario.signer.v1");
        }
    }
}

use santuario::signer::v1::signer_client::SignerClient;
use santuario::signer::v1::{GetStatusRequest, ResumeRequest, TriggerAuditRequest};

#[derive(Parser, Debug)]
#[command(
    name = "santuarioctl",
    version,
    about = "Operator control plane for santuario-signer v0.2.0 (Custos)",
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let channel = connect(&cli).await?;
    let mut client = SignerClient::new(channel);

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
    }
    Ok(())
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
