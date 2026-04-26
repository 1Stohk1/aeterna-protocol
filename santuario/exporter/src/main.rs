//! santuario-exporter -- Phase D entrypoint.
//!
//! Wires the three layers:
//!   admin_client::AdminGrpcClient   -- consumer of Santuario.GetMetrics
//!   render::render                  -- pure formatter (Prometheus 0.0.4)
//!   server::serve                   -- hyper /metrics endpoint
//!
//! Configuration sources (precedence: CLI > env > default):
//!   --bind / $AETERNA_EXPORTER_BIND          (default 127.0.0.1:9477)
//!   --admin-endpoint / $SANTUARIO_PORT       (default 127.0.0.1:50051)
//!   --network / $AETERNA_NETWORK             (default "aeterna-testnet-0")
//!   --julia-version / $AETERNA_JULIA_VERSION (default "unknown")
//!
//! The `$SANTUARIO_PORT` integration mirrors what bootstrap.ps1 already
//! exports for the signer + sentinel, so a single env var keeps three
//! processes agreeing on the gRPC target.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use clap::Parser;

use santuario_exporter::admin_client::AdminGrpcClient;
use santuario_exporter::render::NodeIdentity;
use santuario_exporter::server::{self, ExporterState};

#[derive(Parser, Debug)]
#[command(
    name = "santuario-exporter",
    about = "AETERNA v0.3.0 \"Oculus\" Prometheus exporter -- /metrics over hyper, fed by Santuario.Admin gRPC."
)]
struct Cli {
    /// HTTP bind address. Defaults to loopback for safety.
    #[arg(long, env = "AETERNA_EXPORTER_BIND", default_value = "127.0.0.1:9477")]
    bind: SocketAddr,

    /// Santuario gRPC endpoint as host:port (no scheme). When omitted,
    /// falls back to env: $AETERNA_ADMIN_ENDPOINT, then to a value built
    /// from $SANTUARIO_PORT, then to the default 127.0.0.1:50051. The
    /// $SANTUARIO_PORT path is what bootstrap.ps1 uses to multi-instance.
    #[arg(long, env = "AETERNA_ADMIN_ENDPOINT")]
    admin_endpoint: Option<String>,

    /// Network identifier baked into aeterna_node_info.
    #[arg(long, env = "AETERNA_NETWORK", default_value = "aeterna-testnet-0")]
    network: String,

    /// Julia version baked into aeterna_node_info. Bootstrap.ps1 can
    /// resolve this from `julia --version` and export it; without that
    /// it just shows as "unknown" which is fine for non-prod.
    #[arg(long, env = "AETERNA_JULIA_VERSION", default_value = "unknown")]
    julia_version: String,
}

fn resolve_admin_endpoint(cli: &Cli) -> String {
    if let Some(ref ep) = cli.admin_endpoint {
        return ep.clone();
    }
    if let Ok(port) = std::env::var("SANTUARIO_PORT") {
        return format!("127.0.0.1:{}", port);
    }
    "127.0.0.1:50051".to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    // env_logger respects RUST_LOG; bootstrap.ps1 can pass RUST_LOG=info
    // via Start-Child's ExtraEnv if richer logging is desired.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let cli = Cli::parse();
    let admin_endpoint = resolve_admin_endpoint(&cli);

    log::info!(
        "santuario-exporter v{} bind={} admin_endpoint={}",
        env!("CARGO_PKG_VERSION"),
        cli.bind,
        admin_endpoint
    );

    let identity = NodeIdentity {
        network: cli.network,
        version: env!("CARGO_PKG_VERSION").to_string(),
        julia_version: cli.julia_version,
        pq_sig: "Dilithium-5".to_string(),
        pq_kem: "Kyber-1024".to_string(),
    };

    let client = AdminGrpcClient::new(admin_endpoint);
    let state = ExporterState::new(client, identity);

    server::serve(cli.bind, state)
        .await
        .context("HTTP server returned error")?;

    log::info!("santuario-exporter shutdown complete");
    Ok(())
}
