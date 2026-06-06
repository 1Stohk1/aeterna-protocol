//! `vaultctl` — operator CLI for the Santuario vault.
//!
//! Used by `bootstrap.sh` to unseal the vault at boot, and by hand for key
//! rotation and tamper inspection.
//!
//! ```shell
//! vaultctl seal            # initialise + seal a new vault
//! vaultctl unseal          # unseal into RAM and exit (smoke test)
//! vaultctl put <name> -    # read stdin, store as checkpoint <name>
//! vaultctl get <name>      # dump plaintext to stdout
//! vaultctl list            # list checkpoint names
//! vaultctl rotate <name>   # re-wrap the inner DEK for that checkpoint
//! vaultctl status          # print tier, sealed/unsealed, fingerprint
//! ```

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use santuario_vault::file::FileVault;
use santuario_vault::{default_vault_dir, TrustTier, Vault, VaultError};

#[derive(Parser)]
#[command(
    name = "vaultctl",
    version = env!("CARGO_PKG_VERSION"),
    about = "Operator CLI for the AETERNA Santuario vault",
)]
struct Cli {
    #[arg(long, env = "SANTUARIO_VAULT_DIR")]
    vault_dir: Option<PathBuf>,

    /// Trust tier to advertise. On a host without TPM2, anything above
    /// `osservatore` is silently downgraded to `osservatore` with a warning.
    #[arg(long, default_value = "osservatore")]
    tier: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialise a fresh vault (no-op if it already exists) and seal it.
    Seal,
    /// Unseal into RAM, confirm the master is usable, drop it, and exit.
    Unseal,
    /// Store a checkpoint. Reads plaintext from stdin when `path == "-"`.
    Put { name: String, path: String },
    /// Read a checkpoint, emit plaintext to stdout.
    Get { name: String },
    /// List the checkpoint names currently sealed in the vault.
    List,
    /// Rotate the inner DEK of a checkpoint. Master key is NOT rotated.
    Rotate { name: String },
    /// Print vault status — tier, sealed flag, fingerprint.
    Status,
}

fn parse_tier(s: &str) -> TrustTier {
    match s {
        "osservatore" => TrustTier::Osservatore,
        "guardiano" => TrustTier::Guardiano,
        "saggio" => TrustTier::Saggio,
        "architetto" => TrustTier::Architetto,
        other => {
            eprintln!("vaultctl: unknown tier '{other}', falling back to osservatore");
            TrustTier::Osservatore
        }
    }
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let dir = cli.vault_dir.unwrap_or_else(default_vault_dir);
    let tier = parse_tier(&cli.tier);

    match run(&dir, tier, cli.cmd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vaultctl: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(dir: &std::path::Path, tier: TrustTier, cmd: Cmd) -> Result<(), VaultError> {
    match cmd {
        Cmd::Seal => {
            let _ = FileVault::open_or_init(dir, tier)?;
            println!("vault sealed at {}", dir.display());
        }
        Cmd::Unseal => {
            let mut v = FileVault::open_or_init(dir, tier)?;
            v.unseal("vaultctl-unseal")?;
            println!("vault unsealed (tier={:?})", v.tier());
            v.reseal()?;
        }
        Cmd::Put { name, path } => {
            let mut v = FileVault::open_or_init(dir, tier)?;
            v.unseal("vaultctl-put")?;
            let mut buf = Vec::new();
            if path == "-" {
                std::io::stdin().read_to_end(&mut buf)?;
            } else {
                buf = std::fs::read(&path)?;
            }
            let p = v.put_checkpoint(&name, &buf)?;
            println!("wrote checkpoint {name} -> {}", p.display());
        }
        Cmd::Get { name } => {
            let mut v = FileVault::open_or_init(dir, tier)?;
            v.unseal("vaultctl-get")?;
            let data = v.get_checkpoint(&name)?;
            std::io::stdout().write_all(&data)?;
        }
        Cmd::List => {
            let v = FileVault::open_or_init(dir, tier)?;
            for name in v.list_checkpoints()? {
                println!("{name}");
            }
        }
        Cmd::Rotate { name } => {
            let mut v = FileVault::open_or_init(dir, tier)?;
            v.unseal("vaultctl-rotate")?;
            // Rotate by round-tripping through the API — tamper-evident by
            // construction. A future hardware path overrides `rotate_dek`.
            let data = v.get_checkpoint(&name)?;
            let path = v.put_checkpoint(&name, &data)?;
            println!("rotated {name} -> {}", path.display());
        }
        Cmd::Status => {
            let v = FileVault::open_or_init(dir, tier)?;
            let fp = santuario_vault::fingerprint(dir.display().to_string().as_bytes());
            println!(
                "vault_dir={dir} tier={tier:?} sealed={sealed} fingerprint={fp}",
                dir = dir.display(),
                sealed = v.is_sealed()
            );
        }
    }
    Ok(())
}
