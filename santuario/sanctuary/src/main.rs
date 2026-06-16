use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use serde::Deserialize;

use santuario_sanctuary::spool::SpoolProcessor;
use santuario_sanctuary::MockVault;
use santuario_sanctuary::{SecureStorage, SanctuaryRecord, SanctuaryError};
use santuario_sanctuary::file::FileSecureStorage;
use santuario_sanctuary::ipfs::IpfsSecureStorage;

#[derive(Debug, Deserialize)]
struct VaultConfig {
    #[serde(default = "default_storage_mode")]
    storage_mode: String,
}

fn default_storage_mode() -> String {
    "local_encrypted".to_string()
}

#[derive(Debug, Deserialize)]
struct AeternaConfig {
    #[serde(default)]
    vault: Option<VaultConfig>,
}

enum StorageType {
    File(FileSecureStorage),
    Ipfs(IpfsSecureStorage),
}

impl SecureStorage for StorageType {
    fn append(&mut self, record: SanctuaryRecord) -> Result<(), SanctuaryError> {
        match self {
            StorageType::File(s) => s.append(record),
            StorageType::Ipfs(s) => s.append(record),
        }
    }

    fn read_all(&self) -> Result<Vec<SanctuaryRecord>, SanctuaryError> {
        match self {
            StorageType::File(s) => s.read_all(),
            StorageType::Ipfs(s) => s.read_all(),
        }
    }
}

fn load_config() -> AeternaConfig {
    let config_path = PathBuf::from("aeterna.toml");
    if config_path.exists() {
        if let Ok(content) = fs::read_to_string(&config_path) {
            if let Ok(config) = toml::from_str::<AeternaConfig>(&content) {
                return config;
            }
        }
    }
    AeternaConfig { vault: None }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("Starting AETERNA Data Sanctuary Daemon (Milestone v1.0.0 Sovereign)...");

    let config = load_config();
    let storage_mode = config
        .vault
        .map(|v| v.storage_mode)
        .unwrap_or_else(default_storage_mode);
    log::info!("Configured storage mode: {}", storage_mode);

    // Initialize paths
    let vault_dir = PathBuf::from("santuario/vault");
    let inbound_dir = vault_dir.join("inbound");
    let outbound_dir = vault_dir.join("outbound");
    let cold_storage_path = vault_dir.join("cold_storage.jsonl");
    let ipfs_index_path = vault_dir.join("ipfs_index.jsonl");

    log::info!("  Inbound spool : {:?}", inbound_dir);
    log::info!("  Outbound spool: {:?}", outbound_dir);
    log::info!("  Cold storage  : {:?}", cold_storage_path);

    // Initialize storage based on mode
    let mut storage = if storage_mode == "ipfs" {
        log::info!("  IPFS Index    : {:?}", ipfs_index_path);
        StorageType::Ipfs(IpfsSecureStorage::new(
            "http://127.0.0.1:5001".to_string(),
            "http://127.0.0.1:8080".to_string(),
            ipfs_index_path,
            cold_storage_path,
        ))
    } else {
        StorageType::File(FileSecureStorage::new(cold_storage_path))
    };

    // Initialize components
    let vault = MockVault;
    let processor = SpoolProcessor::new(inbound_dir, outbound_dir);

    // Initial setup
    processor.setup_dirs()?;

    log::info!("Sanctuary Spool Processor loop active. Polling for transactions...");

    loop {
        match processor.sweep(&mut storage, &vault) {
            Ok(count) => {
                if count > 0 {
                    log::info!("Processed {} memory envelope(s) successfully.", count);
                }
            }
            Err(e) => {
                log::error!("Sweep error: {:?}", e);
            }
        }
        thread::sleep(Duration::from_millis(1000));
    }
}
