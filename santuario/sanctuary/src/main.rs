use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use santuario_sanctuary::spool::SpoolProcessor;
use santuario_sanctuary::MockVault;
use santuario_sanctuary::{SanctuaryError, SanctuaryRecord, SecureStorage};

/// File-backed append-only cold storage for the sanctuary.
pub struct FileSecureStorage {
    file_path: PathBuf,
}

impl FileSecureStorage {
    pub fn new(path: PathBuf) -> Self {
        Self { file_path: path }
    }
}

impl SecureStorage for FileSecureStorage {
    fn append(&mut self, record: SanctuaryRecord) -> Result<(), SanctuaryError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;
        
        let json_line = serde_json::to_string(&record)?;
        writeln!(file, "{}", json_line)?;
        Ok(())
    }

    fn read_all(&self) -> Result<Vec<SanctuaryRecord>, SanctuaryError> {
        if !self.file_path.exists() {
            return Ok(Vec::new());
        }
        let content = fs::read_to_string(&self.file_path)?;
        let mut records = Vec::new();
        for line in content.lines() {
            if !line.trim().is_empty() {
                let rec: SanctuaryRecord = serde_json::from_str(line)?;
                records.push(rec);
            }
        }
        Ok(records)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("Starting AETERNA Data Sanctuary Daemon (Phase H)...");

    // Initialize paths
    let vault_dir = PathBuf::from("santuario/vault");
    let inbound_dir = vault_dir.join("inbound");
    let outbound_dir = vault_dir.join("outbound");
    let cold_storage_path = vault_dir.join("cold_storage.jsonl");

    log::info!("  Inbound spool : {:?}", inbound_dir);
    log::info!("  Outbound spool: {:?}", outbound_dir);
    log::info!("  Cold storage  : {:?}", cold_storage_path);

    // Initialize components
    let vault = MockVault;
    let mut storage = FileSecureStorage::new(cold_storage_path);
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
