use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use crate::{SanctuaryError, SanctuaryRecord, SecureStorage};

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
