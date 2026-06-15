use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use reqwest::blocking::{Client, multipart};
use serde::{Deserialize, Serialize};

use crate::{SanctuaryError, SanctuaryRecord, SecureStorage};
use crate::file::FileSecureStorage;

#[derive(Debug, Deserialize)]
struct IpfsAddResponse {
    #[serde(rename = "Hash")]
    hash: String,
}

#[derive(Serialize, Deserialize)]
struct IndexEntry {
    cid: String,
    record: SanctuaryRecord,
}

/// IPFS-backed cold storage with local index cache and filesystem fallback.
pub struct IpfsSecureStorage {
    api_url: String,
    _gateway_url: String,
    client: Client,
    index_path: PathBuf,
    fallback: FileSecureStorage,
}

impl IpfsSecureStorage {
    pub fn new(api_url: String, gateway_url: String, index_path: PathBuf, fallback_path: PathBuf) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap_or_else(|_| Client::new());
        let fallback = FileSecureStorage::new(fallback_path);
        Self {
            api_url,
            _gateway_url: gateway_url,
            client,
            index_path,
            fallback,
        }
    }

    fn write_index(&self, cid: &str, record: &SanctuaryRecord) -> Result<(), std::io::Error> {
        let entry = IndexEntry {
            cid: cid.to_string(),
            record: record.clone(),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.index_path)?;
        let json_line = serde_json::to_string(&entry)?;
        writeln!(file, "{}", json_line)?;
        Ok(())
    }
}

impl SecureStorage for IpfsSecureStorage {
    fn append(&mut self, record: SanctuaryRecord) -> Result<(), SanctuaryError> {
        // Serialize the record
        let record_bytes = serde_json::to_vec(&record)?;

        // Prepare multipart upload
        let form = multipart::Form::new()
            .part("file", multipart::Part::bytes(record_bytes).file_name("record.json"));

        let url = format!("{}/api/v0/add", self.api_url);
        log::info!("Attempting to pin SanctuaryRecord to IPFS via {}", url);

        match self.client.post(&url).multipart(form).send() {
            Ok(res) => {
                if res.status().is_success() {
                    match res.json::<IpfsAddResponse>() {
                        Ok(add_resp) => {
                            let cid = add_resp.hash;
                            log::info!("Successfully pinned to IPFS. CID: {}", cid);

                            // Write to local index cache
                            if let Err(e) = self.write_index(&cid, &record) {
                                log::error!("Failed to write to local IPFS index cache: {:?}", e);
                            }
                            
                            // Also append to local fallback for dual-write redundancy
                            let _ = self.fallback.append(record.clone());
                            return Ok(());
                        }
                        Err(e) => {
                            log::warn!("IPFS response deserialization failed: {:?}", e);
                        }
                    }
                } else {
                    log::warn!("IPFS add returned error status: {:?}", res.status());
                }
            }
            Err(e) => {
                log::warn!("IPFS daemon unreachable or request failed: {:?}", e);
            }
        }

        // Fallback to local file storage if IPFS fails
        log::warn!("IPFS upload failed, falling back to local file storage only");
        self.fallback.append(record)
    }

    fn read_all(&self) -> Result<Vec<SanctuaryRecord>, SanctuaryError> {
        if !self.index_path.exists() {
            return self.fallback.read_all();
        }

        let content = fs::read_to_string(&self.index_path)?;
        let mut records = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let index_entry: IndexEntry = match serde_json::from_str(line) {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            // Try to fetch from IPFS first
            let cat_url = format!("{}/api/v0/cat?arg={}", self.api_url, index_entry.cid);
            let mut fetched = false;

            match self.client.post(&cat_url).send() {
                Ok(res) if res.status().is_success() => {
                    if let Ok(rec) = res.json::<SanctuaryRecord>() {
                        records.push(rec);
                        fetched = true;
                    }
                }
                _ => {}
            }

            if !fetched {
                // Return cached version if IPFS fetch failed
                records.push(index_entry.record);
            }
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SanctuaryRecord;
    use tempfile::tempdir;

    #[test]
    fn test_ipfs_fallback_to_file() {
        let dir = tempdir().unwrap();
        let index_path = dir.path().join("ipfs_index.jsonl");
        let fallback_path = dir.path().join("cold_storage.jsonl");

        // Use a bogus port to ensure it is offline and forces fallback
        let mut storage = IpfsSecureStorage::new(
            "http://127.0.0.1:59999".to_string(),
            "http://127.0.0.1:59999".to_string(),
            index_path,
            fallback_path.clone(),
        );

        let rec = SanctuaryRecord {
            seq: 100,
            ts_utc: 123456789,
            sender: "test_sender".to_string(),
            payload: b"offline_fallback_test".to_vec(),
            signature: [0u8; 64],
        };

        // This should fall back to local file and succeed
        assert!(storage.append(rec.clone()).is_ok());

        // Verify fallback file exists and has records
        assert!(fallback_path.exists());
        let all_records = storage.read_all().unwrap();
        assert_eq!(all_records.len(), 1);
        assert_eq!(all_records[0].seq, 100);
        assert_eq!(all_records[0].sender, "test_sender");
        assert_eq!(all_records[0].payload, b"offline_fallback_test");
    }
}
