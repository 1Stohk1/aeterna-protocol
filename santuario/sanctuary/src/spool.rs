use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use santuario_vault::{Sealed, Vault};
use crate::{SanctuaryError, SanctuaryRecord, SecureStorage};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctuaryEnvelope {
    pub sender: String,
    pub seq: u64,
    pub ts_utc: i64,
    pub wrapped_dek: Sealed,
    pub payload_sealed: Sealed,
    pub verifying_key: [u8; 32],
    #[serde(with = "hex")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctuaryResponse {
    pub status: String,
    pub seq: u64,
    pub ts_utc: i64,
    pub error: Option<String>,
}

pub struct SpoolProcessor {
    inbound_dir: PathBuf,
    outbound_dir: PathBuf,
}

impl SpoolProcessor {
    pub fn new<P: AsRef<Path>>(inbound: P, outbound: P) -> Self {
        Self {
            inbound_dir: inbound.as_ref().to_path_buf(),
            outbound_dir: outbound.as_ref().to_path_buf(),
        }
    }

    /// Setup folders if they don't exist
    pub fn setup_dirs(&self) -> Result<(), SanctuaryError> {
        if !self.inbound_dir.exists() {
            fs::create_dir_all(&self.inbound_dir)?;
        }
        if !self.outbound_dir.exists() {
            fs::create_dir_all(&self.outbound_dir)?;
        }
        Ok(())
    }

    /// Process a single envelope file
    pub fn process_file<S: SecureStorage>(
        &self,
        file_path: &Path,
        storage: &mut S,
        vault: &dyn Vault,
    ) -> Result<SanctuaryResponse, SanctuaryError> {
        let content = fs::read(file_path)?;
        let envelope: SanctuaryEnvelope = serde_json::from_slice(&content)?;

        // 1. Decrypt plaintext payload using the Vault
        let decrypted_payload = vault
            .open_blob(&envelope.wrapped_dek, &envelope.payload_sealed)
            .map_err(|e| SanctuaryError::Cipher(format!("Vault decryption failed: {}", e)))?;

        // 2. Validate sender signature using Ed25519
        let pubkey = VerifyingKey::from_bytes(&envelope.verifying_key)
            .map_err(|_| SanctuaryError::Attestation("Invalid verifying key bytes".to_string()))?;
        let sig = Signature::from_bytes(&envelope.signature);

        pubkey
            .verify(&decrypted_payload, &sig)
            .map_err(|_| SanctuaryError::InvalidSignature)?;

        // 3. Append to cold storage
        let record = SanctuaryRecord {
            seq: envelope.seq,
            ts_utc: envelope.ts_utc,
            sender: envelope.sender.clone(),
            payload: decrypted_payload,
            signature: envelope.signature,
        };
        storage.append(record)?;

        // 4. Return success response
        Ok(SanctuaryResponse {
            status: "ok".to_string(),
            seq: envelope.seq,
            ts_utc: envelope.ts_utc,
            error: None,
        })
    }

    /// Poll and sweep all files in inbound directory
    pub fn sweep<S: SecureStorage>(&self, storage: &mut S, vault: &dyn Vault) -> Result<usize, SanctuaryError> {
        self.setup_dirs()?;
        let mut processed_count = 0;

        for entry in fs::read_dir(&self.inbound_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "envelope") {
                let filename = path.file_stem().unwrap().to_string_lossy().into_owned();
                let resp_path = self.outbound_dir.join(format!("{}.response", filename));

                match self.process_file(&path, storage, vault) {
                    Ok(resp) => {
                        let resp_bytes = serde_json::to_vec(&resp)?;
                        fs::write(&resp_path, resp_bytes)?;
                        fs::remove_file(path)?;
                        processed_count += 1;
                    }
                    Err(e) => {
                        log::error!("Error processing spool file {:?}: {:?}", path, e);
                        let err_resp = SanctuaryResponse {
                            status: "error".to_string(),
                            seq: 0,
                            ts_utc: crate::now_utc(),
                            error: Some(e.to_string()),
                        };
                        let resp_bytes = serde_json::to_vec(&err_resp)?;
                        fs::write(&resp_path, resp_bytes)?;
                        // Move file to quarantine or rename to .failed to prevent infinite looping
                        let mut failed_path = path.clone();
                        failed_path.set_extension("failed");
                        fs::rename(path, failed_path)?;
                    }
                }
            }
        }

        Ok(processed_count)
    }
}
