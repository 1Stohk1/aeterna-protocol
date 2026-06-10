pub mod spool;
pub mod vector;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SanctuaryError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Attestation failure: {0}")]
    Attestation(String),
    #[error("Cipher/vault error: {0}")]
    Cipher(String),
    #[error("Record mismatch or corrupt: {0}")]
    Corrupt(String),
}

/// A transaction containing signed memory context or neural weights.
pub trait MemoryTransaction {
    fn seq(&self) -> u64;
    fn ts_utc(&self) -> i64;
    fn sender(&self) -> &str;
    fn payload(&self) -> &[u8];
    fn signature(&self) -> &[u8; 64];
}

/// A cryptographic signer/verifier interface for memory records.
pub trait RecordSigner {
    fn sign(&self, payload: &[u8]) -> Result<[u8; 64], SanctuaryError>;
    fn verify(&self, payload: &[u8], signature: &[u8; 64]) -> Result<(), SanctuaryError>;
}

/// Abstract secure cold storage layout for the sanctuary.
pub trait SecureStorage {
    fn append(&mut self, record: SanctuaryRecord) -> Result<(), SanctuaryError>;
    fn read_all(&self) -> Result<Vec<SanctuaryRecord>, SanctuaryError>;
}

/// Concrete implementation of `MemoryTransaction`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanctuaryRecord {
    pub seq: u64,
    pub ts_utc: i64,
    pub sender: String,
    pub payload: Vec<u8>,
    #[serde(with = "hex")]
    pub signature: [u8; 64],
}

impl MemoryTransaction for SanctuaryRecord {
    fn seq(&self) -> u64 {
        self.seq
    }
    fn ts_utc(&self) -> i64 {
        self.ts_utc
    }
    fn sender(&self) -> &str {
        &self.sender
    }
    fn payload(&self) -> &[u8] {
        &self.payload
    }
    fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Concrete Ed25519 signer using `ed25519_dalek`.
pub struct Ed25519Signer {
    signing_key: ed25519_dalek::SigningKey,
}

impl Ed25519Signer {
    pub fn new(signing_key: ed25519_dalek::SigningKey) -> Self {
        Self { signing_key }
    }

    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl RecordSigner for Ed25519Signer {
    fn sign(&self, payload: &[u8]) -> Result<[u8; 64], SanctuaryError> {
        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(payload);
        Ok(signature.to_bytes())
    }

    fn verify(&self, payload: &[u8], signature: &[u8; 64]) -> Result<(), SanctuaryError> {
        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.signing_key
            .verifying_key()
            .verify(payload, &sig)
            .map_err(|_| SanctuaryError::InvalidSignature)
    }
}

/// Concrete Ed25519 verifier.
pub struct Ed25519Verifier {
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl Ed25519Verifier {
    pub fn new(verifying_key: ed25519_dalek::VerifyingKey) -> Self {
        Self { verifying_key }
    }
}

impl RecordSigner for Ed25519Verifier {
    fn sign(&self, _payload: &[u8]) -> Result<[u8; 64], SanctuaryError> {
        Err(SanctuaryError::Attestation("Verifier cannot sign".to_string()))
    }

    fn verify(&self, payload: &[u8], signature: &[u8; 64]) -> Result<(), SanctuaryError> {
        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.verifying_key
            .verify(payload, &sig)
            .map_err(|_| SanctuaryError::InvalidSignature)
    }
}

/// Helper in-memory storage implementation for testing and simple environments.
#[derive(Default)]
pub struct InMemorySecureStorage {
    pub records: Vec<SanctuaryRecord>,
}

impl InMemorySecureStorage {
    pub fn new() -> Self {
        Self { records: Vec::new() }
    }
}

impl SecureStorage for InMemorySecureStorage {
    fn append(&mut self, record: SanctuaryRecord) -> Result<(), SanctuaryError> {
        self.records.push(record);
        Ok(())
    }

    fn read_all(&self) -> Result<Vec<SanctuaryRecord>, SanctuaryError> {
        Ok(self.records.clone())
    }
}

/// Current UTC seconds since the epoch.
pub fn now_utc() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// Mock Vault for sanctuary daemon and tests
pub struct MockVault;

impl santuario_vault::Vault for MockVault {
    fn tier(&self) -> santuario_vault::TrustTier {
        santuario_vault::TrustTier::Guardiano
    }

    fn is_sealed(&self) -> bool {
        false
    }

    fn unseal(&mut self, _ctx: &str) -> Result<(), santuario_vault::VaultError> {
        Ok(())
    }

    fn reseal(&mut self) -> Result<(), santuario_vault::VaultError> {
        Ok(())
    }

    fn wrap_dek(&self, dek: &[u8; 32], _aad: &str) -> Result<santuario_vault::Sealed, santuario_vault::VaultError> {
        Ok(santuario_vault::Sealed {
            ciphertext: dek.to_vec(),
            iv: vec![0u8; 12],
            aad: String::new(),
            tag: vec![0u8; 16],
        })
    }

    fn unwrap_dek(&self, sealed: &santuario_vault::Sealed) -> Result<[u8; 32], santuario_vault::VaultError> {
        let mut dek = [0u8; 32];
        if sealed.ciphertext.len() == 32 {
            dek.copy_from_slice(&sealed.ciphertext);
            Ok(dek)
        } else {
            Err(santuario_vault::VaultError::Crypto("Invalid DEK length".to_string()))
        }
    }

    fn open_blob(&self, wrapped_dek: &santuario_vault::Sealed, payload: &santuario_vault::Sealed) -> Result<Vec<u8>, santuario_vault::VaultError> {
        let dek = self.unwrap_dek(wrapped_dek)?;
        santuario_vault::gcm_decrypt(&santuario_vault::MasterKey::from_bytes(dek), payload)
    }

    fn seal_blob(&self, plaintext: &[u8], label: &str) -> Result<(santuario_vault::Sealed, santuario_vault::Sealed), santuario_vault::VaultError> {
        let mut dek = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut dek);
        let payload = santuario_vault::gcm_encrypt(&santuario_vault::MasterKey::from_bytes(dek), plaintext, label)?;
        let wrapped = self.wrap_dek(&dek, label)?;
        Ok((wrapped, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use crate::vector::ContextVectorRecord;
    use crate::spool::{SpoolProcessor, SanctuaryEnvelope};
    use rand::rngs::OsRng;
    use santuario_vault::{Sealed, Vault, VaultError, TrustTier};

    #[test]
    fn test_signature_verification() {
        let mut rng = OsRng;
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut secret);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let signer = Ed25519Signer::new(signing_key);

        let payload = b"Hello, AETERNA Data Sanctuary!";
        let signature = signer.sign(payload).unwrap();

        // Verification using signer (which holds public key)
        assert!(signer.verify(payload, &signature).is_ok());

        // Verification using separate verifier
        let verifier = Ed25519Verifier::new(signer.verifying_key());
        assert!(verifier.verify(payload, &signature).is_ok());

        // Tampered payload fails
        assert!(verifier.verify(b"tampered payload", &signature).is_err());
    }

    #[test]
    fn test_context_vector_signing_and_similarity() {
        let mut rng = OsRng;
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut secret);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let signer = Ed25519Signer::new(signing_key);

        let vector = ContextVectorRecord {
            vector_id: "test-v1".to_string(),
            dimensions: 3,
            values: vec![1.0, 0.0, 0.0],
            metadata: serde_json::json!({"model": "test"}),
        };

        let record = vector.serialize_and_sign(&signer, 42, "sentinel-1".to_string()).unwrap();
        assert_eq!(record.seq, 42);
        assert_eq!(record.sender, "sentinel-1");

        let verifier = Ed25519Verifier::new(signer.verifying_key());
        let recovered = ContextVectorRecord::verify_and_deserialize(&record, &verifier).unwrap();
        assert_eq!(recovered, vector);

        // Cosine similarity check
        let orth_vector = ContextVectorRecord {
            vector_id: "test-v2".to_string(),
            dimensions: 3,
            values: vec![0.0, 1.0, 0.0],
            metadata: serde_json::json!({}),
        };
        let similarity = vector.cosine_similarity(&orth_vector).unwrap();
        assert!(similarity.abs() < 1e-6); // Orthogonal vectors -> similarity 0.0
    }

    #[test]
    fn test_spool_processor_flow() {
        let dir = tempfile::tempdir().unwrap();
        let inbound = dir.path().join("inbound");
        let outbound = dir.path().join("outbound");

        let processor = SpoolProcessor::new(&inbound, &outbound);
        processor.setup_dirs().unwrap();

        let vault = MockVault;
        let mut storage = InMemorySecureStorage::new();

        // 1. Create a signed and sealed envelope
        let mut rng = OsRng;
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut secret);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let signer = Ed25519Signer::new(signing_key);

        let raw_data = b"secret contextual memory payload";
        let (wrapped_dek, payload_sealed) = vault.seal_blob(raw_data, "sanctuary_test").unwrap();
        let signature = signer.sign(raw_data).unwrap();

        let envelope = SanctuaryEnvelope {
            sender: "neural_node_1".to_string(),
            seq: 1,
            ts_utc: now_utc(),
            wrapped_dek,
            payload_sealed,
            verifying_key: signer.verifying_key().to_bytes(),
            signature,
        };

        let envelope_path = inbound.join("tx_1.envelope");
        fs::write(&envelope_path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        // 2. Run sweep
        let count = processor.sweep(&mut storage, &vault).unwrap();
        assert_eq!(count, 1);

        // 3. Verify storage updated correctly
        assert_eq!(storage.records.len(), 1);
        let stored = &storage.records[0];
        assert_eq!(stored.seq, 1);
        assert_eq!(stored.sender, "neural_node_1");
        assert_eq!(stored.payload, raw_data);

        // 4. Verify envelope was deleted and response created
        assert!(!envelope_path.exists());
        let response_path = outbound.join("tx_1.response");
        assert!(response_path.exists());
    }
}
