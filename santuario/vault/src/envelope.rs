//! High-level envelope-encryption writer/reader.
//!
//! Wraps any [`Vault`] backend so that callers never touch AES-GCM directly.
//! Usage:
//!
//! ```no_run
//! use santuario_vault::{file::FileVault, envelope::EnvelopeWriter, TrustTier, Vault};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut v = FileVault::open_or_init(std::path::Path::new("/tmp/vault"), TrustTier::Osservatore)?;
//! v.unseal("bootstrap")?;
//! let w = EnvelopeWriter::new(&v);
//! let record = w.put("sentinel.state", b"... serialised state ...")?;
//! let rt = w.get(&record)?;
//! assert_eq!(rt, b"... serialised state ...");
//! # Ok(()) }
//! ```

use serde::{Deserialize, Serialize};

use crate::{Sealed, Vault, VaultError};

/// A sealed envelope on the wire. The inner DEK is wrapped under the vault's
/// master; the payload is encrypted under the DEK. Rotating the master only
/// requires re-wrapping [`EnvelopeRecord::wrapped_dek`] — the bulk ciphertext
/// is untouched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeRecord {
    pub label: String,
    pub created_utc: String,
    pub wrapped_dek: Sealed,
    pub payload: Sealed,
}

pub struct EnvelopeWriter<'v> {
    vault: &'v dyn Vault,
}

impl<'v> EnvelopeWriter<'v> {
    pub fn new(vault: &'v dyn Vault) -> Self {
        Self { vault }
    }

    /// Encrypt `plaintext` under a fresh DEK and wrap the DEK under the
    /// vault master. `label` is bound into the AAD so the ciphertext cannot
    /// be silently swapped between purposes (e.g. swapping the checkpoint
    /// for the Dilithium secret key).
    pub fn put(&self, label: &str, plaintext: &[u8]) -> Result<EnvelopeRecord, VaultError> {
        let (wrapped, payload) = self.vault.seal_blob(plaintext, label)?;
        Ok(EnvelopeRecord {
            label: label.to_string(),
            created_utc: chrono::Utc::now().to_rfc3339(),
            wrapped_dek: wrapped,
            payload,
        })
    }

    pub fn get(&self, record: &EnvelopeRecord) -> Result<Vec<u8>, VaultError> {
        self.vault.open_blob(&record.wrapped_dek, &record.payload)
    }

    /// Rotate the inner DEK on an existing record — useful for hygiene
    /// sweeps even when the master has not changed.
    pub fn rotate(&self, record: &EnvelopeRecord) -> Result<EnvelopeRecord, VaultError> {
        let (wrapped, payload) = self
            .vault
            .rotate_dek(&record.wrapped_dek, &record.payload)?;
        Ok(EnvelopeRecord {
            label: record.label.clone(),
            created_utc: chrono::Utc::now().to_rfc3339(),
            wrapped_dek: wrapped,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::FileVault;
    use crate::TrustTier;
    use tempfile::tempdir;

    fn fixture() -> (tempfile::TempDir, FileVault) {
        let d = tempdir().unwrap();
        let mut v = FileVault::open_or_init(d.path(), TrustTier::Osservatore).unwrap();
        v.unseal("test").unwrap();
        (d, v)
    }

    #[test]
    fn envelope_put_get_roundtrip() {
        let (_d, v) = fixture();
        let w = EnvelopeWriter::new(&v);
        let rec = w.put("l1", b"payload").unwrap();
        let rt = w.get(&rec).unwrap();
        assert_eq!(rt, b"payload");
    }

    #[test]
    fn envelope_label_mismatch_tampers() {
        let (_d, v) = fixture();
        let w = EnvelopeWriter::new(&v);
        let mut rec = w.put("label-a", b"p").unwrap();
        rec.payload.aad = "label-b".to_string();
        match w.get(&rec) {
            Err(VaultError::Tamper) => {}
            other => panic!("expected Tamper, got {other:?}"),
        }
    }

    #[test]
    fn envelope_rotate_round_trips() {
        let (_d, v) = fixture();
        let w = EnvelopeWriter::new(&v);
        let rec = w.put("rotme", b"contents").unwrap();
        let rotated = w.rotate(&rec).unwrap();
        assert_ne!(rec.wrapped_dek.ciphertext, rotated.wrapped_dek.ciphertext);
        assert_eq!(w.get(&rotated).unwrap(), b"contents");
    }
}
