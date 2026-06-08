//! santuario-vault — Sovereign Vault.
//!
//! Enforces key envelope integrity and mock TPM2 attestation.

use std::path::PathBuf;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub mod envelope;
pub mod file;

#[cfg(all(target_os = "linux", feature = "tpm2"))]
pub mod tpm2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustTier {
    Osservatore,
    Guardiano,
    Saggio,
    Architetto,
}

impl TrustTier {
    pub fn can_sign(&self) -> bool {
        match self {
            TrustTier::Osservatore => false,
            TrustTier::Guardiano | TrustTier::Saggio | TrustTier::Architetto => true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Vault is sealed")]
    Sealed,

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Vault data has been tampered with or corrupted")]
    Tamper,

    #[error("TPM2 device is unavailable")]
    TpmUnavailable,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(with = "hex")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "hex")]
    pub iv: Vec<u8>,
    pub aad: String,
    #[serde(with = "hex")]
    pub tag: Vec<u8>,
}

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub trait Vault {
    fn tier(&self) -> TrustTier;
    fn is_sealed(&self) -> bool;
    fn unseal(&mut self, ctx: &str) -> Result<(), VaultError>;
    fn reseal(&mut self) -> Result<(), VaultError>;
    fn wrap_dek(&self, dek: &[u8; 32], aad: &str) -> Result<Sealed, VaultError>;
    fn unwrap_dek(&self, sealed: &Sealed) -> Result<[u8; 32], VaultError>;

    fn seal_blob(&self, plaintext: &[u8], label: &str) -> Result<(Sealed, Sealed), VaultError> {
        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);
        let payload = gcm_encrypt(&MasterKey::from_bytes(dek), plaintext, label)?;
        let wrapped = self.wrap_dek(&dek, label)?;
        Ok((wrapped, payload))
    }

    fn open_blob(&self, wrapped_dek: &Sealed, payload: &Sealed) -> Result<Vec<u8>, VaultError> {
        let dek = self.unwrap_dek(wrapped_dek)?;
        gcm_decrypt(&MasterKey::from_bytes(dek), payload)
    }

    fn rotate_dek(&self, wrapped_dek: &Sealed, payload: &Sealed) -> Result<(Sealed, Sealed), VaultError> {
        let old_dek = self.unwrap_dek(wrapped_dek)?;
        let plaintext = gcm_decrypt(&MasterKey::from_bytes(old_dek), payload)?;
        
        let mut new_dek = [0u8; 32];
        OsRng.fill_bytes(&mut new_dek);
        
        let new_payload = gcm_encrypt(&MasterKey::from_bytes(new_dek), &plaintext, &payload.aad)?;
        let new_wrapped = self.wrap_dek(&new_dek, &payload.aad)?;
        Ok((new_wrapped, new_payload))
    }
}

pub fn gcm_encrypt(key: &MasterKey, plaintext: &[u8], aad: &str) -> Result<Sealed, VaultError> {
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&iv);
    let payload = Payload {
        msg: plaintext,
        aad: aad.as_bytes(),
    };
    let ciphertext_with_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|e| VaultError::Crypto(e.to_string()))?;

    if ciphertext_with_tag.len() < 16 {
        return Err(VaultError::Crypto("Invalid ciphertext length".to_string()));
    }
    let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);

    Ok(Sealed {
        ciphertext: ciphertext.to_vec(),
        iv: iv.to_vec(),
        aad: aad.to_string(),
        tag: tag.to_vec(),
    })
}

pub fn gcm_decrypt(key: &MasterKey, sealed: &Sealed) -> Result<Vec<u8>, VaultError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| VaultError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&sealed.iv);
    let payload = Payload {
        msg: &[sealed.ciphertext.as_slice(), sealed.tag.as_slice()].concat(),
        aad: sealed.aad.as_bytes(),
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| VaultError::Tamper)
}

pub fn default_vault_dir() -> PathBuf {
    PathBuf::from("santuario/vault")
}

pub fn fingerprint(data: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
