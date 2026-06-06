//! File-backed vault. Used only on `osservatore` tier; the master key sits
//! on disk encrypted with a key derived from the file's own random salt.
//! It is NOT a substitute for TPM2 sealing — a local attacker with read
//! access to the vault directory can extract the master. That is the cost of
//! not having attested hardware.

use std::fs;
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{gcm_decrypt, gcm_encrypt, MasterKey, Sealed, TrustTier, Vault, VaultError};

const MANIFEST: &str = "vault.manifest.json";

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    /// Per-vault 32-byte salt used to derive the KEK from a constant node
    /// identity. This is deliberately low-security: the node is `osservatore`,
    /// any attacker on the box can unseal. The salt exists only so two
    /// different file-vaults on the same host diverge.
    #[serde(with = "hex")]
    salt: Vec<u8>,
    /// Master key, AES-256-GCM-sealed under the KEK. AAD is the salt.
    master: Sealed,
    /// Vault format version. Bumped when the envelope layout changes.
    version: u32,
}

/// The file vault. Stores:
///
/// - `vault.manifest.json` — public salt + sealed master
/// - `checkpoints/<name>.sealed.json` — per-checkpoint blobs
pub struct FileVault {
    dir: PathBuf,
    tier: TrustTier,
    master: Option<MasterKey>,
    manifest: Manifest,
}

impl FileVault {
    pub fn open_or_init(dir: &Path, tier: TrustTier) -> Result<Self, VaultError> {
        fs::create_dir_all(dir)?;
        let path = dir.join(MANIFEST);
        let manifest = if path.exists() {
            let data = fs::read(&path)?;
            serde_json::from_slice::<Manifest>(&data)?
        } else {
            let mut salt = vec![0u8; 32];
            OsRng.fill_bytes(&mut salt);
            let master = MasterKey::generate();
            let kek = derive_kek(&salt);
            let sealed = gcm_encrypt(&kek, master.as_bytes(), &hex::encode(&salt))?;
            let m = Manifest {
                salt,
                master: sealed,
                version: 1,
            };
            let json = serde_json::to_vec_pretty(&m)?;
            atomic_write(&path, &json)?;
            #[cfg(unix)]
            harden_mode(&path)?;
            m
        };
        fs::create_dir_all(dir.join("checkpoints"))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            tier,
            master: None,
            manifest,
        })
    }

    fn master_ref(&self) -> Result<&MasterKey, VaultError> {
        self.master.as_ref().ok_or(VaultError::Sealed)
    }
}

impl Vault for FileVault {
    fn tier(&self) -> TrustTier {
        self.tier
    }

    fn is_sealed(&self) -> bool {
        self.master.is_none()
    }

    fn unseal(&mut self, _ctx: &str) -> Result<(), VaultError> {
        if self.master.is_some() {
            return Ok(());
        }
        let kek = derive_kek(&self.manifest.salt);
        let bytes = gcm_decrypt(&kek, &self.manifest.master)?;
        if bytes.len() != 32 {
            return Err(VaultError::Crypto("master key not 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        self.master = Some(MasterKey::from_bytes(arr));
        let mut scratch = bytes;
        scratch.zeroize();
        Ok(())
    }

    fn reseal(&mut self) -> Result<(), VaultError> {
        self.master = None;
        Ok(())
    }

    fn wrap_dek(&self, dek: &[u8; 32], aad: &str) -> Result<Sealed, VaultError> {
        gcm_encrypt(self.master_ref()?, dek, aad)
    }

    fn unwrap_dek(&self, sealed: &Sealed) -> Result<[u8; 32], VaultError> {
        let bytes = gcm_decrypt(self.master_ref()?, sealed)?;
        if bytes.len() != 32 {
            return Err(VaultError::Crypto("unwrapped DEK not 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl FileVault {
    /// Persist a named checkpoint under the vault. Used by the `vaultctl`
    /// CLI and by higher-level envelope writers.
    pub fn put_checkpoint(&self, name: &str, plaintext: &[u8]) -> Result<PathBuf, VaultError> {
        let (wrapped, sealed) = self.seal_blob(plaintext, &format!("checkpoint:{name}"))?;
        #[derive(Serialize)]
        struct OnDisk<'a> {
            wrapped: &'a Sealed,
            sealed: &'a Sealed,
            created: String,
            name: &'a str,
        }
        let od = OnDisk {
            wrapped: &wrapped,
            sealed: &sealed,
            created: chrono::Utc::now().to_rfc3339(),
            name,
        };
        let path = self
            .dir
            .join("checkpoints")
            .join(format!("{name}.sealed.json"));
        atomic_write(&path, &serde_json::to_vec_pretty(&od)?)?;
        #[cfg(unix)]
        harden_mode(&path)?;
        Ok(path)
    }

    /// Read back a checkpoint by name.
    pub fn get_checkpoint(&self, name: &str) -> Result<Vec<u8>, VaultError> {
        #[derive(Deserialize)]
        struct OnDisk {
            wrapped: Sealed,
            sealed: Sealed,
        }
        let path = self
            .dir
            .join("checkpoints")
            .join(format!("{name}.sealed.json"));
        let data = fs::read(&path)?;
        let od: OnDisk = serde_json::from_slice(&data)?;
        self.open_blob(&od.wrapped, &od.sealed)
    }

    /// List every checkpoint the vault currently stores.
    pub fn list_checkpoints(&self) -> Result<Vec<String>, VaultError> {
        let dir = self.dir.join("checkpoints");
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if let Some(stem) = name.strip_suffix(".sealed.json") {
                    out.push(stem.to_string());
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

/// Derive the Key-Encryption-Key from the per-vault salt plus a fixed
/// application-scope label. In the `osservatore` tier this is symbolic
/// hardening — anyone with the salt can recompute the KEK.
fn derive_kek(salt: &[u8]) -> MasterKey {
    let hk = Hkdf::<Sha256>::new(Some(salt), b"aeterna-santuario-file-vault-v1");
    let mut out = [0u8; 32];
    hk.expand(b"kek", &mut out)
        .expect("HKDF expand never fails for 32 bytes");
    MasterKey::from_bytes(out)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn harden_mode(path: &Path) -> Result<(), VaultError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip_checkpoint() {
        let dir = tempdir().unwrap();
        let mut v = FileVault::open_or_init(dir.path(), TrustTier::Osservatore).unwrap();
        v.unseal("test").unwrap();
        let path = v.put_checkpoint("alpha", b"hello secret").unwrap();
        assert!(path.exists());
        let got = v.get_checkpoint("alpha").unwrap();
        assert_eq!(got, b"hello secret");
    }

    #[test]
    fn list_checkpoints_is_sorted() {
        let dir = tempdir().unwrap();
        let mut v = FileVault::open_or_init(dir.path(), TrustTier::Osservatore).unwrap();
        v.unseal("t").unwrap();
        v.put_checkpoint("b-second", b"x").unwrap();
        v.put_checkpoint("a-first", b"y").unwrap();
        let list = v.list_checkpoints().unwrap();
        assert_eq!(list, vec!["a-first".to_string(), "b-second".to_string()]);
    }

    #[test]
    fn sealed_blob_tamper_rejected() {
        let dir = tempdir().unwrap();
        let mut v = FileVault::open_or_init(dir.path(), TrustTier::Osservatore).unwrap();
        v.unseal("t").unwrap();
        let (wrapped, mut sealed) = v.seal_blob(b"critical data", "unit-test").unwrap();
        sealed.ciphertext[0] ^= 0xFF;
        match v.open_blob(&wrapped, &sealed) {
            Err(VaultError::Tamper) => {}
            other => panic!("expected Tamper, got {other:?}"),
        }
    }

    #[test]
    fn reseal_hides_master() {
        let dir = tempdir().unwrap();
        let mut v = FileVault::open_or_init(dir.path(), TrustTier::Osservatore).unwrap();
        v.unseal("t").unwrap();
        assert!(!v.is_sealed());
        v.reseal().unwrap();
        assert!(v.is_sealed());
        assert!(matches!(
            v.wrap_dek(&[0u8; 32], "x"),
            Err(VaultError::Sealed)
        ));
    }

    #[test]
    fn osservatore_tier_refuses_signing() {
        let dir = tempdir().unwrap();
        let v = FileVault::open_or_init(dir.path(), TrustTier::Osservatore).unwrap();
        assert!(!v.tier().can_sign());
    }
}
