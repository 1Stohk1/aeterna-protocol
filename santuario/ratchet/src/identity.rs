//! Signer's long-term X25519 identity key.
//!
//! Mirrors the `MasterLogKey::load_or_generate` pattern from
//! santuario-cipher (Phase A): random 32-byte secret on first boot,
//! atomic write tmp+rename, chmod 0o600 on POSIX, refuses to silently
//! regenerate a corrupted file.
//!
//! The corresponding **public** key is what the operator imports
//! out-of-band (typed into santuarioctl, or scanned from a printed
//! QR code, or copy-pasted from a side channel). The operator never
//! sees the secret.

use std::path::Path;

use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::error::{Error, Result};

/// Length of an X25519 secret/public key on the wire.
pub const X25519_KEY_LEN: usize = 32;

/// Public X25519 identity key. Safe to log / distribute / paste into
/// QR codes. Carries no secret information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerIdentityPublic(pub [u8; X25519_KEY_LEN]);

impl SignerIdentityPublic {
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_bytes(b: [u8; X25519_KEY_LEN]) -> Self {
        Self(b)
    }

    pub(crate) fn to_dalek(&self) -> PublicKey {
        PublicKey::from(self.0)
    }
}

/// Signer's long-term X25519 secret. Process-long; loaded once at
/// signer boot from `<vault>/signer_identity.x25519`.
///
/// `Debug` is hand-redacted: anyone calling `{:?}` on this gets
/// `SignerIdentityKey(<redacted, id=...>)` rather than leaking the
/// secret bytes into a log.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SignerIdentityKey {
    secret: StaticSecret,
}

impl SignerIdentityKey {
    /// Construct from raw bytes. Used by `load_or_generate` and by
    /// tests that want a deterministic identity. Production callers
    /// should NEVER hand-roll bytes -- always go via `generate` or
    /// `load_or_generate`.
    pub fn from_bytes(bytes: [u8; X25519_KEY_LEN]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    /// Generate a fresh random identity from the OS CSPRNG.
    pub fn generate() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// Public half. Cheap to compute (curve25519 base point mult).
    pub fn public(&self) -> SignerIdentityPublic {
        SignerIdentityPublic(PublicKey::from(&self.secret).to_bytes())
    }

    /// 16-byte truncated SHA-256 of the **public** key. Safe to log
    /// or expose. The operator's santuarioctl prints this so they can
    /// confirm "yes, I'm pinning this signer and not a MITM".
    pub fn id_hex(&self) -> String {
        let pk = self.public();
        let digest = Sha256::digest(pk.0);
        hex::encode(&digest[..16])
    }

    /// Crate-internal accessor. The handshake layer needs the
    /// `StaticSecret` to perform ECDH; nobody else.
    pub(crate) fn dalek_secret(&self) -> &StaticSecret {
        &self.secret
    }

    /// Load the identity from `path`, OR generate + persist a fresh
    /// one if the file does not exist. Same first-boot semantics as
    /// `MasterLogKey::load_or_generate` -- this is the boot-time hook
    /// the signer's main calls.
    ///
    /// Refuses to silently regenerate a file with the wrong length:
    /// if the file is corrupted, a fresh random key would orphan
    /// every operator that has imported the previous public half.
    /// Operator must intervene.
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            if bytes.len() != X25519_KEY_LEN {
                return Err(Error::InvalidIdentityKeyFile {
                    path: path.display().to_string(),
                    got: bytes.len(),
                });
            }
            let mut arr = [0u8; X25519_KEY_LEN];
            arr.copy_from_slice(&bytes);
            return Ok(Self::from_bytes(arr));
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let key = Self::generate();
        let raw = key.secret.to_bytes();
        let tmp = path.with_extension("x25519.tmp");
        std::fs::write(&tmp, raw)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&tmp, perms)?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(key)
    }
}

impl std::fmt::Debug for SignerIdentityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignerIdentityKey(<redacted, id={}>)", self.id_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_produces_distinct_keys() {
        let a = SignerIdentityKey::generate();
        let b = SignerIdentityKey::generate();
        assert_ne!(a.public(), b.public());
        assert_ne!(a.id_hex(), b.id_hex());
    }

    #[test]
    fn id_hex_is_16_bytes_of_hex() {
        let k = SignerIdentityKey::generate();
        let h = k.id_hex();
        assert_eq!(h.len(), 32, "16 bytes = 32 hex chars");
        // Round-trip stability.
        assert_eq!(h, k.id_hex());
    }

    #[test]
    fn debug_redacts_secret_bytes() {
        let bytes = [0x01u8; 32];
        let k = SignerIdentityKey::from_bytes(bytes);
        let s = format!("{:?}", k);
        assert!(s.contains("redacted"));
        // The literal "01010101..." must NOT appear in the debug.
        assert!(!s.contains("01, 01, 01"));
    }

    #[test]
    fn load_or_generate_first_boot_creates_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault").join("signer_identity.x25519");
        assert!(!path.exists());
        let k = SignerIdentityKey::load_or_generate(&path).unwrap();
        assert!(path.exists());
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), X25519_KEY_LEN);
        // Loading again must yield the same identity.
        let k2 = SignerIdentityKey::load_or_generate(&path).unwrap();
        assert_eq!(k.public(), k2.public());
    }

    #[test]
    fn load_or_generate_rejects_corrupted_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("signer_identity.x25519");
        // Wrong length: 16 bytes instead of 32. Refusing silent regen
        // is the whole point -- a regen would orphan every operator
        // that already imported the previous public half.
        std::fs::write(&path, [0u8; 16]).unwrap();
        let err = SignerIdentityKey::load_or_generate(&path).unwrap_err();
        assert!(matches!(err, Error::InvalidIdentityKeyFile { .. }), "got {:?}", err);
    }

    #[test]
    fn public_round_trips_through_bytes() {
        let k = SignerIdentityKey::generate();
        let pk = k.public();
        let pk2 = SignerIdentityPublic::from_bytes(*pk.as_bytes());
        assert_eq!(pk, pk2);
        assert_eq!(pk.to_hex(), pk2.to_hex());
    }

    #[cfg(unix)]
    #[test]
    fn load_or_generate_chmods_0o600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("signer_identity.x25519");
        SignerIdentityKey::load_or_generate(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "signer identity key MUST be operator-only on Unix"
        );
    }
}
