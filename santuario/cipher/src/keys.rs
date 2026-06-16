//! Key types for Sigillum.
//!
//! Layered hierarchy:
//!
//! ```text
//!   BIP-39 seed (24 words, operator memorizes / paper-backs)
//!         |  PBKDF2 / Argon2  (Phase C, in santuario-ratchet -- not here)
//!         v
//!   master_secret (256 bits)
//!         |  HKDF-SHA256, info="aeterna-sigillum-master-log-key-v1"
//!         v
//!   MasterLogKey (this module)
//!         |  HKDF-SHA256, info="aeterna-sigillum-log-segment-v1" || segment_id
//!         v
//!   SegmentSubKey + nonce_prefix (one per .sigillum file)
//!         |  ChaCha20-Poly1305 with nonce = nonce_prefix || record_counter_le
//!         v
//!   Per-record sealed bytes
//! ```
//!
//! `MasterLogKey` is `Zeroize` -- its bytes are wiped on drop. Same
//! for `SegmentSubKey`. Identifiers (`MasterKeyId`) are public and
//! safe to log; key material is not.

use std::path::Path;

use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// 16-byte public identifier for a master key. Computed as the first
/// 16 bytes of SHA-256(master_key_bytes). Safe to log, safe to embed
/// in segment headers; reveals nothing about the key itself thanks to
/// the one-way hash + truncation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MasterKeyId(pub [u8; 16]);

impl MasterKeyId {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// 32-byte master key for the audit log. Lifetime: process-long, set
/// once at sentinel boot from the operator's BIP-39 seed.
///
/// `Debug` is intentionally NOT derived; we hand-implement it to
/// redact the bytes. Anyone calling `{:?}` on a MasterLogKey gets
/// "MasterLogKey(<redacted, id=...>)" instead of leaking key material
/// into a log.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MasterLogKey {
    bytes: [u8; 32],
}

impl MasterLogKey {
    pub const LEN: usize = 32;

    /// Construct directly from raw bytes. Used by the BIP-39 deriver
    /// in santuario-ratchet (Phase C); also used in tests.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Retrieve the raw 32 bytes of the MasterLogKey.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Generate a fresh random master key from the OS CSPRNG.
    /// Production callers should prefer `load_or_generate` so the key
    /// is persisted; this constructor exists for tests and for
    /// in-memory scratch deployments where loss-on-restart is intended.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Load the master key from `path`, OR generate a fresh one and
    /// persist it if the file does not exist yet.
    ///
    /// On creation: the file is `chmod 0o600` on Unix; on Windows the
    /// inherited ACL is used (the operator's vault directory should
    /// itself be operator-only ACL'd by `bootstrap.ps1`).
    ///
    /// Returns `Err(Error::Invariant)` if the file exists but is not
    /// exactly 32 bytes -- treats this as a corrupted key file rather
    /// than silently regenerating, because silent regeneration would
    /// orphan every encrypted segment sealed under the prior key.
    ///
    /// **Phase A note**: this is the v0.4 provisioning path. Phase C
    /// will replace the random-on-first-boot semantics with BIP-39
    /// seed derivation, but the on-disk layout (`<vault>/log_master.key`,
    /// 32 bytes raw, 0o600) and the `MasterLogKey` type stay stable so
    /// the migration is a one-line swap at the call site.
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            if bytes.len() != Self::LEN {
                return Err(Error::Invariant(
                    "log_master.key has wrong length -- corrupted or wrong file",
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(Self::from_bytes(arr));
        }

        // First-boot path: generate, write atomically (write to .tmp then
        // rename) so a crash mid-write doesn't leave a partial key file
        // that the next boot would reject as corrupted.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let key = Self::generate();
        let tmp = path.with_extension("key.tmp");
        std::fs::write(&tmp, key.bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&tmp, perms)?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(key)
    }

    /// Public identifier -- safe to expose, log, embed in headers.
    pub fn id(&self) -> MasterKeyId {
        let digest = Sha256::digest(self.bytes);
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        MasterKeyId(id)
    }

    /// Internal accessor -- intentionally crate-private. External
    /// callers MUST go through `derive_segment_subkey`. Used by Phase B
    /// (gossip) and Phase C (ratchet) which derive their own subkeys
    /// from the same master.
    #[allow(dead_code)]
    pub(crate) fn raw(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Derive a per-segment subkey + nonce_prefix from this master.
    ///
    /// Output layout: 32 bytes of subkey followed by 8 bytes of
    /// nonce_prefix. Total OKM = 40 bytes.
    pub fn derive_segment_subkey(&self, segment_id: u64) -> Result<SegmentSubKey> {
        let salt = self.id().0;
        let mut info = Vec::with_capacity(48);
        info.extend_from_slice(b"aeterna-sigillum-log-segment-v1");
        info.extend_from_slice(&segment_id.to_le_bytes());

        let hk = Hkdf::<Sha256>::new(Some(&salt), &self.bytes);
        let mut okm = [0u8; 40];
        hk.expand(&info, &mut okm)
            .map_err(|_| Error::Kdf("hkdf expand failed for segment subkey"))?;

        let mut subkey = [0u8; 32];
        subkey.copy_from_slice(&okm[..32]);
        let mut nonce_prefix = [0u8; 8];
        nonce_prefix.copy_from_slice(&okm[32..40]);

        // Wipe the intermediate OKM buffer immediately.
        okm.zeroize();

        Ok(SegmentSubKey {
            subkey,
            nonce_prefix,
            segment_id,
        })
    }
}

impl std::fmt::Debug for MasterLogKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterLogKey(<redacted, id={}>)", self.id().to_hex())
    }
}

/// Per-segment derived key + nonce prefix. Owns ~40 bytes of secret
/// material. Wiped on drop via `ZeroizeOnDrop`.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SegmentSubKey {
    subkey: [u8; 32],
    nonce_prefix: [u8; 8],
    #[zeroize(skip)]
    segment_id: u64,
}

impl SegmentSubKey {
    pub fn segment_id(&self) -> u64 {
        self.segment_id
    }

    pub(crate) fn subkey(&self) -> &[u8; 32] {
        &self.subkey
    }

    /// Crate-internal accessor used by tests and future Phase B/C
    /// integrations that need the raw nonce prefix (e.g., for shared
    /// random/derivation logic across surfaces).
    #[allow(dead_code)]
    pub(crate) fn nonce_prefix(&self) -> &[u8; 8] {
        &self.nonce_prefix
    }

    /// Build a 12-byte ChaCha20-Poly1305 nonce from
    /// `nonce_prefix(8) || record_counter_le(4)`.
    pub fn nonce_for_record(&self, record_counter: u32) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.nonce_prefix);
        n[8..].copy_from_slice(&record_counter.to_le_bytes());
        n
    }
}

impl std::fmt::Debug for SegmentSubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SegmentSubKey(<redacted, segment_id={}>)", self.segment_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_master() -> MasterLogKey {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        MasterLogKey::from_bytes(k)
    }

    #[test]
    fn master_id_is_deterministic() {
        let k = dummy_master();
        let id1 = k.id();
        let id2 = k.id();
        assert_eq!(id1, id2);
        assert_eq!(id1.0.len(), 16);
    }

    #[test]
    fn master_debug_redacts() {
        let k = dummy_master();
        let s = format!("{:?}", k);
        assert!(s.contains("redacted"));
        // The actual bytes 0..32 must NOT appear in any obvious form.
        assert!(!s.contains("0x00, 0x01, 0x02"));
    }

    #[test]
    fn subkey_derivation_is_deterministic() {
        let k = dummy_master();
        let s1 = k.derive_segment_subkey(42).unwrap();
        let s2 = k.derive_segment_subkey(42).unwrap();
        assert_eq!(s1.subkey(), s2.subkey());
        assert_eq!(s1.nonce_prefix(), s2.nonce_prefix());
    }

    #[test]
    fn different_segments_produce_different_subkeys() {
        let k = dummy_master();
        let s1 = k.derive_segment_subkey(1).unwrap();
        let s2 = k.derive_segment_subkey(2).unwrap();
        assert_ne!(s1.subkey(), s2.subkey(), "segment_id MUST diversify subkey");
        assert_ne!(s1.nonce_prefix(), s2.nonce_prefix(),
            "segment_id MUST diversify nonce_prefix to prevent cross-segment reuse");
    }

    #[test]
    fn different_masters_produce_different_subkeys_for_same_segment() {
        let k1 = dummy_master();
        let mut bytes = [0u8; 32];
        bytes[0] = 1;  // differs from dummy_master in exactly one bit
        let k2 = MasterLogKey::from_bytes(bytes);
        let s1 = k1.derive_segment_subkey(0).unwrap();
        let s2 = k2.derive_segment_subkey(0).unwrap();
        assert_ne!(s1.subkey(), s2.subkey());
        assert_ne!(s1.nonce_prefix(), s2.nonce_prefix());
    }

    #[test]
    fn nonce_for_record_layout() {
        let k = dummy_master();
        let s = k.derive_segment_subkey(7).unwrap();
        let nonce = s.nonce_for_record(0xDEADBEEF);
        assert_eq!(&nonce[..8], s.nonce_prefix());
        assert_eq!(&nonce[8..], &0xDEADBEEFu32.to_le_bytes());
    }

    #[test]
    fn nonce_uniqueness_across_counter() {
        let k = dummy_master();
        let s = k.derive_segment_subkey(0).unwrap();
        let n1 = s.nonce_for_record(0);
        let n2 = s.nonce_for_record(1);
        assert_ne!(n1, n2);
    }

    #[test]
    fn generate_produces_distinct_keys() {
        // Two consecutive generations almost certainly differ;
        // collision probability is 2^-256.
        let k1 = MasterLogKey::generate();
        let k2 = MasterLogKey::generate();
        assert_ne!(k1.id(), k2.id());
    }

    #[test]
    fn load_or_generate_creates_file_on_first_call() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault").join("log_master.key");
        assert!(!path.exists());
        let k = MasterLogKey::load_or_generate(&path).unwrap();
        assert!(path.exists(), "first call must persist the key file");
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 32, "persisted key must be exactly 32 bytes");
        assert_eq!(&bytes[..], k.raw());
    }

    #[test]
    fn load_or_generate_returns_same_key_on_second_call() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log_master.key");
        let k1 = MasterLogKey::load_or_generate(&path).unwrap();
        let k2 = MasterLogKey::load_or_generate(&path).unwrap();
        assert_eq!(
            k1.id(),
            k2.id(),
            "persistence: second load must yield the original key"
        );
    }

    #[test]
    fn load_or_generate_rejects_corrupted_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log_master.key");
        // Wrong length on purpose -- 16 bytes instead of 32.
        std::fs::write(&path, [0u8; 16]).unwrap();
        let err = MasterLogKey::load_or_generate(&path).unwrap_err();
        assert!(
            matches!(err, Error::Invariant(_)),
            "corrupted key file must NOT be silently regenerated, got {:?}",
            err
        );
    }

    #[test]
    fn load_or_generate_creates_parent_directory() {
        // Provisioning at a deep path that does not yet exist.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/c/log_master.key");
        let _ = MasterLogKey::load_or_generate(&path).unwrap();
        assert!(path.exists());
        assert!(path.parent().unwrap().is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn load_or_generate_sets_0o600_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log_master.key");
        let _ = MasterLogKey::load_or_generate(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "log_master.key MUST be operator-only on Unix"
        );
    }
}
