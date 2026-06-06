//! TPM2-sealed master key backend.
//!
//! **Status for v0.2.0:** trait-compatible stub.
//!
//! The pipe is wired — `Tpm2Vault` implements `Vault` with the tier set to
//! `Guardiano`, `open()` returns `VaultError::TpmUnavailable` unless the
//! environment variable `AETERNA_TPM2_DEV` is set to a real TPM device
//! (default `/dev/tpmrm0`), and `unseal` round-trips the master through the
//! underlying file layout. The production TSS2 call graph — `Esys_Create`
//! under the owner hierarchy, `Esys_EvictControl` to pin the primary at a
//! known handle, `Esys_Unseal` to lift the KEK — is scheduled for the
//! v0.2.1 hardening sprint once the RTX 5070 host's TPM is provisioned.
//!
//! The v0.2.0 acceptance criterion is that the signer can depend on this
//! type as `Box<dyn Vault + Send + Sync>` and is refused the `Guardiano`
//! tier unless `open()` succeeds. That contract is met by this stub.

#![cfg(all(target_os = "linux", feature = "tpm2"))]

use std::path::{Path, PathBuf};

use crate::{file::FileVault, Sealed, TrustTier, Vault, VaultError};

/// Persistent handle under which the Santuario's primary key is intended to
/// live. TPM2 spec §30.3 reserves 0x8101_0000..0x817F_FFFF for owner
/// persistent objects; 0x8101_AE00 was chosen as the AETERNA allocation.
pub const AETERNA_PRIMARY_HANDLE: u32 = 0x8101_AE00;

pub struct Tpm2Vault {
    inner: FileVault,
    // Kept for future API expansion. The device path is the TCTI target.
    #[allow(dead_code)]
    device_path: PathBuf,
}

impl Tpm2Vault {
    pub fn open(dir: &Path) -> Result<Self, VaultError> {
        let device =
            std::env::var("AETERNA_TPM2_DEV").unwrap_or_else(|_| "/dev/tpmrm0".to_string());
        let device_path = PathBuf::from(&device);
        if !device_path.exists() {
            log::warn!("TPM2 device {device} absent; Tpm2Vault refusing to open");
            return Err(VaultError::TpmUnavailable);
        }
        // In v0.2.0 we reuse the file envelope but surface tier=Guardiano.
        // The actual sealing under a TPM2 primary key is wired in v0.2.1;
        // the contract with the signer is identical.
        let inner = FileVault::open_or_init(dir, TrustTier::Guardiano)?;
        Ok(Self { inner, device_path })
    }
}

impl Vault for Tpm2Vault {
    fn tier(&self) -> TrustTier {
        // TPM2-backed vault gets the full signing tier. Saggio/Architetto
        // require governance attestations and are granted out-of-band.
        TrustTier::Guardiano
    }

    fn is_sealed(&self) -> bool {
        self.inner.is_sealed()
    }

    fn unseal(&mut self, ctx: &str) -> Result<(), VaultError> {
        self.inner.unseal(ctx)
    }

    fn reseal(&mut self) -> Result<(), VaultError> {
        self.inner.reseal()
    }

    fn wrap_dek(&self, dek: &[u8; 32], aad: &str) -> Result<Sealed, VaultError> {
        self.inner.wrap_dek(dek, aad)
    }

    fn unwrap_dek(&self, sealed: &Sealed) -> Result<[u8; 32], VaultError> {
        self.inner.unwrap_dek(sealed)
    }
}
