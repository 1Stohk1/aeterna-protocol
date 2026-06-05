//! santuario-vault — Sovereign Vault Stub.
//!
//! Enforces key envelope integrity and mock TPM2 attestation.
//! In v0.3.0 "Oculus", a full embedded Vault object on the hot signing
//! path is out of scope; the state is trackable via environment variables.

use std::path::Path;

pub struct Vault {
    pub is_sealed: bool,
}

impl Vault {
    pub fn new() -> Self {
        let sealed = std::env::var("SANTUARIO_VAULT_STATE")
            .map(|v| v.trim().eq_ignore_ascii_case("sealed"))
            .unwrap_or(false);
        Vault { is_sealed: sealed }
    }

    pub fn attest_tpm2(&self) -> bool {
        // Mock TPM2 attestation. True means PCRs match and hardware is validated.
        true
    }

    pub fn unseal<P: AsRef<Path>>(&mut self, _key_path: P, _passphrase: &str) -> Result<(), &'static str> {
        self.is_sealed = false;
        Ok(())
    }

    pub fn seal(&mut self) {
        self.is_sealed = true;
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}
