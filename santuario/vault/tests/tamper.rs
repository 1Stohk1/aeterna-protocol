//! Phase A acceptance test. Flip a byte inside a persisted checkpoint on
//! disk, then reopen the vault and try to read the checkpoint back. The
//! vault MUST surface a hard `Tamper` error — any other outcome is a
//! regression on the v0.2.0 sprint goal.

use santuario_vault::file::FileVault;
use santuario_vault::{TrustTier, Vault, VaultError};
use std::fs;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn tamper_flipped_byte_is_detected() {
    let dir = tempdir().unwrap();
    let mut v = FileVault::open_or_init(dir.path(), TrustTier::Osservatore).unwrap();
    v.unseal("tamper-test").unwrap();
    let path = v
        .put_checkpoint("gompertz", b"state=N_final:1.23e9")
        .unwrap();

    // Drop the vault handle, then mutate the file on disk. Flipping a byte
    // anywhere in the ciphertext section of the JSON must cause AES-GCM
    // authentication to fail.
    drop(v);
    {
        let raw = fs::read_to_string(&path).unwrap();
        // Surgically flip a single hex digit *inside* the value of the
        // first `"ciphertext": "<hex>"` field. Mutating an arbitrary char
        // (e.g. inside `"wrapped"`) would break the JSON structure
        // before AES-GCM ever runs and we'd surface a serde error
        // instead of the Tamper we're testing for.
        let needle = "\"ciphertext\": \"";
        let val_start = raw
            .find(needle)
            .map(|p| p + needle.len())
            .expect("on-disk JSON must contain a ciphertext field");
        // Flip the hex digit at `val_start`: rotate within [0-9a-f].
        let bytes = raw.as_bytes();
        let orig = bytes[val_start];
        let flipped = match orig {
            b'0'..=b'8' => orig + 1,
            b'9' => b'0',
            b'a'..=b'e' => orig + 1,
            b'f' => b'a',
            other => panic!("non-hex char {other:#x} at start of ciphertext value"),
        };
        let mut mutated = raw.into_bytes();
        mutated[val_start] = flipped;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.write_all(&mutated).unwrap();
    }

    let mut v2 = FileVault::open_or_init(dir.path(), TrustTier::Osservatore).unwrap();
    v2.unseal("tamper-reopen").unwrap();
    match v2.get_checkpoint("gompertz") {
        Err(VaultError::Tamper) => {} // expected
        other => panic!("expected VaultError::Tamper after disk flip, got {other:?}"),
    }
}

#[test]
fn tamper_wrapped_dek_is_detected() {
    let dir = tempdir().unwrap();
    let mut v = FileVault::open_or_init(dir.path(), TrustTier::Osservatore).unwrap();
    v.unseal("tamper-dek").unwrap();
    let (mut wrapped, sealed) = v.seal_blob(b"secret state", "phase-a-tamper").unwrap();
    // Mutate one bit of the wrapped-DEK ciphertext. This MUST surface as Tamper.
    wrapped.ciphertext[0] ^= 0x80;
    match v.open_blob(&wrapped, &sealed) {
        Err(VaultError::Tamper) => {}
        other => panic!("expected Tamper on wrapped DEK corruption, got {other:?}"),
    }
}

#[test]
fn tamper_manifest_master_is_detected() {
    let dir = tempdir().unwrap();
    // Initialise, then brutally corrupt the manifest master.ciphertext.
    {
        let _ = FileVault::open_or_init(dir.path(), TrustTier::Osservatore).unwrap();
    }
    let manifest_path = dir.path().join("vault.manifest.json");
    let raw = fs::read_to_string(&manifest_path).unwrap();
    // Flip one character in the master ciphertext block.
    let corrupted = raw.replacen("\"ciphertext\": \"", "\"ciphertext\": \"ff", 1);
    fs::write(&manifest_path, corrupted).unwrap();

    let mut v = FileVault::open_or_init(dir.path(), TrustTier::Osservatore).unwrap();
    match v.unseal("post-tamper") {
        Err(VaultError::Tamper) | Err(VaultError::Crypto(_)) => {}
        other => panic!("expected Tamper/Crypto on corrupt manifest, got {other:?}"),
    }
}
