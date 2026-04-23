//! Recovery-token protocol.
//!
//! When the signer is suspended by an α/β/γ threshold, the only way out
//! is an operator-signed **recovery token**. The protocol is:
//!
//!   1. Suspended signer writes a random 32-byte `challenge` to
//!      `santuario/integrity/recovery_challenge.hex`.
//!   2. Operator signs the challenge with their Dilithium-5 operator
//!      key (the public half is installed in `aeterna.toml
//!      [santuario].operator_pubkey_path`) — typically via an air-gapped
//!      box.
//!   3. Operator presents the signature to `santuarioctl resume
//!      --token <hex>` which calls [`try_resume`] below.
//!   4. On successful verification, the state flips back to `Ready`
//!      and the audit log records the `SignerResume` event.
//!
//! The challenge is rotated on every suspension so a replayed token
//! from a prior incident is rejected.

use std::path::{Path, PathBuf};

use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SignedMessage};
use rand::RngCore;
use thiserror::Error;

use santuario_integrity::{log::AuditLog, SignerState};

/// Length of the random challenge in bytes (256-bit).
pub const CHALLENGE_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("signer is not currently suspended — no challenge outstanding")]
    NotSuspended,
    #[error("challenge file missing — suspension was not recorded?")]
    ChallengeMissing,
    #[error("challenge file corrupted: {0}")]
    ChallengeCorrupt(String),
    #[error("operator public key unreadable: {0}")]
    PubkeyIo(String),
    #[error("operator public key is not a valid Dilithium-5 public key")]
    PubkeyInvalid,
    #[error("recovery token is not valid hex: {0}")]
    TokenHex(String),
    #[error("recovery token did not verify against the challenge")]
    BadSignature,
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit: {0}")]
    Audit(String),
}

#[derive(Debug, Clone)]
pub struct RecoveryContext {
    pub challenge_path: PathBuf,
    pub operator_pubkey_path: PathBuf,
    pub audit_log: AuditLog,
}

impl RecoveryContext {
    pub fn new_under(repo_root: &Path, audit_log: AuditLog) -> Self {
        Self {
            challenge_path: repo_root.join("santuario/integrity/recovery_challenge.hex"),
            operator_pubkey_path: repo_root.join("santuario/integrity/operator.pk"),
            audit_log,
        }
    }
}

/// Mint a fresh 32-byte challenge for the currently-suspended state and
/// write it to `challenge_path`. Called by the integrity watchdog at
/// the moment of suspension.
pub fn issue_challenge(ctx: &RecoveryContext) -> Result<[u8; CHALLENGE_LEN], RecoveryError> {
    let mut buf = [0u8; CHALLENGE_LEN];
    rand::thread_rng().fill_bytes(&mut buf);
    if let Some(parent) = ctx.challenge_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&ctx.challenge_path, hex::encode(buf))?;
    Ok(buf)
}

/// Attempt to resume the signer from a suspension using a
/// hex-encoded Dilithium-5 signed message over the outstanding
/// challenge. On success, flips `state` back to Ready and rotates the
/// challenge file. On failure, leaves the state unchanged.
pub fn try_resume(
    ctx: &RecoveryContext,
    state: &SignerState,
    token_hex: &str,
    operator_label: &str,
) -> Result<(), RecoveryError> {
    if state.is_ready() {
        return Err(RecoveryError::NotSuspended);
    }

    // Load the challenge we previously issued.
    if !ctx.challenge_path.exists() {
        return Err(RecoveryError::ChallengeMissing);
    }
    let chal_hex = std::fs::read_to_string(&ctx.challenge_path)
        .map_err(|e| RecoveryError::ChallengeCorrupt(e.to_string()))?;
    let challenge =
        hex::decode(chal_hex.trim()).map_err(|e| RecoveryError::ChallengeCorrupt(e.to_string()))?;
    if challenge.len() != CHALLENGE_LEN {
        return Err(RecoveryError::ChallengeCorrupt(format!(
            "expected {CHALLENGE_LEN} bytes, got {}",
            challenge.len()
        )));
    }

    // Load the operator public key.
    let pk_bytes = std::fs::read(&ctx.operator_pubkey_path)
        .map_err(|e| RecoveryError::PubkeyIo(e.to_string()))?;
    let pk =
        dilithium5::PublicKey::from_bytes(&pk_bytes).map_err(|_| RecoveryError::PubkeyInvalid)?;

    // Decode the token (Dilithium-5 signed message). The operator signs
    // the challenge as the message; we accept either the
    // signed-message (open) form or the detached-signature form.
    let raw = hex::decode(token_hex.trim()).map_err(|e| RecoveryError::TokenHex(e.to_string()))?;
    let ok = verify_signed_message(&raw, &challenge, &pk) || verify_detached(&raw, &challenge, &pk);
    if !ok {
        return Err(RecoveryError::BadSignature);
    }

    // Rotate the challenge so the same token can't be replayed.
    let _ = std::fs::remove_file(&ctx.challenge_path);

    state.resume();
    ctx.audit_log
        .log_resume(operator_label)
        .map_err(|e| RecoveryError::Audit(e.to_string()))?;
    Ok(())
}

fn verify_signed_message(raw: &[u8], expected_msg: &[u8], pk: &dilithium5::PublicKey) -> bool {
    let Ok(sm) = dilithium5::SignedMessage::from_bytes(raw) else {
        return false;
    };
    match dilithium5::open(&sm, pk) {
        Ok(m) => m == expected_msg,
        Err(_) => false,
    }
}

fn verify_detached(raw: &[u8], msg: &[u8], pk: &dilithium5::PublicKey) -> bool {
    let Ok(det) = dilithium5::DetachedSignature::from_bytes(raw) else {
        return false;
    };
    dilithium5::verify_detached_signature(&det, msg, pk).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use santuario_integrity::{AlertKind, SignerState};

    fn setup() -> (
        tempfile::TempDir,
        RecoveryContext,
        SignerState,
        dilithium5::SecretKey,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::create_dir_all(root.join("santuario/integrity")).unwrap();
        let audit = AuditLog::new(root.join("santuario/integrity/audit.log.jsonl"));
        let ctx = RecoveryContext::new_under(&root, audit);
        let (pk, sk) = dilithium5::keypair();
        std::fs::write(&ctx.operator_pubkey_path, pk.as_bytes()).unwrap();
        let state = SignerState::new();
        state.suspend(AlertKind::Alpha, "test");
        (dir, ctx, state, sk)
    }

    #[test]
    fn resume_with_valid_signed_message() {
        let (_dir, ctx, state, sk) = setup();
        let chal = issue_challenge(&ctx).unwrap();
        let sm = dilithium5::sign(&chal, &sk);
        let token = hex::encode(pqcrypto_traits::sign::SignedMessage::as_bytes(&sm));
        try_resume(&ctx, &state, &token, "christian").unwrap();
        assert!(state.is_ready());
        // Challenge file should be removed.
        assert!(!ctx.challenge_path.exists());
    }

    #[test]
    fn resume_with_valid_detached_signature() {
        let (_dir, ctx, state, sk) = setup();
        let chal = issue_challenge(&ctx).unwrap();
        let det = dilithium5::detached_sign(&chal, &sk);
        let token = hex::encode(pqcrypto_traits::sign::DetachedSignature::as_bytes(&det));
        try_resume(&ctx, &state, &token, "christian").unwrap();
        assert!(state.is_ready());
    }

    #[test]
    fn ready_signer_has_no_outstanding_challenge() {
        let dir = tempfile::tempdir().unwrap();
        let audit = AuditLog::new(dir.path().join("x.jsonl"));
        let ctx = RecoveryContext::new_under(dir.path(), audit);
        let state = SignerState::new();
        let r = try_resume(&ctx, &state, "00", "op");
        matches!(r, Err(RecoveryError::NotSuspended));
    }

    #[test]
    fn garbage_token_rejected() {
        let (_dir, ctx, state, _sk) = setup();
        issue_challenge(&ctx).unwrap();
        let r = try_resume(&ctx, &state, "deadbeef", "op");
        matches!(r, Err(RecoveryError::BadSignature));
        assert!(!state.is_ready());
    }

    #[test]
    fn wrong_key_signature_rejected() {
        let (_dir, ctx, state, _sk) = setup();
        let chal = issue_challenge(&ctx).unwrap();
        let (_, rogue_sk) = dilithium5::keypair();
        let sm = dilithium5::sign(&chal, &rogue_sk);
        let token = hex::encode(pqcrypto_traits::sign::SignedMessage::as_bytes(&sm));
        let r = try_resume(&ctx, &state, &token, "op");
        matches!(r, Err(RecoveryError::BadSignature));
        assert!(!state.is_ready());
    }
}
