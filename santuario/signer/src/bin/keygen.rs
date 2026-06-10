use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::{PublicKey as TraitPubKey, SecretKey as TraitSecKey};
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating new Dilithium-5 keypair for operator...");
    let (public_key, secret_key) = dilithium5::keypair();

    // Write public key to the expected operator public key path
    let operator_pk_path = PathBuf::from("santuario/integrity/operator.pk");
    if let Some(parent) = operator_pk_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&operator_pk_path, public_key.as_bytes())?;
    println!("Saved operator public key to {:?}", operator_pk_path);

    // Read the recovery challenge
    let challenge_path = PathBuf::from("santuario/integrity/recovery_challenge.hex");
    if !challenge_path.exists() {
        return Err("santuario/integrity/recovery_challenge.hex not found".into());
    }
    let challenge_hex = fs::read_to_string(&challenge_path)?;
    let challenge_bytes = hex::decode(challenge_hex.trim())?;

    // Sign the challenge using Dilithium-5
    let signed_msg = dilithium5::sign(&challenge_bytes, &secret_key);
    let token_hex = hex::encode(pqcrypto_traits::sign::SignedMessage::as_bytes(&signed_msg));

    println!("TOKEN: {}", token_hex);
    Ok(())
}
