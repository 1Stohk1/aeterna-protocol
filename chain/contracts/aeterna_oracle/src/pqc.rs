use crate::error::ContractError;
use crystals_dilithium::dilithium5::PublicKey;

pub fn verify_dilithium5(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ContractError> {
    let pk = PublicKey::from_bytes(public_key).map_err(|_| ContractError::InvalidSignature {})?;
    if !pk.verify(message, signature) {
        return Err(ContractError::InvalidSignature {});
    }
    Ok(())
}

