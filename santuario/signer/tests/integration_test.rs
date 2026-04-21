use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::sign::SignedMessage;

pub mod santuario {
    pub mod signer {
        pub mod v1 {
            tonic::include_proto!("santuario.signer.v1");
        }
    }
}

#[tokio::test]
async fn test_sign_and_verify() {
    let (pk, sk) = dilithium5::keypair();
    let message = b"this is a 32 byte hash fake dat!"; // 32 bytes

    assert_eq!(message.len(), 32);

    let signature = dilithium5::sign(message, &sk);
    let opened_message = dilithium5::open(&signature, &pk).expect("Signature verification failed");

    assert_eq!(message.as_ref(), opened_message.as_slice());
}

#[tokio::test]
async fn test_invalid_signature() {
    let (pk, sk) = dilithium5::keypair();
    let message = b"this is a 32 byte hash fake dat!";

    let signature = dilithium5::sign(message, &sk);

    // Corrupt the signature
    let mut sig_bytes = signature.as_bytes().to_vec();
    if !sig_bytes.is_empty() {
        sig_bytes[0] ^= 0x01;
    }
    let corrupted = dilithium5::SignedMessage::from_bytes(&sig_bytes)
        .expect("corrupted bytes keep the signed message length intact");

    let result = dilithium5::open(&corrupted, &pk);
    assert!(result.is_err());
}
