//! Gossip P2P hybrid handshake (Kyber-1024 + X25519).
//!
//! ## Protocol
//!
//! Node A (initiator) generates:
//! - Ephemeral X25519 keypair: `a_eph_sec`, `a_eph_pub`
//! - Ephemeral Kyber-1024 keypair: `a_kyber_sec`, `a_kyber_pub`
//!
//! Sends `P2PHandshakeRequest { a_eph_pub, a_kyber_pub }` to Node B.
//!
//! Node B (responder) generates:
//! - Ephemeral X25519 keypair: `b_eph_sec`, `b_eph_pub`
//! - Performs Kyber encapsulation using Node A's `a_kyber_pub` to get a shared secret `kyber_ss` and ciphertext `b_kyber_ct`.
//! - Computes:
//!   - `dh = ECDH(b_eph_sec, a_eph_pub)`
//!   - `ikm = dh || kyber_ss`
//!   - `session_key = HKDF-SHA256(salt = b"aeterna-sigillum-gossip-p2p-v1", ikm = ikm)`
//!
//! Node B sends back `P2PHandshakeResponse { b_eph_pub, b_kyber_ct }`.
//!
//! Node A receives the response:
//! - Decapsulates `b_kyber_ct` using `a_kyber_sec` to get `kyber_ss`.
//! - Computes:
//!   - `dh = ECDH(a_eph_sec, b_eph_pub)`
//!   - `ikm = dh || kyber_ss`
//!   - `session_key = HKDF-SHA256(salt = b"aeterna-sigillum-gossip-p2p-v1", ikm = ikm)`
//!
//! Both nodes derive the exact same 32-byte gossip session key.

use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{x25519, PublicKey, StaticSecret};
use zeroize::Zeroize;

use pqcrypto_kyber::kyber1024::{
    self,
    PublicKey as KyberPubKey,
    SecretKey as KyberSecKey,
    Ciphertext as KyberCiphertext,
};
use pqcrypto_traits::kem::{
    PublicKey as _,
    SecretKey as _,
    Ciphertext as _,
    SharedSecret as _,
};

use crate::error::{Error, Result};
use crate::identity::X25519_KEY_LEN;

pub const KYBER_PUB_LEN: usize = 1568;
pub const KYBER_CT_LEN: usize = 1568;

const P2P_SALT: &[u8] = b"aeterna-sigillum-gossip-p2p-v1";

// ===========================================================================
// Wire Messages
// ===========================================================================

/// Handshake Request from Node A to Node B.
#[derive(Clone, PartialEq, Eq)]
pub struct P2PHandshakeRequest {
    pub a_eph_pub: [u8; X25519_KEY_LEN],
    pub a_kyber_pub: [u8; KYBER_PUB_LEN],
}

impl std::fmt::Debug for P2PHandshakeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2PHandshakeRequest")
            .field("a_eph_pub", &hex::encode(self.a_eph_pub))
            .field("a_kyber_pub", &format!("KyberPubKey(len={})", self.a_kyber_pub.len()))
            .finish()
    }
}

impl P2PHandshakeRequest {
    /// Serialize request to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; X25519_KEY_LEN + KYBER_PUB_LEN];
        out[..X25519_KEY_LEN].copy_from_slice(&self.a_eph_pub);
        out[X25519_KEY_LEN..].copy_from_slice(&self.a_kyber_pub);
        out
    }

    /// Deserialize request from bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let expected = X25519_KEY_LEN + KYBER_PUB_LEN;
        if buf.len() < expected {
            return Err(Error::FrameTooShort {
                got: buf.len(),
                need: expected,
            });
        }
        let mut a_eph_pub = [0u8; X25519_KEY_LEN];
        a_eph_pub.copy_from_slice(&buf[..X25519_KEY_LEN]);
        let mut a_kyber_pub = [0u8; KYBER_PUB_LEN];
        a_kyber_pub.copy_from_slice(&buf[X25519_KEY_LEN..expected]);
        Ok(Self {
            a_eph_pub,
            a_kyber_pub,
        })
    }
}

/// Handshake Response from Node B to Node A.
#[derive(Clone, PartialEq, Eq)]
pub struct P2PHandshakeResponse {
    pub b_eph_pub: [u8; X25519_KEY_LEN],
    pub b_kyber_ct: [u8; KYBER_CT_LEN],
}

impl std::fmt::Debug for P2PHandshakeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2PHandshakeResponse")
            .field("b_eph_pub", &hex::encode(self.b_eph_pub))
            .field("b_kyber_ct", &format!("KyberCiphertext(len={})", self.b_kyber_ct.len()))
            .finish()
    }
}

impl P2PHandshakeResponse {
    /// Serialize response to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; X25519_KEY_LEN + KYBER_CT_LEN];
        out[..X25519_KEY_LEN].copy_from_slice(&self.b_eph_pub);
        out[X25519_KEY_LEN..].copy_from_slice(&self.b_kyber_ct);
        out
    }

    /// Deserialize response from bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let expected = X25519_KEY_LEN + KYBER_CT_LEN;
        if buf.len() < expected {
            return Err(Error::FrameTooShort {
                got: buf.len(),
                need: expected,
            });
        }
        let mut b_eph_pub = [0u8; X25519_KEY_LEN];
        b_eph_pub.copy_from_slice(&buf[..X25519_KEY_LEN]);
        let mut b_kyber_ct = [0u8; KYBER_CT_LEN];
        b_kyber_ct.copy_from_slice(&buf[X25519_KEY_LEN..expected]);
        Ok(Self {
            b_eph_pub,
            b_kyber_ct,
        })
    }
}

// ===========================================================================
// P2P Handshake Drivers
// ===========================================================================

/// P2P Initiator (Node A) endpoint driver.
pub struct P2PInitiator {
    a_eph_sec: [u8; X25519_KEY_LEN],
    a_eph_pub: [u8; X25519_KEY_LEN],
    a_kyber_sec: KyberSecKey,
    a_kyber_pub: KyberPubKey,
}

impl P2PInitiator {
    /// Initialize a new handshake initiator with ephemeral keys.
    pub fn new() -> Self {
        let mut a_eph_sec = [0u8; X25519_KEY_LEN];
        OsRng.fill_bytes(&mut a_eph_sec);
        let a_eph_pub = PublicKey::from(&StaticSecret::from(a_eph_sec)).to_bytes();

        let (a_kyber_pub, a_kyber_sec) = kyber1024::keypair();

        Self {
            a_eph_sec,
            a_eph_pub,
            a_kyber_sec,
            a_kyber_pub,
        }
    }

    /// Construct a serialized initiator state for CLI / stateless transport.
    pub fn export_state(&self) -> Vec<u8> {
        let mut state = vec![0u8; X25519_KEY_LEN + self.a_kyber_sec.as_bytes().len()];
        state[..X25519_KEY_LEN].copy_from_slice(&self.a_eph_sec);
        state[X25519_KEY_LEN..].copy_from_slice(self.a_kyber_sec.as_bytes());
        state
    }

    /// Import initiator state from bytes.
    pub fn import_state(buf: &[u8]) -> Result<Self> {
        let expected = X25519_KEY_LEN + 3168; // Kyber1024 secret key is exactly 3168 bytes
        if buf.len() < expected {
            return Err(Error::FrameTooShort {
                got: buf.len(),
                need: expected,
            });
        }
        let mut a_eph_sec = [0u8; X25519_KEY_LEN];
        a_eph_sec.copy_from_slice(&buf[..X25519_KEY_LEN]);
        let a_eph_pub = PublicKey::from(&StaticSecret::from(a_eph_sec)).to_bytes();

        let a_kyber_sec = KyberSecKey::from_bytes(&buf[X25519_KEY_LEN..expected])
            .map_err(|e| Error::Kyber(format!("malformed Kyber secret key state: {:?}", e)))?;

        // Reconstruct Kyber public key using a dummy keypair, as during decapsulation we only need the secret key.
        let (a_kyber_pub, _) = kyber1024::keypair(); 

        Ok(Self {
            a_eph_sec,
            a_eph_pub,
            a_kyber_sec,
            a_kyber_pub,
        })
    }

    /// Produce the handshake request wire message.
    pub fn handshake_request(&self) -> P2PHandshakeRequest {
        let mut a_kyber_pub_bytes = [0u8; KYBER_PUB_LEN];
        a_kyber_pub_bytes.copy_from_slice(self.a_kyber_pub.as_bytes());
        P2PHandshakeRequest {
            a_eph_pub: self.a_eph_pub,
            a_kyber_pub: a_kyber_pub_bytes,
        }
    }

    /// Finalize the handshake using the response from Node B, yielding the 32-byte shared session key.
    pub fn finalize(mut self, response: P2PHandshakeResponse) -> Result<[u8; 32]> {
        let b_eph_pub = PublicKey::from(response.b_eph_pub);

        let kyber_ct = KyberCiphertext::from_bytes(&response.b_kyber_ct)
            .map_err(|e| Error::Kyber(format!("malformed Kyber ciphertext: {:?}", e)))?;

        let session_key = derive_session_key_initiator(
            &self.a_eph_sec,
            &b_eph_pub,
            &self.a_kyber_sec,
            &kyber_ct,
        )?;

        self.a_eph_sec.zeroize();
        Ok(session_key)
    }
}

impl Drop for P2PInitiator {
    fn drop(&mut self) {
        self.a_eph_sec.zeroize();
    }
}

/// P2P Responder (Node B) endpoint driver.
pub struct P2PResponder;

impl P2PResponder {
    pub fn new() -> Self {
        Self
    }

    /// Process the request, derive the shared session key, and construct the response.
    pub fn accept(&self, request: P2PHandshakeRequest) -> Result<(P2PHandshakeResponse, [u8; 32])> {
        let b_eph_sec = StaticSecret::random_from_rng(OsRng);
        let b_eph_pub = PublicKey::from(&b_eph_sec);

        let a_eph_pub = PublicKey::from(request.a_eph_pub);

        let a_kyber_pub = KyberPubKey::from_bytes(&request.a_kyber_pub)
            .map_err(|e| Error::Kyber(format!("malformed Kyber public key: {:?}", e)))?;

        let (kyber_ss, kyber_ct) = kyber1024::encapsulate(&a_kyber_pub);

        let dh = b_eph_sec.diffie_hellman(&a_eph_pub);

        let mut ikm = [0u8; X25519_KEY_LEN + 32];
        ikm[..X25519_KEY_LEN].copy_from_slice(dh.as_bytes());
        ikm[X25519_KEY_LEN..].copy_from_slice(kyber_ss.as_bytes());

        let session_key = hkdf_derive(&ikm)?;
        ikm.zeroize();

        let mut ct_bytes = [0u8; KYBER_CT_LEN];
        ct_bytes.copy_from_slice(kyber_ct.as_bytes());

        Ok((
            P2PHandshakeResponse {
                b_eph_pub: b_eph_pub.to_bytes(),
                b_kyber_ct: ct_bytes,
            },
            session_key,
        ))
    }
}

// ===========================================================================
// Cryptographic Derivations
// ===========================================================================

fn derive_session_key_initiator(
    a_eph_sec_bytes: &[u8; X25519_KEY_LEN],
    b_eph_pub: &PublicKey,
    a_kyber_sec: &KyberSecKey,
    b_kyber_ct: &KyberCiphertext,
) -> Result<[u8; 32]> {
    let dh = x25519(*a_eph_sec_bytes, b_eph_pub.to_bytes());
    let kyber_ss = kyber1024::decapsulate(b_kyber_ct, a_kyber_sec);

    let mut ikm = [0u8; X25519_KEY_LEN + 32];
    ikm[..X25519_KEY_LEN].copy_from_slice(&dh);
    ikm[X25519_KEY_LEN..].copy_from_slice(kyber_ss.as_bytes());

    let session_key = hkdf_derive(&ikm)?;
    ikm.zeroize();
    Ok(session_key)
}

fn hkdf_derive(ikm: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(P2P_SALT), ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"", &mut okm)
        .map_err(|_| Error::Kdf("hkdf expand failed for gossip p2p session key"))?;
    Ok(okm)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p2p_handshake_round_trip() {
        let initiator = P2PInitiator::new();
        let req = initiator.handshake_request();

        let responder = P2PResponder::new();
        let (resp, responder_key) = responder.accept(req).unwrap();

        let initiator_key = initiator.finalize(resp).unwrap();

        assert_eq!(initiator_key, responder_key);
        assert_ne!(initiator_key, [0u8; 32]);
    }

    #[test]
    fn p2p_handshake_request_serialization() {
        let initiator = P2PInitiator::new();
        let req = initiator.handshake_request();
        let bytes = req.to_bytes();
        let deserialized = P2PHandshakeRequest::from_bytes(&bytes).unwrap();
        assert_eq!(req, deserialized);
    }

    #[test]
    fn p2p_handshake_response_serialization() {
        let resp = P2PHandshakeResponse {
            b_eph_pub: [0x55u8; 32],
            b_kyber_ct: [0xAAu8; KYBER_CT_LEN],
        };
        let bytes = resp.to_bytes();
        let deserialized = P2PHandshakeResponse::from_bytes(&bytes).unwrap();
        assert_eq!(resp, deserialized);
    }

    #[test]
    fn p2p_stateless_initiator_state_round_trip() {
        let initiator = P2PInitiator::new();
        let state_bytes = initiator.export_state();
        
        let req = initiator.handshake_request();

        let reconstructed_initiator = P2PInitiator::import_state(&state_bytes).unwrap();
        
        let responder = P2PResponder::new();
        let (resp, responder_key) = responder.accept(req).unwrap();

        let initiator_key = reconstructed_initiator.finalize(resp).unwrap();

        assert_eq!(initiator_key, responder_key);
    }
}
