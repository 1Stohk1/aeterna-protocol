//! X3DH-lite handshake.
//!
//! ## Protocol
//!
//! Operator (client) holds `signer_id_pub` (imported out-of-band) and
//! generates a single-use ephemeral `operator_eph` (X25519). Operator
//! sends `HandshakeRequest { operator_eph.pub }` to the signer.
//!
//! Signer holds its long-term `signer_id_secret`. On request, the
//! signer generates a single-use ephemeral `signer_eph`. The signer
//! computes:
//!
//! ```text
//!   dh1 = ECDH(signer_id_secret,  operator_eph_pub)
//!   dh2 = ECDH(signer_eph_secret, operator_eph_pub)
//!   ikm = dh1 || dh2
//!   root_key = HKDF-SHA256(salt = b"aeterna-sigillum-ratchet-root-v1",
//!                          ikm  = ikm,
//!                          info = b"")
//! ```
//!
//! and ships back `HandshakeResponse { signer_eph.pub }`. The
//! operator computes the symmetric counterpart with `operator_eph`
//! against `signer_id_pub` and `signer_eph_pub`. Both ends reach the
//! same `root_key`. All ephemerals are wiped on drop; only the
//! signer's long-term identity persists.
//!
//! ## Why "lite"
//!
//! Real X3DH (Signal) layers signed prekeys, one-time prekeys, and
//! supports asynchronous initial messages. We don't need any of that
//! for an interactive operator <-> signer channel: the signer is
//! always online, the operator is the only client, and the handshake
//! is a synchronous round-trip over gRPC. Two ephemerals, one
//! long-term, four bytes of wire framing, one HKDF expand.

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
    Ciphertext as _,
    SharedSecret as _,
};

use crate::error::{Error, Result};
use crate::identity::{SignerIdentityKey, SignerIdentityPublic, X25519_KEY_LEN};
use crate::HANDSHAKE_VERSION;

pub const KYBER_PUB_LEN: usize = 1568;
pub const KYBER_CT_LEN: usize = 1568;

const REQUEST_FRAME_LEN: usize = 1 + X25519_KEY_LEN + KYBER_PUB_LEN;
const RESPONSE_FRAME_LEN: usize = 1 + X25519_KEY_LEN + KYBER_CT_LEN;

const HKDF_SALT: &[u8] = b"aeterna-sigillum-ratchet-root-v1";

// ===========================================================================
// Wire messages
// ===========================================================================

/// Operator -> signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeRequest {
    pub operator_eph_pub: [u8; X25519_KEY_LEN],
    pub operator_kyber_pub: [u8; KYBER_PUB_LEN],
}

impl HandshakeRequest {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; REQUEST_FRAME_LEN];
        out[0] = HANDSHAKE_VERSION;
        out[1..1 + X25519_KEY_LEN].copy_from_slice(&self.operator_eph_pub);
        out[1 + X25519_KEY_LEN..].copy_from_slice(&self.operator_kyber_pub);
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < REQUEST_FRAME_LEN {
            return Err(Error::FrameTooShort {
                got: buf.len(),
                need: REQUEST_FRAME_LEN,
            });
        }
        if buf[0] != HANDSHAKE_VERSION {
            return Err(Error::HandshakeVersionMismatch {
                got: buf[0],
                expected: HANDSHAKE_VERSION,
            });
        }
        let mut eph = [0u8; X25519_KEY_LEN];
        eph.copy_from_slice(&buf[1..1 + X25519_KEY_LEN]);
        let mut kyber = [0u8; KYBER_PUB_LEN];
        kyber.copy_from_slice(&buf[1 + X25519_KEY_LEN..REQUEST_FRAME_LEN]);
        Ok(Self {
            operator_eph_pub: eph,
            operator_kyber_pub: kyber,
        })
    }
}

/// Signer -> operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeResponse {
    pub signer_eph_pub: [u8; X25519_KEY_LEN],
    pub kyber_ciphertext: [u8; KYBER_CT_LEN],
}

impl HandshakeResponse {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0u8; RESPONSE_FRAME_LEN];
        out[0] = HANDSHAKE_VERSION;
        out[1..1 + X25519_KEY_LEN].copy_from_slice(&self.signer_eph_pub);
        out[1 + X25519_KEY_LEN..].copy_from_slice(&self.kyber_ciphertext);
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < RESPONSE_FRAME_LEN {
            return Err(Error::FrameTooShort {
                got: buf.len(),
                need: RESPONSE_FRAME_LEN,
            });
        }
        if buf[0] != HANDSHAKE_VERSION {
            return Err(Error::HandshakeVersionMismatch {
                got: buf[0],
                expected: HANDSHAKE_VERSION,
            });
        }
        let mut eph = [0u8; X25519_KEY_LEN];
        eph.copy_from_slice(&buf[1..1 + X25519_KEY_LEN]);
        let mut ct = [0u8; KYBER_CT_LEN];
        ct.copy_from_slice(&buf[1 + X25519_KEY_LEN..RESPONSE_FRAME_LEN]);
        Ok(Self {
            signer_eph_pub: eph,
            kyber_ciphertext: ct,
        })
    }
}

// ===========================================================================
// Operator-side driver
// ===========================================================================

/// Operator-side handshake driver. Holds the imported signer identity
/// pubkey, the operator's single-use 32-byte ephemeral secret,
/// and the operator's ephemeral Kyber-1024 keypair.
pub struct OperatorEndpoint {
    signer_id_pub: SignerIdentityPublic,
    eph_secret: [u8; X25519_KEY_LEN],
    eph_pub: [u8; X25519_KEY_LEN],
    kyber_secret: KyberSecKey,
    kyber_pub: KyberPubKey,
}

impl OperatorEndpoint {
    /// Generate a fresh ephemeral keypair and bundle it with the
    /// imported signer identity. The ephemerals live for one
    /// handshake then are zeroized.
    pub fn new(signer_id_pub: SignerIdentityPublic) -> Self {
        let mut eph_secret = [0u8; X25519_KEY_LEN];
        OsRng.fill_bytes(&mut eph_secret);
        let eph_pub = PublicKey::from(&StaticSecret::from(eph_secret)).to_bytes();

        let (kyber_pub, kyber_secret) = kyber1024::keypair();

        Self {
            signer_id_pub,
            eph_secret,
            eph_pub,
            kyber_secret,
            kyber_pub,
        }
    }

    /// The wire message to ship to the signer.
    pub fn handshake_request(&self) -> HandshakeRequest {
        let mut kyber_pub_bytes = [0u8; KYBER_PUB_LEN];
        kyber_pub_bytes.copy_from_slice(self.kyber_pub.as_bytes());
        HandshakeRequest {
            operator_eph_pub: self.eph_pub,
            operator_kyber_pub: kyber_pub_bytes,
        }
    }

    /// Consume the endpoint and produce the shared 32-byte root_key
    /// using the signer's response. Ephemerals are zeroized.
    pub fn finalize(mut self, response: HandshakeResponse) -> Result<[u8; 32]> {
        let signer_eph_pub = PublicKey::from(response.signer_eph_pub);
        let signer_id_pub = self.signer_id_pub.to_dalek();

        let kyber_ct = KyberCiphertext::from_bytes(&response.kyber_ciphertext)
            .map_err(|e| Error::Kyber(format!("malformed Kyber ciphertext: {:?}", e)))?;

        let root = derive_root_key_operator(
            &self.eph_secret,
            &signer_id_pub,
            &signer_eph_pub,
            &self.kyber_secret,
            &kyber_ct,
        )?;

        self.eph_secret.zeroize();
        Ok(root)
    }
}

impl Drop for OperatorEndpoint {
    fn drop(&mut self) {
        self.eph_secret.zeroize();
    }
}

// ===========================================================================
// Signer-side driver
// ===========================================================================

/// Signer-side handshake driver. Borrows the long-term identity for
/// the duration of one handshake.
pub struct SignerEndpoint<'a> {
    identity: &'a SignerIdentityKey,
}

impl<'a> SignerEndpoint<'a> {
    pub fn new(identity: &'a SignerIdentityKey) -> Self {
        Self { identity }
    }

    /// Process an incoming handshake request and produce both the
    /// outbound response and the derived root_key.
    pub fn accept(&self, req: HandshakeRequest) -> Result<(HandshakeResponse, [u8; 32])> {
        let signer_eph_secret = StaticSecret::random_from_rng(OsRng);
        let signer_eph_pub = PublicKey::from(&signer_eph_secret);

        let operator_eph_pub = PublicKey::from(req.operator_eph_pub);

        let operator_kyber_pub = KyberPubKey::from_bytes(&req.operator_kyber_pub)
            .map_err(|e| Error::Kyber(format!("malformed Kyber public key: {:?}", e)))?;

        let (kyber_ct, root_key) = derive_root_key_signer(
            self.identity.dalek_secret(),
            &signer_eph_secret,
            &operator_eph_pub,
            &operator_kyber_pub,
        )?;

        let mut ct_bytes = [0u8; KYBER_CT_LEN];
        ct_bytes.copy_from_slice(kyber_ct.as_bytes());

        Ok((
            HandshakeResponse {
                signer_eph_pub: signer_eph_pub.to_bytes(),
                kyber_ciphertext: ct_bytes,
            },
            root_key,
        ))
    }
}

// ===========================================================================
// Pure derivation primitives
// ===========================================================================

pub(crate) fn derive_root_key_operator(
    operator_eph_secret_bytes: &[u8; X25519_KEY_LEN],
    signer_id_pub: &PublicKey,
    signer_eph_pub: &PublicKey,
    kyber_secret: &KyberSecKey,
    kyber_ciphertext: &KyberCiphertext,
) -> Result<[u8; 32]> {
    let dh1 = x25519(*operator_eph_secret_bytes, signer_id_pub.to_bytes());
    let dh2 = x25519(*operator_eph_secret_bytes, signer_eph_pub.to_bytes());

    let kyber_ss = kyber1024::decapsulate(kyber_ciphertext, kyber_secret);

    let mut ikm = [0u8; 64 + 32];
    ikm[..32].copy_from_slice(&dh1);
    ikm[32..64].copy_from_slice(&dh2);
    ikm[64..96].copy_from_slice(kyber_ss.as_bytes());

    let root_key = hkdf_root(&ikm)?;
    ikm.zeroize();
    Ok(root_key)
}

pub(crate) fn derive_root_key_signer(
    signer_id_secret: &StaticSecret,
    signer_eph_secret: &StaticSecret,
    operator_eph_pub: &PublicKey,
    operator_kyber_pub: &KyberPubKey,
) -> Result<(KyberCiphertext, [u8; 32])> {
    let dh1 = signer_id_secret.diffie_hellman(operator_eph_pub);
    let dh2 = signer_eph_secret.diffie_hellman(operator_eph_pub);

    let (kyber_ss, kyber_ct) = kyber1024::encapsulate(operator_kyber_pub);

    let mut ikm = [0u8; 64 + 32];
    ikm[..32].copy_from_slice(dh1.as_bytes());
    ikm[32..64].copy_from_slice(dh2.as_bytes());
    ikm[64..96].copy_from_slice(kyber_ss.as_bytes());

    let root_key = hkdf_root(&ikm)?;
    ikm.zeroize();
    Ok((kyber_ct, root_key))
}

fn hkdf_root(ikm: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"", &mut okm)
        .map_err(|_| Error::Kdf("hkdf expand failed for ratchet root"))?;
    Ok(okm)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Happy path: operator + signer derive identical root_key.
    #[test]
    fn handshake_round_trip_yields_same_root_key() {
        let identity = SignerIdentityKey::generate();
        let signer_pub = identity.public();

        let operator = OperatorEndpoint::new(signer_pub);
        let req = operator.handshake_request();

        let signer = SignerEndpoint::new(&identity);
        let (resp, signer_root) = signer.accept(req).unwrap();

        let operator_root = operator.finalize(resp).unwrap();

        assert_eq!(signer_root, operator_root, "Hybrid X3DH-lite must agree");
        assert_eq!(signer_root.len(), 32);
        assert_ne!(signer_root, [0u8; 32]);
    }

    #[test]
    fn handshake_request_round_trips_bytes() {
        let req = HandshakeRequest {
            operator_eph_pub: [0x42u8; 32],
            operator_kyber_pub: [0x43u8; KYBER_PUB_LEN],
        };
        let wire = req.to_bytes();
        assert_eq!(wire[0], HANDSHAKE_VERSION);
        assert_eq!(HandshakeRequest::from_bytes(&wire).unwrap(), req);
    }

    #[test]
    fn handshake_response_round_trips_bytes() {
        let resp = HandshakeResponse {
            signer_eph_pub: [0x99u8; 32],
            kyber_ciphertext: [0x88u8; KYBER_CT_LEN],
        };
        let wire = resp.to_bytes();
        assert_eq!(HandshakeResponse::from_bytes(&wire).unwrap(), resp);
    }

    #[test]
    fn handshake_request_rejects_short_buffer() {
        let err = HandshakeRequest::from_bytes(&[0x01, 0x02, 0x03]).unwrap_err();
        assert!(matches!(err, Error::FrameTooShort { .. }));
    }

    #[test]
    fn handshake_request_rejects_wrong_version() {
        let mut buf = [0u8; REQUEST_FRAME_LEN];
        buf[0] = 0xFE;
        let err = HandshakeRequest::from_bytes(&buf).unwrap_err();
        assert!(matches!(err, Error::HandshakeVersionMismatch { .. }));
    }

    #[test]
    fn different_signer_identities_diverge_root_keys() {
        let id_a = SignerIdentityKey::generate();
        let id_b = SignerIdentityKey::generate();
        let mut eph = [0u8; 32];
        OsRng.fill_bytes(&mut eph);
        let mut kyber_pub = [0u8; KYBER_PUB_LEN];
        OsRng.fill_bytes(&mut kyber_pub);
        let req = HandshakeRequest {
            operator_eph_pub: PublicKey::from(&StaticSecret::from(eph)).to_bytes(),
            operator_kyber_pub: kyber_pub,
        };
        let (_, root_a) = SignerEndpoint::new(&id_a).accept(req).unwrap();
        let (_, root_b) = SignerEndpoint::new(&id_b).accept(req).unwrap();
        assert_ne!(root_a, root_b, "identity must diversify the root key");
    }

    #[test]
    fn fresh_handshakes_diverge_root_keys() {
        let identity = SignerIdentityKey::generate();
        let signer_pub = identity.public();
        let drive = || {
            let op = OperatorEndpoint::new(signer_pub);
            let req = op.handshake_request();
            let (resp, _) = SignerEndpoint::new(&identity).accept(req).unwrap();
            op.finalize(resp).unwrap()
        };
        let r1 = drive();
        let r2 = drive();
        assert_ne!(r1, r2);
    }

    #[test]
    fn operator_endpoint_wipes_eph_on_finalize() {
        let identity = SignerIdentityKey::generate();
        let op = OperatorEndpoint::new(identity.public());
        let req = op.handshake_request();
        let (resp, _) = SignerEndpoint::new(&identity).accept(req).unwrap();
        let _root = op.finalize(resp).unwrap();
    }
}
