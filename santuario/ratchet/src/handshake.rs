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

use crate::error::{Error, Result};
use crate::identity::{SignerIdentityKey, SignerIdentityPublic, X25519_KEY_LEN};
use crate::HANDSHAKE_VERSION;

const HANDSHAKE_FRAME_LEN: usize = 1 + X25519_KEY_LEN; // ver + pub
const HKDF_SALT: &[u8] = b"aeterna-sigillum-ratchet-root-v1";

// ===========================================================================
// Wire messages
// ===========================================================================

/// Operator -> signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeRequest {
    pub operator_eph_pub: [u8; X25519_KEY_LEN],
}

impl HandshakeRequest {
    pub fn to_bytes(&self) -> [u8; HANDSHAKE_FRAME_LEN] {
        let mut out = [0u8; HANDSHAKE_FRAME_LEN];
        out[0] = HANDSHAKE_VERSION;
        out[1..].copy_from_slice(&self.operator_eph_pub);
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < HANDSHAKE_FRAME_LEN {
            return Err(Error::FrameTooShort {
                got: buf.len(),
                need: HANDSHAKE_FRAME_LEN,
            });
        }
        if buf[0] != HANDSHAKE_VERSION {
            return Err(Error::HandshakeVersionMismatch {
                got: buf[0],
                expected: HANDSHAKE_VERSION,
            });
        }
        let mut pk = [0u8; X25519_KEY_LEN];
        pk.copy_from_slice(&buf[1..HANDSHAKE_FRAME_LEN]);
        Ok(Self {
            operator_eph_pub: pk,
        })
    }
}

/// Signer -> operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeResponse {
    pub signer_eph_pub: [u8; X25519_KEY_LEN],
}

impl HandshakeResponse {
    pub fn to_bytes(&self) -> [u8; HANDSHAKE_FRAME_LEN] {
        let mut out = [0u8; HANDSHAKE_FRAME_LEN];
        out[0] = HANDSHAKE_VERSION;
        out[1..].copy_from_slice(&self.signer_eph_pub);
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < HANDSHAKE_FRAME_LEN {
            return Err(Error::FrameTooShort {
                got: buf.len(),
                need: HANDSHAKE_FRAME_LEN,
            });
        }
        if buf[0] != HANDSHAKE_VERSION {
            return Err(Error::HandshakeVersionMismatch {
                got: buf[0],
                expected: HANDSHAKE_VERSION,
            });
        }
        let mut pk = [0u8; X25519_KEY_LEN];
        pk.copy_from_slice(&buf[1..HANDSHAKE_FRAME_LEN]);
        Ok(Self {
            signer_eph_pub: pk,
        })
    }
}

// ===========================================================================
// Operator-side driver
// ===========================================================================

/// Operator-side handshake driver. Holds the imported signer identity
/// pubkey and the operator's single-use 32-byte ephemeral secret.
///
/// The ephemeral lives in process memory only for the duration of the
/// handshake. On `finalize`, the secret bytes are explicitly zeroized
/// before returning.
pub struct OperatorEndpoint {
    signer_id_pub: SignerIdentityPublic,
    eph_secret: [u8; X25519_KEY_LEN],
    eph_pub: [u8; X25519_KEY_LEN],
}

impl OperatorEndpoint {
    /// Generate a fresh ephemeral keypair and bundle it with the
    /// imported signer identity. The ephemeral lives for one
    /// handshake then is wiped on finalize.
    pub fn new(signer_id_pub: SignerIdentityPublic) -> Self {
        let mut eph_secret = [0u8; X25519_KEY_LEN];
        OsRng.fill_bytes(&mut eph_secret);
        // X25519 clamping: x25519_dalek::x25519 clamps internally per
        // RFC 7748 §5; we don't need to pre-clamp here.
        let eph_pub = PublicKey::from(&StaticSecret::from(eph_secret)).to_bytes();
        Self {
            signer_id_pub,
            eph_secret,
            eph_pub,
        }
    }

    /// Construct from caller-provided ephemeral bytes. Useful when the
    /// caller wants the secret to live in a specific store (HSM proxy,
    /// process-private mmap, etc.) rather than be generated here.
    pub fn from_eph_bytes(
        signer_id_pub: SignerIdentityPublic,
        eph_secret: [u8; X25519_KEY_LEN],
    ) -> Self {
        let eph_pub = PublicKey::from(&StaticSecret::from(eph_secret)).to_bytes();
        Self {
            signer_id_pub,
            eph_secret,
            eph_pub,
        }
    }

    /// The wire message to ship to the signer.
    pub fn handshake_request(&self) -> HandshakeRequest {
        HandshakeRequest {
            operator_eph_pub: self.eph_pub,
        }
    }

    /// Consume the endpoint and produce the shared 32-byte root_key
    /// using the signer's response. The ephemeral secret bytes are
    /// zeroized as part of this call.
    pub fn finalize(mut self, response: HandshakeResponse) -> Result<[u8; 32]> {
        let signer_eph_pub = PublicKey::from(response.signer_eph_pub);
        let signer_id_pub = self.signer_id_pub.to_dalek();
        let root = derive_root_key_operator(&self.eph_secret, &signer_id_pub, &signer_eph_pub)?;
        // Wipe the operator ephemeral before returning.
        self.eph_secret.zeroize();
        Ok(root)
    }
}

impl Drop for OperatorEndpoint {
    fn drop(&mut self) {
        // Defense in depth: if the caller forgot to call finalize(),
        // wipe the ephemeral on drop too. (finalize already wipes.)
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
    /// outbound response and the derived root_key. The signer's
    /// ephemeral is generated, used, and wiped (zeroized) inside
    /// this call; it never escapes.
    pub fn accept(&self, req: HandshakeRequest) -> Result<(HandshakeResponse, [u8; 32])> {
        let signer_eph_secret = StaticSecret::random_from_rng(OsRng);
        let signer_eph_pub = PublicKey::from(&signer_eph_secret);

        let operator_eph_pub = PublicKey::from(req.operator_eph_pub);
        let root_key = derive_root_key_signer(
            self.identity.dalek_secret(),
            &signer_eph_secret,
            &operator_eph_pub,
        )?;

        Ok((
            HandshakeResponse {
                signer_eph_pub: signer_eph_pub.to_bytes(),
            },
            root_key,
        ))
        // signer_eph_secret drops here -> ZeroizeOnDrop wipes it.
    }
}

// ===========================================================================
// Pure derivation primitives
// ===========================================================================

pub(crate) fn derive_root_key_operator(
    operator_eph_secret_bytes: &[u8; X25519_KEY_LEN],
    signer_id_pub: &PublicKey,
    signer_eph_pub: &PublicKey,
) -> Result<[u8; 32]> {
    let dh1 = x25519(*operator_eph_secret_bytes, signer_id_pub.to_bytes());
    let dh2 = x25519(*operator_eph_secret_bytes, signer_eph_pub.to_bytes());
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&dh1);
    ikm[32..].copy_from_slice(&dh2);
    let root_key = hkdf_root(&ikm)?;
    ikm.zeroize();
    Ok(root_key)
}

pub(crate) fn derive_root_key_signer(
    signer_id_secret: &StaticSecret,
    signer_eph_secret: &StaticSecret,
    operator_eph_pub: &PublicKey,
) -> Result<[u8; 32]> {
    let dh1 = signer_id_secret.diffie_hellman(operator_eph_pub);
    let dh2 = signer_eph_secret.diffie_hellman(operator_eph_pub);
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(dh1.as_bytes());
    ikm[32..].copy_from_slice(dh2.as_bytes());
    let root_key = hkdf_root(&ikm)?;
    ikm.zeroize();
    Ok(root_key)
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

        assert_eq!(signer_root, operator_root, "X3DH-lite must agree");
        assert_eq!(signer_root.len(), 32);
        // root key is high-entropy, NOT zeros (sanity check).
        assert_ne!(signer_root, [0u8; 32]);
    }

    #[test]
    fn handshake_request_round_trips_bytes() {
        let req = HandshakeRequest {
            operator_eph_pub: [0x42u8; 32],
        };
        let wire = req.to_bytes();
        assert_eq!(wire[0], HANDSHAKE_VERSION);
        assert_eq!(HandshakeRequest::from_bytes(&wire).unwrap(), req);
    }

    #[test]
    fn handshake_response_round_trips_bytes() {
        let resp = HandshakeResponse {
            signer_eph_pub: [0x99u8; 32],
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
        let mut buf = [0u8; HANDSHAKE_FRAME_LEN];
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
        let req = HandshakeRequest {
            operator_eph_pub: PublicKey::from(&StaticSecret::from(eph)).to_bytes(),
        };
        let (_, root_a) = SignerEndpoint::new(&id_a).accept(req).unwrap();
        let (_, root_b) = SignerEndpoint::new(&id_b).accept(req).unwrap();
        assert_ne!(root_a, root_b, "identity must diversify the root key");
    }

    #[test]
    fn fresh_handshakes_diverge_root_keys() {
        // Same identity, different operator ephemerals -> different
        // root keys. Per-handshake forward secrecy.
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
        // We can't directly observe zeroization (the field is private)
        // but we can confirm finalize succeeds and then double-finalize
        // is impossible because the value moved.
        let identity = SignerIdentityKey::generate();
        let op = OperatorEndpoint::new(identity.public());
        let req = op.handshake_request();
        let (resp, _) = SignerEndpoint::new(&identity).accept(req).unwrap();
        let _root = op.finalize(resp).unwrap();
        // op moved; the borrow checker prevents reuse, which is the
        // strongest possible guard against re-entry attacks.
    }
}
