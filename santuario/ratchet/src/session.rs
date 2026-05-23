//! Established ratchet session: encrypt / decrypt + step + tombstone.
//!
//! ## Lifecycle
//!
//! A `Session` is built by handing it the 32-byte root_key produced
//! by [`crate::handshake`]. From then on, each side (operator OR
//! signer) holds an independent `Session` instance that derives the
//! same per-step cryptographic material because both started from
//! the same `root_key`.
//!
//! ## Per-step key derivation
//!
//! `step_key[0] = HKDF(salt=root_key, ikm=b"", info=b"step-0")`
//! `step_key[N] = HKDF(salt=step_key[N-1], ikm=b"", info=b"step")`
//!
//! Within a step, two nonce prefixes are derived from the step_key
//! via separate HKDF info strings:
//!
//!   `nonce_prefix_op_to_signer = HKDF(step_key, info=b"op-to-signer-nonce")[:8]`
//!   `nonce_prefix_signer_to_op = HKDF(step_key, info=b"signer-to-op-nonce")[:8]`
//!
//! Per-message nonce: `prefix(8 bytes) || counter(4 bytes BE)`.
//! AEAD AAD: the full 9-byte wire header. This binds every sealed
//! message to its claimed step and counter, defeating splice/swap.
//!
//! ## State machine
//!
//! `Session` is internally a tagged union of `Active` and
//! `Tombstone`. Every public method first checks for `Tombstone`;
//! ops in that state return `Error::SessionTombstoned`. The only way
//! out of `Tombstone` is to construct a new `Session` from a fresh
//! handshake.
//!
//! The `Active` variant tracks:
//! * `step`: monotonic step counter (0, 1, 2, ...)
//! * `step_key`: current step's 32-byte key (chained from root)
//! * `send_counter`: per-step monotonic, drives outbound nonces
//! * `expected_recv_step`, `expected_recv_counter`: framing-level
//!   replay/reorder guards
//! * `consecutive_authfails`: tombstone trigger (>= 3 = death)
//! * Time + count thresholds for auto-step

use std::time::Instant;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::{
    DEFAULT_STEP_MAX_MESSAGES, DEFAULT_STEP_MAX_SECONDS, SEALED_VERSION,
    TOMBSTONE_AUTHFAIL_THRESHOLD,
};

/// Header layout for a sealed message:
/// `[ver: 1][step: 4 BE][counter: 4 BE]` => 9 bytes.
pub(crate) const SEALED_HEADER_LEN: usize = 1 + 4 + 4;
const TAG_LEN: usize = 16;

/// Hard stop on how far a receiver will lazily derive forward when
/// the peer's `step_counter` outruns ours. Bounded to keep work
/// finite if a malicious peer ships a frame with `step_counter =
/// u32::MAX`.
const MAX_LAZY_FORWARD_STEPS: u32 = 16;

/// Identifies which direction this `Session` instance encrypts on.
/// Operator's send nonce prefix = HKDF(step_key, info=op-to-signer);
/// the same value is the operator's RECV opposite-direction prefix
/// at the signer end. Symmetric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Operator,
    Signer,
}

impl Side {
    fn send_info(self) -> &'static [u8] {
        match self {
            Side::Operator => b"aeterna-sigillum-ratchet-op-to-signer-nonce",
            Side::Signer => b"aeterna-sigillum-ratchet-signer-to-op-nonce",
        }
    }

    fn recv_info(self) -> &'static [u8] {
        // Mirror image: receiver expects the peer's send_info.
        match self {
            Side::Operator => b"aeterna-sigillum-ratchet-signer-to-op-nonce",
            Side::Signer => b"aeterna-sigillum-ratchet-op-to-signer-nonce",
        }
    }
}

/// Public-facing snapshot for `santuarioctl ratchet status`.
#[derive(Debug, Clone, Copy)]
pub struct SessionStatus {
    pub step: u32,
    pub send_counter: u32,
    pub expected_recv_step: u32,
    pub expected_recv_counter: u32,
    pub age_seconds: f64,
    pub msgs_sent_in_step: u32,
    pub consecutive_authfails: u32,
    pub tombstoned: bool,
}

/// Per-step working keys. Held inline in `Active`. Wiped on drop via
/// `ZeroizeOnDrop`.
#[derive(ZeroizeOnDrop)]
struct StepKeys {
    /// 32-byte chain key for this step. Drives both prefix derivations.
    step_key: [u8; 32],
    /// HKDF-derived 8-byte nonce prefix for outbound messages.
    send_prefix: [u8; 8],
    /// HKDF-derived 8-byte nonce prefix for inbound messages.
    recv_prefix: [u8; 8],
}

impl StepKeys {
    fn derive(prev_chain_key: &[u8; 32], side: Side) -> Result<Self> {
        // Chain step: step_key[N] = HKDF(salt=step_key[N-1], ikm=b"", info=b"step")
        let hk = Hkdf::<Sha256>::new(Some(prev_chain_key), b"");
        let mut step_key = [0u8; 32];
        hk.expand(b"aeterna-sigillum-ratchet-step", &mut step_key)
            .map_err(|_| Error::Kdf("hkdf chain step"))?;

        // Two nonce prefixes from the step key.
        let hk2 = Hkdf::<Sha256>::new(Some(&step_key), b"");
        let mut send_prefix = [0u8; 8];
        hk2.expand(side.send_info(), &mut send_prefix)
            .map_err(|_| Error::Kdf("hkdf send prefix"))?;
        let hk3 = Hkdf::<Sha256>::new(Some(&step_key), b"");
        let mut recv_prefix = [0u8; 8];
        hk3.expand(side.recv_info(), &mut recv_prefix)
            .map_err(|_| Error::Kdf("hkdf recv prefix"))?;

        Ok(Self {
            step_key,
            send_prefix,
            recv_prefix,
        })
    }

    /// First step from the root_key (the post-handshake material).
    fn from_root(root_key: &[u8; 32], side: Side) -> Result<Self> {
        // For step 0 we treat root_key as the "previous chain key"
        // so the same chaining logic applies uniformly.
        Self::derive(root_key, side)
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.step_key))
    }

    fn nonce_for_send(&self, counter: u32) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.send_prefix);
        n[8..].copy_from_slice(&counter.to_be_bytes());
        n
    }

    fn nonce_for_recv(&self, counter: u32) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.recv_prefix);
        n[8..].copy_from_slice(&counter.to_be_bytes());
        n
    }
}

/// Active-state ratchet session.
struct Active {
    side: Side,
    step: u32,
    keys: StepKeys,
    send_counter: u32,
    msgs_sent_in_step: u32,
    expected_recv_step: u32,
    expected_recv_counter: u32,
    consecutive_authfails: u32,
    started_at: Instant,
    max_seconds: f64,
    max_messages: u32,
    /// Clock injection for deterministic tests. Default is
    /// `Instant::now`, indirected through this closure.
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
}

/// Public session handle. Tagged by an internal Option so transitions
/// to Tombstone don't require recreating the wrapper.
pub struct Session {
    state: Option<Active>,
    /// Set when the session has tombstoned. Caller must construct a
    /// new Session to recover.
    tombstoned: bool,
}

impl Session {
    /// Build a fresh session from a post-handshake root_key.
    pub fn new(root_key: &[u8; 32], side: Side) -> Result<Self> {
        Self::new_with_options(root_key, side, SessionOptions::default())
    }

    /// Test/dev constructor with custom thresholds and clock.
    pub fn new_with_options(
        root_key: &[u8; 32],
        side: Side,
        opts: SessionOptions,
    ) -> Result<Self> {
        let keys = StepKeys::from_root(root_key, side)?;
        let started_at = (opts.clock)();
        let active = Active {
            side,
            step: 0,
            keys,
            send_counter: 0,
            msgs_sent_in_step: 0,
            expected_recv_step: 0,
            expected_recv_counter: 0,
            consecutive_authfails: 0,
            started_at,
            max_seconds: opts.max_seconds,
            max_messages: opts.max_messages,
            clock: opts.clock,
        };
        Ok(Self {
            state: Some(active),
            tombstoned: false,
        })
    }

    pub fn is_tombstoned(&self) -> bool {
        self.tombstoned
    }

    pub fn status(&self) -> SessionStatus {
        if self.tombstoned || self.state.is_none() {
            return SessionStatus {
                step: 0,
                send_counter: 0,
                expected_recv_step: 0,
                expected_recv_counter: 0,
                age_seconds: 0.0,
                msgs_sent_in_step: 0,
                consecutive_authfails: 0,
                tombstoned: true,
            };
        }
        let a = self.state.as_ref().unwrap();
        let now = (a.clock)();
        SessionStatus {
            step: a.step,
            send_counter: a.send_counter,
            expected_recv_step: a.expected_recv_step,
            expected_recv_counter: a.expected_recv_counter,
            age_seconds: now.duration_since(a.started_at).as_secs_f64(),
            msgs_sent_in_step: a.msgs_sent_in_step,
            consecutive_authfails: a.consecutive_authfails,
            tombstoned: false,
        }
    }

    /// Force an immediate ratchet step (operator-triggered, e.g.,
    /// `santuarioctl ratchet step`).
    pub fn step(&mut self) -> Result<()> {
        self.ensure_alive()?;
        let a = self.state.as_mut().unwrap();
        Self::do_step(a)
    }

    fn ensure_alive(&self) -> Result<()> {
        if self.tombstoned {
            Err(Error::SessionTombstoned)
        } else {
            Ok(())
        }
    }

    fn do_step(a: &mut Active) -> Result<()> {
        let new_keys = StepKeys::derive(&a.keys.step_key, a.side)?;
        // Old keys drop here -> ZeroizeOnDrop wipes them.
        a.keys = new_keys;
        a.step = a.step.checked_add(1).ok_or(Error::CounterSaturated)?;
        a.send_counter = 0;
        a.msgs_sent_in_step = 0;
        a.started_at = (a.clock)();
        Ok(())
    }

    /// Encrypt a plaintext into a wire frame ready for transport.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.ensure_alive()?;
        // Auto-step if thresholds exceeded.
        let needs_step = {
            let a = self.state.as_ref().unwrap();
            let age = (a.clock)().duration_since(a.started_at).as_secs_f64();
            age >= a.max_seconds || a.msgs_sent_in_step >= a.max_messages
        };
        if needs_step {
            let a = self.state.as_mut().unwrap();
            Self::do_step(a)?;
        }
        let a = self.state.as_mut().unwrap();
        if a.send_counter >= u32::MAX - 1024 {
            return Err(Error::CounterSaturated);
        }
        let counter = a.send_counter;
        let header = build_header(a.step, counter);
        let nonce_bytes = a.keys.nonce_for_send(counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = a
            .keys
            .cipher()
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| Error::Invariant("ChaCha20-Poly1305 encrypt failed"))?;
        a.send_counter = counter
            .checked_add(1)
            .ok_or(Error::CounterSaturated)?;
        a.msgs_sent_in_step = a
            .msgs_sent_in_step
            .checked_add(1)
            .ok_or(Error::CounterSaturated)?;

        let mut wire = Vec::with_capacity(SEALED_HEADER_LEN + ciphertext.len());
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&ciphertext);
        Ok(wire)
    }

    /// Decrypt a wire frame.
    pub fn decrypt(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        self.ensure_alive()?;
        if frame.len() < SEALED_HEADER_LEN + TAG_LEN {
            return Err(Error::FrameTooShort {
                got: frame.len(),
                need: SEALED_HEADER_LEN + TAG_LEN,
            });
        }
        if frame[0] != SEALED_VERSION {
            return Err(Error::UnsupportedVersion(frame[0]));
        }
        let mut step_bytes = [0u8; 4];
        step_bytes.copy_from_slice(&frame[1..5]);
        let frame_step = u32::from_be_bytes(step_bytes);
        let mut counter_bytes = [0u8; 4];
        counter_bytes.copy_from_slice(&frame[5..9]);
        let frame_counter = u32::from_be_bytes(counter_bytes);

        let header = &frame[..SEALED_HEADER_LEN];
        let ciphertext = &frame[SEALED_HEADER_LEN..];

        // Resolve the receive-side step keys to use.
        let res = self.try_decrypt(frame_step, frame_counter, header, ciphertext);
        match res {
            Ok(pt) => {
                let a = self.state.as_mut().unwrap();
                a.consecutive_authfails = 0;
                a.expected_recv_step = frame_step;
                a.expected_recv_counter = frame_counter
                    .checked_add(1)
                    .ok_or(Error::CounterSaturated)?;
                Ok(pt)
            }
            Err(Error::AuthFailed) => {
                let a = self.state.as_mut().unwrap();
                a.consecutive_authfails = a.consecutive_authfails.saturating_add(1);
                if a.consecutive_authfails >= TOMBSTONE_AUTHFAIL_THRESHOLD {
                    self.tombstoned = true;
                    self.state = None;
                }
                Err(Error::AuthFailed)
            }
            Err(e) => Err(e),
        }
    }

    fn try_decrypt(
        &mut self,
        frame_step: u32,
        frame_counter: u32,
        header: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let a = self.state.as_mut().unwrap();
        // Reject step regress (replay across a step boundary).
        if frame_step < a.expected_recv_step {
            return Err(Error::AuthFailed);
        }
        // Reject within-step regress.
        if frame_step == a.expected_recv_step && frame_counter < a.expected_recv_counter {
            return Err(Error::OutOfOrder {
                expected: a.expected_recv_counter,
                got: frame_counter,
            });
        }
        // Lazy forward derivation: if peer is ahead, derive recv keys
        // forward up to MAX_LAZY_FORWARD_STEPS.
        if frame_step > a.expected_recv_step {
            let delta = frame_step - a.expected_recv_step;
            if delta > MAX_LAZY_FORWARD_STEPS {
                return Err(Error::AuthFailed);
            }
            // Derive forward in a temporary chain so we don't perturb
            // our local send_state.
            let mut chain = a.keys.step_key;
            let mut tmp_keys = StepKeys::derive(&chain, a.side)?;
            for _ in 1..delta {
                chain = tmp_keys.step_key;
                tmp_keys = StepKeys::derive(&chain, a.side)?;
            }
            chain.zeroize();
            // Try decrypt with the forward keys.
            let nonce_bytes = tmp_keys.nonce_for_recv(frame_counter);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let pt = tmp_keys
                .cipher()
                .decrypt(
                    nonce,
                    Payload {
                        msg: ciphertext,
                        aad: header,
                    },
                )
                .map_err(|_| Error::AuthFailed)?;
            // Adopt the new step state.
            a.keys = tmp_keys;
            a.step = frame_step;
            a.send_counter = 0;
            a.msgs_sent_in_step = 0;
            a.started_at = (a.clock)();
            return Ok(pt);
        }
        // Same step.
        let nonce_bytes = a.keys.nonce_for_recv(frame_counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        a.keys
            .cipher()
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| Error::AuthFailed)
    }
}

/// Constructor options for `Session::new_with_options`.
pub struct SessionOptions {
    pub max_seconds: f64,
    pub max_messages: u32,
    pub clock: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            max_seconds: DEFAULT_STEP_MAX_SECONDS,
            max_messages: DEFAULT_STEP_MAX_MESSAGES,
            clock: Box::new(Instant::now),
        }
    }
}

fn build_header(step: u32, counter: u32) -> [u8; SEALED_HEADER_LEN] {
    let mut h = [0u8; SEALED_HEADER_LEN];
    h[0] = SEALED_VERSION;
    h[1..5].copy_from_slice(&step.to_be_bytes());
    h[5..9].copy_from_slice(&counter.to_be_bytes());
    h
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn roots(side_a: Side, side_b: Side) -> (Session, Session) {
        let root = [0xAA; 32];
        (
            Session::new(&root, side_a).unwrap(),
            Session::new(&root, side_b).unwrap(),
        )
    }

    #[test]
    fn round_trip_single_message() {
        let (mut op, mut sg) = roots(Side::Operator, Side::Signer);
        let frame = op.encrypt(b"ciao signer").unwrap();
        assert_eq!(frame[0], SEALED_VERSION);
        let pt = sg.decrypt(&frame).unwrap();
        assert_eq!(pt, b"ciao signer");
    }

    #[test]
    fn round_trip_bidirectional() {
        let (mut op, mut sg) = roots(Side::Operator, Side::Signer);
        let f1 = op.encrypt(b"req-1").unwrap();
        assert_eq!(sg.decrypt(&f1).unwrap(), b"req-1");
        let f2 = sg.encrypt(b"resp-1").unwrap();
        assert_eq!(op.decrypt(&f2).unwrap(), b"resp-1");
    }

    #[test]
    fn unsupported_version_rejected() {
        let (mut op, _sg) = roots(Side::Operator, Side::Signer);
        let mut frame = op.encrypt(b"x").unwrap();
        frame[0] = 0xFE;
        let mut sg = Session::new(&[0xAA; 32], Side::Signer).unwrap();
        let err = sg.decrypt(&frame).unwrap_err();
        assert!(matches!(err, Error::UnsupportedVersion(0xFE)), "got {:?}", err);
    }

    #[test]
    fn frame_too_short_rejected() {
        let (mut _op, mut sg) = roots(Side::Operator, Side::Signer);
        let err = sg.decrypt(&[0x10, 0, 0, 0, 0]).unwrap_err();
        assert!(matches!(err, Error::FrameTooShort { .. }));
    }

    #[test]
    fn tampered_ciphertext_authfails() {
        let (mut op, mut sg) = roots(Side::Operator, Side::Signer);
        let mut frame = op.encrypt(b"valid").unwrap();
        // Flip a byte deep in the ciphertext.
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        let err = sg.decrypt(&frame).unwrap_err();
        assert!(matches!(err, Error::AuthFailed));
    }

    #[test]
    fn three_consecutive_authfails_tombstone() {
        let (mut op, mut sg) = roots(Side::Operator, Side::Signer);
        for _ in 0..3 {
            let mut frame = op.encrypt(b"x").unwrap();
            let last = frame.len() - 1;
            frame[last] ^= 0xFF;
            let _ = sg.decrypt(&frame);
        }
        assert!(sg.is_tombstoned());
        // A subsequent legitimate frame is rejected with SessionTombstoned.
        let frame = op.encrypt(b"valid-but-too-late").unwrap();
        assert!(matches!(
            sg.decrypt(&frame).unwrap_err(),
            Error::SessionTombstoned
        ));
    }

    #[test]
    fn authfail_counter_resets_on_success() {
        let (mut op, mut sg) = roots(Side::Operator, Side::Signer);
        // Two bad frames.
        for _ in 0..2 {
            let mut frame = op.encrypt(b"x").unwrap();
            let last = frame.len() - 1;
            frame[last] ^= 0xFF;
            let _ = sg.decrypt(&frame);
        }
        // One good frame -- consecutive_authfails resets to 0.
        let good = op.encrypt(b"recovery").unwrap();
        assert_eq!(sg.decrypt(&good).unwrap(), b"recovery");
        assert!(!sg.is_tombstoned());
        // Two more bad in a row should NOT tombstone (we reset).
        for _ in 0..2 {
            let mut frame = op.encrypt(b"x").unwrap();
            let last = frame.len() - 1;
            frame[last] ^= 0xFF;
            let _ = sg.decrypt(&frame);
        }
        assert!(!sg.is_tombstoned());
    }

    #[test]
    fn out_of_order_within_step_returns_outoforder() {
        let (mut op, mut sg) = roots(Side::Operator, Side::Signer);
        let f0 = op.encrypt(b"zero").unwrap();
        let f1 = op.encrypt(b"one").unwrap();
        // Receive in correct order: 0 then 1 -> ok.
        sg.decrypt(&f0).unwrap();
        sg.decrypt(&f1).unwrap();
        // Receive f0 again (replay) -> OutOfOrder (counter regress).
        let err = sg.decrypt(&f0).unwrap_err();
        assert!(matches!(err, Error::OutOfOrder { .. }));
    }

    #[test]
    fn forced_step_changes_step_counter() {
        let (mut op, mut sg) = roots(Side::Operator, Side::Signer);
        assert_eq!(op.status().step, 0);
        op.step().unwrap();
        assert_eq!(op.status().step, 1);
        let frame = op.encrypt(b"after-step").unwrap();
        // Wire frame's step byte must reflect step 1.
        let mut stp = [0u8; 4];
        stp.copy_from_slice(&frame[1..5]);
        assert_eq!(u32::from_be_bytes(stp), 1);
        // Receiver lazy-forwards to step 1 and decrypts cleanly.
        let pt = sg.decrypt(&frame).unwrap();
        assert_eq!(pt, b"after-step");
        assert_eq!(sg.status().step, 1);
    }

    #[test]
    fn auto_step_after_max_messages() {
        let opts = SessionOptions {
            max_messages: 3,
            max_seconds: f64::INFINITY,
            clock: Box::new(Instant::now),
        };
        let mut op = Session::new_with_options(&[0xAA; 32], Side::Operator, opts).unwrap();
        for _ in 0..3 {
            op.encrypt(b"x").unwrap();
        }
        // Next encrypt should auto-trigger step.
        let frame = op.encrypt(b"trigger").unwrap();
        let mut stp = [0u8; 4];
        stp.copy_from_slice(&frame[1..5]);
        assert_eq!(u32::from_be_bytes(stp), 1, "auto-step on max_messages");
    }

    #[test]
    fn lazy_forward_too_far_authfails() {
        // Operator steps many times; signer hasn't seen any. The
        // signer's lazy forward is bounded; beyond MAX, AuthFailed.
        let (mut op, mut sg) = roots(Side::Operator, Side::Signer);
        for _ in 0..(MAX_LAZY_FORWARD_STEPS + 2) {
            op.step().unwrap();
        }
        let frame = op.encrypt(b"too-far-ahead").unwrap();
        let err = sg.decrypt(&frame).unwrap_err();
        assert!(matches!(err, Error::AuthFailed));
    }

    #[test]
    fn tombstone_blocks_encrypt() {
        let mut op = Session::new(&[0xAA; 32], Side::Operator).unwrap();
        // Tombstone manually for the test.
        op.tombstoned = true;
        op.state = None;
        let err = op.encrypt(b"x").unwrap_err();
        assert!(matches!(err, Error::SessionTombstoned));
    }

    #[test]
    fn status_after_tombstone_reports_dead() {
        let mut op = Session::new(&[0xAA; 32], Side::Operator).unwrap();
        op.tombstoned = true;
        op.state = None;
        assert!(op.status().tombstoned);
    }

    #[test]
    fn different_roots_authfail() {
        let mut op = Session::new(&[0xAA; 32], Side::Operator).unwrap();
        let mut sg = Session::new(&[0xBB; 32], Side::Signer).unwrap();
        let frame = op.encrypt(b"secret").unwrap();
        let err = sg.decrypt(&frame).unwrap_err();
        assert!(matches!(err, Error::AuthFailed));
    }

    #[test]
    fn header_round_trip() {
        let h = build_header(0xDEADBEEF, 0xCAFE);
        assert_eq!(h[0], SEALED_VERSION);
        assert_eq!(&h[1..5], &0xDEADBEEFu32.to_be_bytes());
        assert_eq!(&h[5..9], &0xCAFEu32.to_be_bytes());
    }
}
