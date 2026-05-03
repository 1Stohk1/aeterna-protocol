"""
AETERNA v0.4 "Sigillum" — gossip frame cipher.

This module is the Python-side implementation of Phase B of the
SPRINT-v0.4.0 plan. It provides a ``GossipCipher`` that wraps every
outbound UDP datagram in a ChaCha20-Poly1305 sealed envelope and that
unwraps every inbound datagram before the gossip layer touches it.

## Why a separate session layer

The audit log (Phase A) is written by a single process to its own
disk, so a single master key derived per file segment is enough. The
gossip channel is different:

* Many Guardians share the same wire.
* A captured datagram from session N must NOT help an attacker decrypt
  any datagram from session N-1 (replay) or N+1 (forward secrecy).
* Sessions rotate by time AND by message count to bound the blast
  radius of any single key compromise.

We get all three with a tiny HKDF-derived per-session subkey. The
``gossip_root_key`` is the long-term secret (32 random bytes per node);
each session_id derives a unique subkey + nonce_prefix from it via
HKDF-SHA256. Leaking a session_key tells the attacker nothing about
the root key (HKDF is one-way), so prior and future sessions remain
opaque.

A leaked **root key** does compromise every session past and future.
True per-session forward secrecy needs Diffie-Hellman; that is the
operator-endpoint ratchet of Phase C, not gossip.

## Wire format

Every outbound datagram is::

    +------+------+------------+------------+----------------------+
    | ver  | kind | session_id |  counter   | ciphertext + tag(16) |
    | 1B   | 1B   |  4B BE u32 |  4B BE u32 |       variable       |
    +------+------+------------+------------+----------------------+

* ``ver = 0x04``: Sigillum.
* ``kind``: informational (0x00 = untyped). Reserved for v0.5 routing
  filters; today we always set 0x00 and accept any value on receive.
* ``session_id``: monotonically-increasing within a single root-key
  lifetime; resets on root rotation only.
* ``counter``: monotonically-increasing within a single session_id;
  resets on session rotation. The full ChaCha20 nonce is
  ``nonce_prefix(8 bytes from HKDF) || counter(4 bytes BE)``.

The 10-byte header is also the AEAD additional data (AAD), so an
attacker cannot strip ``kind`` or ``session_id`` without breaking
authentication.

## Threat model bullet points

* Read-only network capture: defeated.
* Active MITM that replays past datagrams: defeated by the
  ``(session_id, counter)`` AD binding plus the gossip dedup cache
  upstream.
* Compromise of one session_key: prior and future sessions remain
  opaque (HKDF one-wayness).
* Compromise of the root key: total. Operator must rotate.
* Datagram reordering across session rotation: tolerated within a
  bounded LRU of recent sessions on the receiver (default 4).
"""

from __future__ import annotations

import logging
import os
import secrets
import struct
import threading
import time
from collections import OrderedDict
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

LOG = logging.getLogger("aeterna.sigillum.gossip")


# ---------------------------------------------------------------------------
# Wire constants -- these are part of the inter-node contract. Bumping any of
# them forces a coordinated upgrade across all peers in the network.
# ---------------------------------------------------------------------------

SCHEMA_VERSION: int = 0x04
HEADER_LEN: int = 10  # ver(1) + kind(1) + session_id(4) + counter(4)
TAG_LEN: int = 16     # ChaCha20-Poly1305 authentication tag
NONCE_LEN: int = 12   # ChaCha20-Poly1305 nonce
ROOT_KEY_LEN: int = 32

# HKDF info string for session-key derivation. The "v1" suffix locks the
# format to this sprint -- a future ratchet upgrade would bump it.
_HKDF_INFO_PREFIX: bytes = b"aeterna-sigillum-gossip-session-v1"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SigillumError(Exception):
    """Base class for gossip cipher failures."""


class FrameTooShort(SigillumError):
    """Frame is shorter than the fixed header."""


class UnsupportedVersion(SigillumError):
    """First byte is not 0x04 -- this datagram is not a Sigillum frame."""

    def __init__(self, ver: int) -> None:
        super().__init__(f"unsupported gossip cipher version: 0x{ver:02x}")
        self.ver = ver


class DecryptFailed(SigillumError):
    """Authentication tag verification failed: tampered or wrong key."""


class CounterReused(SigillumError):
    """Internal invariant: same (session_id, counter) emitted twice."""


# ---------------------------------------------------------------------------
# Root key provisioning -- mirrors MasterLogKey::load_or_generate from the
# Rust santuario-cipher crate. Same first-boot semantics: random + persist
# on absence, refuse to silently regenerate a corrupted file.
# ---------------------------------------------------------------------------


def load_or_generate_root_key(path: Path | str) -> bytes:
    """Load 32-byte gossip root key from ``path``, or generate + persist.

    On creation the file is written via tmp+rename for crash-safety, and
    on POSIX is chmodded to 0o600. On Windows the operator is expected
    to have ACL'd the parent directory; bootstrap.ps1 owns that.
    """
    path = Path(path)
    if path.exists():
        data = path.read_bytes()
        if len(data) != ROOT_KEY_LEN:
            raise SigillumError(
                f"gossip_root.key has wrong length {len(data)} (expected {ROOT_KEY_LEN}) "
                f"-- corrupted or wrong file at {path}"
            )
        return data

    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(ROOT_KEY_LEN)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(key)
    if hasattr(os, "chmod") and os.name == "posix":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return key


def root_key_id(root_key: bytes) -> bytes:
    """Public identifier (16 bytes) for a gossip root key."""
    h = hashes.Hash(hashes.SHA256())
    h.update(root_key)
    return h.finalize()[:16]


# ---------------------------------------------------------------------------
# Session entry -- one of these lives in the receiver's LRU and in the
# sender's "current session" slot. Holds the ChaCha20-Poly1305 instance
# so we don't pay key schedule cost per frame.
# ---------------------------------------------------------------------------


class _Session:
    __slots__ = ("session_id", "subkey", "nonce_prefix", "cipher")

    def __init__(self, session_id: int, subkey: bytes, nonce_prefix: bytes) -> None:
        if len(subkey) != 32 or len(nonce_prefix) != 8:
            raise SigillumError("internal: malformed session derivation")
        self.session_id = session_id
        self.subkey = subkey
        self.nonce_prefix = nonce_prefix
        self.cipher = ChaCha20Poly1305(subkey)


def _derive_session(root_key: bytes, root_id: bytes, session_id: int) -> _Session:
    """HKDF-SHA256 expand a root key into a session subkey + nonce_prefix."""
    info = _HKDF_INFO_PREFIX + struct.pack(">I", session_id)
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=32 + 8,
        salt=root_id,
        info=info,
    ).derive(root_key)
    return _Session(session_id, okm[:32], okm[32:])


# ---------------------------------------------------------------------------
# GossipCipher -- the public surface. Thread-safe (a single Sentinel uses
# this from the gossip listener thread + the main loop emitting blocks).
# ---------------------------------------------------------------------------


class GossipCipher:
    """ChaCha20-Poly1305 envelope for AeternaGossipNet datagrams.

    Construction is cheap: we hold the root key, the root id, a single
    active sender session, and a small LRU of receiver sessions. No
    background threads are spawned -- rotation is checked synchronously
    on each :meth:`seal` call.
    """

    def __init__(
        self,
        root_key: bytes,
        *,
        session_max_seconds: float = 3600.0,
        session_max_messages: int = 65_535,
        active_sessions_lru: int = 4,
        clock: "callable | None" = None,
    ) -> None:
        if len(root_key) != ROOT_KEY_LEN:
            raise SigillumError(
                f"gossip root key must be {ROOT_KEY_LEN} bytes, got {len(root_key)}"
            )
        if session_max_messages <= 0:
            raise SigillumError("session_max_messages must be > 0")
        if active_sessions_lru < 1:
            raise SigillumError("active_sessions_lru must be >= 1")

        self._root_key = root_key
        self._root_id = root_key_id(root_key)
        self._max_seconds = float(session_max_seconds)
        self._max_messages = int(session_max_messages)
        self._lru_capacity = int(active_sessions_lru)
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()

        # Sender state.
        self._tx_session: _Session = _derive_session(self._root_key, self._root_id, 0)
        self._tx_session_started_at: float = self._clock()
        self._tx_counter: int = 0
        self._tx_messages_in_session: int = 0
        # ID for the NEXT session we'll mint on rotation.
        self._next_session_id: int = 1

        # Receiver LRU: maps session_id -> _Session; OrderedDict gives us
        # O(1) most-recently-used eviction.
        self._rx_sessions: OrderedDict[int, _Session] = OrderedDict()
        self._touch_rx_session(self._tx_session)

    # --- public api ---------------------------------------------------

    @property
    def root_key_id_hex(self) -> str:
        return self._root_id.hex()

    @property
    def current_session_id(self) -> int:
        return self._tx_session.session_id

    def seal(self, plaintext: bytes, *, kind: int = 0) -> bytes:
        """Encrypt + frame ``plaintext``. Returns the wire datagram.

        Rotates the sender session if it has aged past
        ``session_max_seconds`` OR served more than
        ``session_max_messages`` frames, whichever comes first.
        """
        if not (0 <= kind <= 0xFF):
            raise SigillumError("kind must fit in one unsigned byte")

        with self._lock:
            self._maybe_rotate_locked()

            session = self._tx_session
            counter = self._tx_counter
            if counter >= 0xFFFFFFFF:
                # Same defense as in santuario-cipher: a session_id should
                # rotate long before counter approaches u32::MAX. If it
                # didn't, refuse to ship and force the operator to look.
                raise CounterReused(
                    f"session {session.session_id} counter saturated"
                )
            header = struct.pack(
                ">BBII",
                SCHEMA_VERSION,
                kind & 0xFF,
                session.session_id,
                counter,
            )
            nonce = session.nonce_prefix + struct.pack(">I", counter)
            ciphertext = session.cipher.encrypt(nonce, plaintext, header)
            self._tx_counter = counter + 1
            self._tx_messages_in_session += 1
            return header + ciphertext

    def open(self, frame: bytes) -> tuple[int, bytes]:
        """Decrypt + unframe. Returns ``(kind, plaintext)``.

        Raises :class:`UnsupportedVersion`, :class:`FrameTooShort`,
        :class:`DecryptFailed`, or :class:`SigillumError` on malformed
        frames. The caller (gossip listener) drops on any error.
        """
        if len(frame) < HEADER_LEN + TAG_LEN:
            raise FrameTooShort(
                f"frame is {len(frame)} bytes; need >= {HEADER_LEN + TAG_LEN}"
            )
        header = frame[:HEADER_LEN]
        ciphertext = frame[HEADER_LEN:]
        ver, kind, session_id, counter = struct.unpack(">BBII", header)
        if ver != SCHEMA_VERSION:
            raise UnsupportedVersion(ver)

        with self._lock:
            session = self._lookup_or_derive_locked(session_id)

        nonce = session.nonce_prefix + struct.pack(">I", counter)
        try:
            plaintext = session.cipher.decrypt(nonce, ciphertext, header)
        except InvalidTag as exc:
            raise DecryptFailed(
                f"auth tag invalid for session_id={session_id} counter={counter}"
            ) from exc
        return kind, plaintext

    # --- internals ----------------------------------------------------

    def _maybe_rotate_locked(self) -> None:
        now = self._clock()
        age = now - self._tx_session_started_at
        if (
            age >= self._max_seconds
            or self._tx_messages_in_session >= self._max_messages
        ):
            new_id = self._next_session_id
            self._next_session_id = new_id + 1
            new_session = _derive_session(self._root_key, self._root_id, new_id)
            self._tx_session = new_session
            self._tx_session_started_at = now
            self._tx_counter = 0
            self._tx_messages_in_session = 0
            # Make sure the receiver side can decrypt frames it sent
            # itself (loopback sanity, also keeps the LRU primed).
            self._touch_rx_session(new_session)
            LOG.info(
                "gossip cipher rotated session_id=%d age_s=%.1f msgs=%d",
                new_id,
                age,
                self._max_messages if self._tx_messages_in_session >= self._max_messages else 0,
            )

    def _lookup_or_derive_locked(self, session_id: int) -> _Session:
        """Hot path on receive: O(1) cache hit, slow path derives + evicts."""
        existing = self._rx_sessions.get(session_id)
        if existing is not None:
            # Mark MRU.
            self._rx_sessions.move_to_end(session_id)
            return existing
        derived = _derive_session(self._root_key, self._root_id, session_id)
        self._touch_rx_session(derived)
        return derived

    def _touch_rx_session(self, session: _Session) -> None:
        # Caller holds self._lock OR is in __init__.
        self._rx_sessions[session.session_id] = session
        self._rx_sessions.move_to_end(session.session_id)
        while len(self._rx_sessions) > self._lru_capacity:
            evicted, _ = self._rx_sessions.popitem(last=False)
            LOG.debug("gossip cipher LRU evicted session_id=%d", evicted)
