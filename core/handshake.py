from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any


def canonical_peer_announce_hash(payload: dict[str, Any]) -> bytes:
    payload_raw = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload_raw).digest()


def build_peer_announce(guardian_id: str, manifesto_path: str, santuario_client) -> dict:
    manifesto_digest = hashlib.sha3_256(Path(manifesto_path).read_bytes()).hexdigest()
    public_key_bytes = santuario_client.get_public_key()

    payload_body = {
        "guardian_id": guardian_id,
        "manifesto_digest": manifesto_digest,
        "timestamp": int(time.time()),
    }
    payload_hash = canonical_peer_announce_hash(payload_body)
    signature = santuario_client.sign(payload_hash)

    return {
        "kind": "peer_announce",
        "payload": payload_body,
        "security": {
            "payload_hash": payload_hash.hex(),
            "signature": signature.hex(),
            "public_key": public_key_bytes.hex(),
        },
    }


def verify_peer_announce(message: dict[str, Any], santuario_client) -> tuple[bool, str]:
    payload = message.get("payload")
    security = message.get("security")
    if not isinstance(payload, dict) or not isinstance(security, dict):
        return False, "missing payload or security block"

    try:
        claimed_hash = bytes.fromhex(security.get("payload_hash", ""))
        expected_hash = canonical_peer_announce_hash(payload)
        if claimed_hash != expected_hash:
            return False, "payload_hash mismatch"

        signature = bytes.fromhex(security.get("signature", ""))
        public_key = bytes.fromhex(security.get("public_key", ""))
    except (TypeError, ValueError):
        return False, "malformed hex field"

    if not santuario_client.verify(claimed_hash, signature, public_key):
        return False, "invalid cryptographic signature"

    return True, "ok"
