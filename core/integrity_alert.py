"""
integrity_alert — gossip payload builder for the α/β/γ watchdog.

The Rust ``santuario-integrity`` crate produces ``IntegrityAlert`` records.
The Sentinel reads them from the signer's gRPC stream and broadcasts each
over ``AeternaGossipNet.gossip`` as a signed envelope so every peer knows
this node is now in degraded mode.

The wire shape (one-line JSON, sort_keys-ordered) is:

.. code-block:: json

    {
      "kind": "integrity_alert",
      "payload": {
        "kind": "alpha" | "beta" | "gamma",
        "ts_utc": 1713542400,
        "node_id": "Prometheus-1",
        "evidence": {"type": "alpha_mismatch", "path": "...", ...}
      },
      "signature_hex": "<dilithium5 over canonical(payload)>"
    }

Callers produce the ``signature_hex`` via the signer's gRPC ``sign``
endpoint (the signer does NOT self-suspend until AFTER it has endorsed
the alert — the alert itself is the final Dilithium-5 signature it
emits before going dark).
"""

from __future__ import annotations

import json
from typing import Any

# The gossip ``kind`` discriminator. Peers that don't recognise this kind
# MUST still relay the envelope (unknown-kind fallback in the gossip
# listener) so the warning reaches everyone even if mixed-version nodes
# haven't upgraded to v0.2.0 yet.
INTEGRITY_ALERT_KIND = "integrity_alert"

# Valid threshold types — match santuario_integrity::AlertKind names.
ALPHA = "alpha"
BETA = "beta"
GAMMA = "gamma"
_VALID_KINDS = frozenset({ALPHA, BETA, GAMMA})


def canonical_payload(alert: dict[str, Any]) -> bytes:
    """Produce the exact byte-string the Rust signer signs.

    The Rust side serialises with serde_json default ordering.
    To interop we normalise on sort_keys + separators=(",",":").
    """
    return json.dumps(alert, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def validate_alert(alert: dict[str, Any]) -> None:
    """Raise ValueError if ``alert`` is not a well-formed Rust IntegrityAlert."""
    if not isinstance(alert, dict):
        raise ValueError("alert must be a dict")
    for f in ("kind", "ts_utc", "node_id", "evidence"):
        if f not in alert:
            raise ValueError(f"alert missing required field: {f!r}")
    if alert["kind"] not in _VALID_KINDS:
        raise ValueError(
            f"alert.kind must be one of {sorted(_VALID_KINDS)}, got {alert['kind']!r}"
        )
    ev = alert["evidence"]
    if not isinstance(ev, dict) or "type" not in ev:
        raise ValueError("alert.evidence must be an object with a 'type' tag")


def build_envelope(alert: dict[str, Any], signature_hex: str) -> dict[str, Any]:
    """Wrap an IntegrityAlert for gossip transport.

    ``alert`` must be a parsed Rust ``IntegrityAlert`` (e.g. the result
    of ``json.loads(rust_signer.serialise_latest_alert())``).
    ``signature_hex`` is the Dilithium-5 signature over
    ``canonical_payload(alert)`` in lowercase hex.
    """
    validate_alert(alert)
    if not isinstance(signature_hex, str) or not signature_hex:
        raise ValueError("signature_hex must be a non-empty string")
    return {
        "kind": INTEGRITY_ALERT_KIND,
        "payload": alert,
        "signature_hex": signature_hex,
    }


def is_integrity_alert(envelope: dict[str, Any]) -> bool:
    """Fast discriminator for gossip listeners."""
    return isinstance(envelope, dict) and envelope.get("kind") == INTEGRITY_ALERT_KIND


def extract_alert(envelope: dict[str, Any]) -> dict[str, Any]:
    """Return the inner alert dict from a validated envelope.

    Raises ValueError if the envelope is malformed.
    """
    if not is_integrity_alert(envelope):
        raise ValueError("envelope is not an integrity_alert")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("integrity_alert envelope missing 'payload' dict")
    validate_alert(payload)
    return payload


__all__ = [
    "INTEGRITY_ALERT_KIND",
    "ALPHA",
    "BETA",
    "GAMMA",
    "canonical_payload",
    "validate_alert",
    "build_envelope",
    "is_integrity_alert",
    "extract_alert",
]
