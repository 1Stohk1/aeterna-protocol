"""
AETERNA Protocol — P2P Knowledge Sharing
This module implements functions to package, sign, and verify expert centroids
shared across the decentralised gossip network.
"""

import json
import hashlib
import time
import numpy as np
from typing import Dict, Any, Tuple, Optional

def canonical_hash(obj: Any) -> bytes:
    """
    Computes a canonical SHA-256 hash of a JSON-serializable object.
    """
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).digest()

def build_expert_share_message(
    expert_id: str, 
    centroid_omega: np.ndarray, 
    node_id: str, 
    santuario_client: Any
) -> Dict[str, Any]:
    """
    Builds and cryptographically signs a gossip message containing an expert's shared centroid.
    """
    centroid_list = [float(x) for x in centroid_omega.flatten()]
    
    payload_body = {
        "expert_id": expert_id,
        "centroid": centroid_list,
        "creator_node_id": node_id,
        "timestamp": int(time.time()),
    }
    
    payload_hash = canonical_hash(payload_body)
    
    if santuario_client is not None:
        signature = santuario_client.sign(payload_hash)
        public_key = santuario_client.get_public_key()
        sig_hex = signature.hex()
        pubkey_hex = public_key.hex()
    else:
        sig_hex = ""
        pubkey_hex = ""
        
    return {
        "kind": "expert_share",
        "payload": payload_body,
        "security": {
            "payload_hash": payload_hash.hex(),
            "signature": sig_hex,
            "public_key": pubkey_hex,
        }
    }

def verify_expert_share_message(
    message: Dict[str, Any], 
    santuario_client: Any
) -> Tuple[bool, str]:
    """
    Verifies the signature and payload integrity of a shared expert gossip message.
    """
    payload = message.get("payload")
    security = message.get("security")
    if not isinstance(payload, Dict) or not isinstance(security, Dict):
        return False, "missing payload or security block"
        
    try:
        claimed_hash = bytes.fromhex(security.get("payload_hash", ""))
        expected_hash = canonical_hash(payload)
        if claimed_hash != expected_hash:
            return False, "payload_hash mismatch"
            
        signature = bytes.fromhex(security.get("signature", ""))
        public_key = bytes.fromhex(security.get("public_key", ""))
    except (TypeError, ValueError):
        return False, "malformed hex field"
        
    if santuario_client is None:
        return True, "genesis mode: signature verification bypassed"
        
    if not santuario_client.verify(claimed_hash, signature, public_key):
        return False, "invalid cryptographic signature"
        
    return True, "ok"
