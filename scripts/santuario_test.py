import logging
import sys
from pathlib import Path
import hashlib

# Add parent dir to path so core imports work
sys.path.append(str(Path(__file__).parent.parent))

from core.santuario_client import SantuarioClient

def main():
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger("santuario_test")
    log.info("Starting Santuario Python integration test...")

    try:
        client = SantuarioClient()
    except Exception as e:
        log.error(f"Failed to instantiate SantuarioClient: {e}")
        log.warning("Note: The Rust Santuario signer must be running for this test to pass.")
        sys.exit(1)

    log.info("Client instantiated. Requesting public key...")
    try:
        pub_key = client.get_public_key()
        log.info(f"Received public key: {len(pub_key)} bytes")
    except Exception as e:
        log.error(f"get_public_key failed: {e}")
        log.warning("Make sure the gRPC server is listening on TCP 127.0.0.1:50051 (Windows) or UDS (Unix).")
        sys.exit(1)

    # Create a fake 32-byte hash
    fake_payload = b"AETERNA_SPRINT_V010_TEST_BLOCK_0"
    payload_hash = hashlib.sha256(fake_payload).digest()
    
    log.info(f"Generated fake payload hash (32 bytes): {payload_hash.hex()}")

    log.info("Requesting Dilithium-5 signature...")
    try:
        signature = client.sign(payload_hash)
        log.info(f"Received signature: {len(signature)} bytes")
    except Exception as e:
        log.error(f"sign failed: {e}")
        sys.exit(1)

    log.info("Requesting signature verification...")
    try:
        is_valid = client.verify(payload_hash, signature, pub_key)
        if is_valid:
            log.info("Verification SUCCESS: the signature is valid.")
        else:
            log.error("Verification FAILED: the signature is invalid.")
            sys.exit(1)
    except Exception as e:
        log.error(f"verify failed: {e}")
        sys.exit(1)

    log.info("Testing invalid signature scenario...")
    bad_hash = hashlib.sha256(b"CORRUPTED").digest()
    is_valid_bad = client.verify(bad_hash, signature, pub_key)
    if not is_valid_bad:
        log.info("Corrupted payload verification properly REJECTED.")
    else:
        log.error("Security failure: Corrupted payload was accepted!")
        sys.exit(1)

    log.info("All Santuario integration tests passed.")
    sys.exit(0)

if __name__ == "__main__":
    main()
