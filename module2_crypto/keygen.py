"""
module2_crypto/keygen.py - Secure random key generation.

Rule: keys and nonces MUST come from the operating system's cryptographically
secure random generator (Python's `secrets` module or `os.urandom`).
Never use the `random` module for security - it is predictable.

Each device gets ONE 256-bit master key. From it we derive three separate
sub-keys with HKDF-SHA256, so that one key is never used for two jobs:
    enc  -> AES-GCM encryption of payloads
    mac  -> HMAC-SHA256 integrity tag
    auth -> challenge-response authentication
"""

import os
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_BYTES = 32          # 256-bit keys
NONCE_BYTES = 12        # 96-bit nonce, the recommended size for AES-GCM


def new_key(n_bytes=KEY_BYTES):
    """Return a fresh random secret key (bytes) from the OS secure generator."""
    return secrets.token_bytes(n_bytes)


def new_nonce(n_bytes=NONCE_BYTES):
    """Return a fresh random nonce. A nonce must never repeat with the same key."""
    return os.urandom(n_bytes)


def new_ecdsa_private_key():
    """Generate an ECDSA private key on the NIST P-256 curve."""
    return ec.generate_private_key(ec.SECP256R1())


def derive_subkeys(master_key):
    """Split one master key into independent 'enc', 'mac' and 'auth' keys (HKDF-SHA256)."""
    subkeys = {}
    for purpose in ("enc", "mac", "auth"):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=None,
                    info=b"secureTeam-SecureIoT-Sim/" + purpose.encode())
        subkeys[purpose] = hkdf.derive(master_key)
    return subkeys
