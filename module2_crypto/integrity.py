"""
module2_crypto/integrity.py - SHA-256 hashing and HMAC-SHA256.

SHA-256 alone proves data was not changed ACCIDENTALLY - but an attacker can
simply recompute the hash after changing the data.
HMAC-SHA256 mixes a secret key into the hash, so only someone who holds the
key can produce a valid tag. The gateway uses it to check every message.
"""

import hashlib
import hmac


def sha256_hex(data):
    """Return the SHA-256 digest of bytes as a hex string."""
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key, data):
    """Return the HMAC-SHA256 tag of data under key, as a hex string."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(key, data, tag_hex):
    """Check an HMAC tag in constant time (prevents timing attacks)."""
    if not isinstance(tag_hex, str):
        return False
    return hmac.compare_digest(hmac_sha256(key, data), tag_hex)
