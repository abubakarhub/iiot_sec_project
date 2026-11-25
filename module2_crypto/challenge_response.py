"""
module2_crypto/challenge_response.py - Device authentication without revealing the key.

    device  -> broker : hello, I am temp-01
    broker  -> device : challenge = 32 random bytes (new every time)
    device  -> broker : response  = HMAC-SHA256(auth_key, "temp-01|" + challenge)
    broker            : computes the same HMAC with its copy of the key and compares

The key itself never travels over the network, and because the challenge is
random and used only once, a recorded response is useless later.
"""

import secrets

from module2_crypto.integrity import hmac_sha256, verify_hmac


def make_challenge():
    """Create a fresh, unpredictable 256-bit challenge (hex string)."""
    return secrets.token_hex(32)


def _challenge_bytes(client_id, challenge):
    """The exact bytes that get HMAC'd: the id is included so a response can't be reused for another device."""
    return f"{client_id}|{challenge}".encode("utf-8")


def compute_response(auth_key, client_id, challenge):
    """Device side: prove knowledge of the key by HMAC-ing the challenge."""
    return hmac_sha256(auth_key, _challenge_bytes(client_id, challenge))


def verify_response(auth_key, client_id, challenge, response):
    """Broker side: check the device's answer in constant time."""
    if not challenge:
        return False
    return verify_hmac(auth_key, _challenge_bytes(client_id, challenge), response)
