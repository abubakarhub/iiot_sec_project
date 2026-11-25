"""
module2_crypto/aes_gcm.py - AES-256-GCM authenticated encryption.

AES-GCM gives two things at once:
  * confidentiality - the ciphertext reveals nothing about the plaintext
  * integrity       - a 16-byte authentication tag; if even one bit of the
                      ciphertext, nonce or AAD is changed, decryption FAILS

AAD ("additional authenticated data") is data that is NOT encrypted but IS
protected against changes - we use it for the message header and topic.
"""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from module2_crypto.keygen import new_nonce

TAG_BYTES = 16


def encrypt(key, plaintext, aad=b"", nonce=None):
    """Encrypt bytes. Returns (nonce, ciphertext_with_tag)."""
    nonce = nonce or new_nonce()
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key, nonce, ciphertext, aad=b""):
    """Decrypt and verify. Returns plaintext bytes, or None if anything was tampered with."""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        return None
