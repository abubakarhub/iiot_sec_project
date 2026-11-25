"""
module4_cloud/field_crypto.py - Encrypted storage of sensitive database fields.

If someone copies the SQLite file (stolen backup, lost laptop), the sensitive
columns must be useless to them. We encrypt them with AES-256-GCM before they
are written and decrypt them only inside the cloud application:

  * users.email                     personal data of staff
  * readings of door locks / motion who was where, and when (see core/database.py)

Stored format:  "enc:v1:" + base64(nonce + ciphertext + tag)
The key is derived from the master key with HKDF, so it is never stored itself.
"""

import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from module2_crypto import aes_gcm
from module2_crypto.keygen import NONCE_BYTES

PREFIX = "enc:v1:"


def derive_field_key(master_key):
    """Derive a separate 256-bit key for database field encryption."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"secureTeam-SecureIoT-Sim/db-field-encryption").derive(master_key)


class FieldCipher:
    """Encrypts / decrypts single text values for the database."""

    def __init__(self, key):
        """Keep the 256-bit field key."""
        self.key = key

    def encrypt(self, text):
        """Encrypt a text value; returns 'enc:v1:...'. None stays None."""
        if text is None:
            return None
        nonce, ciphertext = aes_gcm.encrypt(self.key, text.encode("utf-8"), aad=b"db-field")
        return PREFIX + base64.b64encode(nonce + ciphertext).decode()

    def decrypt(self, value):
        """Decrypt a value written by encrypt(). Plain values are returned unchanged."""
        if not isinstance(value, str) or not value.startswith(PREFIX):
            return value
        blob = base64.b64decode(value[len(PREFIX):])
        plain = aes_gcm.decrypt(self.key, blob[:NONCE_BYTES], blob[NONCE_BYTES:], aad=b"db-field")
        if plain is None:
            raise ValueError("encrypted field failed its integrity check")
        return plain.decode("utf-8")
