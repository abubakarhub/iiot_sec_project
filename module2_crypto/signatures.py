"""
module2_crypto/signatures.py - ECDSA P-256 digital signatures for door commands.

The cloud holds a PRIVATE signing key; every door lock holds only the matching
PUBLIC key. The cloud signs each lock/unlock command, the lock verifies it.
  * Nobody without the private key can create a valid command  (authenticity)
  * The cloud cannot later deny having sent it                  (non-repudiation)
Each signed command also carries a unique cmd_id and a timestamp, and the lock
remembers cmd_ids it has already executed, so a copied command is useless.
"""

import base64
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

MAX_COMMAND_AGE = 30            # seconds a signed command stays valid


def canonical_bytes(data):
    """The exact bytes we sign: JSON with sorted keys and no spaces."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(private_key, data):
    """Sign bytes with ECDSA-SHA256. Returns the signature (DER bytes)."""
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify(public_key, data, signature):
    """Return True if signature is a valid ECDSA-SHA256 signature of data."""
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def public_key_pem(private_key):
    """Export the public half of a key pair as PEM text (safe to share)."""
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def load_public_key(pem_text):
    """Load a PEM public key."""
    return serialization.load_pem_public_key(pem_text.encode())


class CommandSigner:
    """Used by the cloud: adds an ECDSA signature to every outgoing command."""

    def __init__(self, private_key):
        """Keep the cloud's private signing key."""
        self.private_key = private_key

    def __call__(self, payload):
        """Return a copy of the command payload with a 'sig' field added."""
        unsigned = {k: v for k, v in payload.items() if k != "sig"}
        signature = sign(self.private_key, canonical_bytes(unsigned))
        unsigned["sig"] = base64.b64encode(signature).decode()
        return unsigned


class CommandVerifier:
    """Used by a door lock: accepts only fresh, never-seen, correctly signed commands."""

    def __init__(self, public_key):
        """Keep the cloud's public key and an empty list of used command ids."""
        self.public_key = public_key
        self.seen_ids = set()
        self.last_reason = ""

    def __call__(self, payload):
        """Return True if the command may be executed; otherwise set last_reason."""
        sig_b64 = payload.get("sig")
        if not isinstance(sig_b64, str):
            return self._fail("command is not signed")
        unsigned = {k: v for k, v in payload.items() if k != "sig"}
        try:
            signature = base64.b64decode(sig_b64)
        except ValueError:
            return self._fail("signature is not valid base64")
        if not verify(self.public_key, canonical_bytes(unsigned), signature):
            return self._fail("bad ECDSA signature")
        if abs(time.time() - float(unsigned.get("ts", 0))) > MAX_COMMAND_AGE:
            return self._fail("command too old")
        if unsigned.get("cmd_id") in self.seen_ids:
            return self._fail("command id already used (replay)")
        self.seen_ids.add(unsigned.get("cmd_id"))
        return True

    def _fail(self, reason):
        """Remember why a command was refused and return False."""
        self.last_reason = reason
        return False
