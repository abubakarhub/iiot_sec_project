"""
tests/test_crypto.py - Module 2: each primitive accepts good input and rejects tampered input.
"""

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from module2_crypto import aes_gcm, integrity                                  # noqa: E402
from module2_crypto.challenge_response import (compute_response, make_challenge,  # noqa: E402
                                               verify_response)
from module2_crypto.key_manager import KeyManager                             # noqa: E402
from module2_crypto.keygen import derive_subkeys, new_ecdsa_private_key, new_key  # noqa: E402
from module2_crypto.secure_channel import DeviceKeyring, SecureChannel        # noqa: E402
from module2_crypto.signatures import CommandSigner, CommandVerifier          # noqa: E402


class TestPrimitives(unittest.TestCase):
    """AES-GCM, HMAC, HKDF and challenge-response."""

    def test_aes_gcm_round_trip_and_tamper(self):
        """Decryption works, and one flipped bit makes it fail."""
        key = new_key()
        nonce, ct = aes_gcm.encrypt(key, b"22.5 C", aad=b"hdr")
        self.assertEqual(aes_gcm.decrypt(key, nonce, ct, aad=b"hdr"), b"22.5 C")
        bad = bytes([ct[0] ^ 1]) + ct[1:]
        self.assertIsNone(aes_gcm.decrypt(key, nonce, bad, aad=b"hdr"))
        self.assertIsNone(aes_gcm.decrypt(key, nonce, ct, aad=b"other"))

    def test_hmac(self):
        """A correct tag verifies; a tag for different data does not."""
        key = new_key()
        tag = integrity.hmac_sha256(key, b"message")
        self.assertTrue(integrity.verify_hmac(key, b"message", tag))
        self.assertFalse(integrity.verify_hmac(key, b"messagE", tag))
        self.assertEqual(len(integrity.sha256_hex(b"x")), 64)

    def test_subkeys_are_different(self):
        """HKDF gives three different sub-keys from one master key."""
        keys = derive_subkeys(new_key())
        self.assertEqual(len({keys["enc"], keys["mac"], keys["auth"]}), 3)

    def test_challenge_response(self):
        """The right key answers correctly; a wrong key or another device id fails."""
        key, challenge = new_key(), make_challenge()
        answer = compute_response(key, "temp-01", challenge)
        self.assertTrue(verify_response(key, "temp-01", challenge, answer))
        self.assertFalse(verify_response(new_key(), "temp-01", challenge, answer))
        self.assertFalse(verify_response(key, "temp-02", challenge, answer))


class TestSignatures(unittest.TestCase):
    """ECDSA-signed door commands."""

    def setUp(self):
        """Create a signer and a verifier sharing one key pair."""
        private = new_ecdsa_private_key()
        self.sign = CommandSigner(private)
        self.verify = CommandVerifier(private.public_key())

    def test_valid_then_replayed(self):
        """A fresh signed command is accepted once, then refused as a replay."""
        cmd = self.sign({"command": "unlock", "cmd_id": "abc", "ts": time.time()})
        self.assertTrue(self.verify(cmd))
        self.assertFalse(self.verify(cmd))
        self.assertIn("replay", self.verify.last_reason)

    def test_modified_and_unsigned(self):
        """Changing a signed field or removing the signature is refused."""
        cmd = self.sign({"command": "lock", "cmd_id": "x1", "ts": time.time()})
        cmd["command"] = "unlock"
        self.assertFalse(self.verify(cmd))
        self.assertFalse(self.verify({"command": "unlock", "cmd_id": "x2", "ts": time.time()}))


class TestSecureChannelAndKeys(unittest.TestCase):
    """Envelope format and key manager."""

    def test_envelope_round_trip_and_tamper(self):
        """The cloud can read a device's envelope; a modified one is dropped."""
        key = new_key()
        device = SecureChannel("temp-01", DeviceKeyring("temp-01", 1, key))
        cloud = SecureChannel("cloud", DeviceKeyring("temp-01", 1, key))
        topic = "building/floor1/temperature/temp-01"
        env = device.wrap("temp-01", topic, {"temperature_c": 21.0})
        self.assertNotIn("21.0", str(env))                      # not readable on the wire
        self.assertEqual(cloud.unwrap("temp-01", topic, env), {"temperature_c": 21.0})
        env["hdr"]["seq"] += 1                                  # tamper with the header
        self.assertIsNone(cloud.unwrap("temp-01", topic, env))

    def test_key_manager_rotate_revoke_and_storage(self):
        """Rotation keeps the old key during grace; revocation removes all; file is encrypted."""
        with tempfile.TemporaryDirectory() as folder:
            km = KeyManager(os.path.join(folder, "ks.enc"), new_key(), grace_seconds=60)
            v1, k1 = km.provision("temp-01")
            v2, _ = km.rotate("temp-01")
            self.assertEqual((v1, v2), (1, 2))
            self.assertEqual(km.lookup("temp-01", 1), (1, k1))   # still valid in grace period
            with open(km.store_path, encoding="utf-8") as handle:
                self.assertNotIn(k1.hex(), handle.read())
            km.revoke("temp-01")
            self.assertIsNone(km.lookup("temp-01"))
            self.assertTrue(km.is_revoked("temp-01"))


if __name__ == "__main__":
    unittest.main()
