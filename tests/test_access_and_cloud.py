"""
tests/test_access_and_cloud.py - Modules 3 and 4: passwords, RBAC, ACL, rate limit,
privacy, validation, field encryption. Uses a temporary SQLite database.
"""

import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import Database                                       # noqa: E402
from module2_crypto.keygen import new_key                                # noqa: E402
from module3_access import privacy                                       # noqa: E402
from module3_access.passwords import (MAX_FAILED, LoginGuard, hash_password,  # noqa: E402
                                      policy_problems, verify_password)
from module3_access.rate_limit import RateLimiter                        # noqa: E402
from module3_access.rbac import SEND_COMMAND, VIEW_AUDIT, has_permission  # noqa: E402
from module3_access.topic_acl import TopicACL                            # noqa: E402
from module4_cloud import validation                                     # noqa: E402
from module4_cloud.field_crypto import FieldCipher                       # noqa: E402


class TestPasswords(unittest.TestCase):
    """bcrypt, policy and lockout."""

    def setUp(self):
        """Create a temporary database with one user."""
        self.folder = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self.folder.name, "t.db"))
        self.db.reset()
        self.db.add_user("op", hash_password("Right-Pass-123"), "operator", "op@x.local")
        self.guard = LoginGuard(self.db)

    def tearDown(self):
        """Delete the temporary database."""
        self.folder.cleanup()

    def test_hash_is_salted(self):
        """Same password -> different hashes, both verify."""
        a, b = hash_password("same"), hash_password("same")
        self.assertNotEqual(a, b)
        self.assertTrue(verify_password("same", a) and verify_password("same", b))
        self.assertFalse(verify_password("x" * 100, a))         # over 72 bytes: no crash

    def test_policy(self):
        """Weak passwords get reasons; a strong one gets none."""
        self.assertTrue(policy_problems("sunshine1"))
        self.assertEqual(policy_problems("Str0ng-Enough!"), [])

    def test_lockout_blocks_even_correct_password(self):
        """After MAX_FAILED wrong passwords the right one is refused with 423."""
        for _ in range(MAX_FAILED):
            self.assertEqual(self.guard.check("op", "wrong")[1], 401)
        self.assertEqual(self.guard.check("op", "Right-Pass-123")[1], 423)

    def test_unknown_user_same_message(self):
        """Unknown user and wrong password give the same 401 message."""
        self.assertEqual(self.guard.check("ghost", "x")[1:], self.guard.check("op", "x")[1:])


class TestAccessControl(unittest.TestCase):
    """RBAC, topic ACL and rate limiting."""

    def test_rbac(self):
        """Viewer cannot command; operator can; only admin sees the audit log."""
        self.assertFalse(has_permission("viewer", SEND_COMMAND))
        self.assertTrue(has_permission("operator", SEND_COMMAND))
        self.assertFalse(has_permission("operator", VIEW_AUDIT))
        self.assertTrue(has_permission("admin", VIEW_AUDIT))
        self.assertFalse(has_permission("hacker", SEND_COMMAND))

    def test_topic_acl(self):
        """A device publishes only on its own topic and cannot subscribe to '#'."""
        acl = TopicACL()
        self.assertTrue(acl.can_publish("temp-01", "building/floor1/temperature/temp-01"))
        self.assertFalse(acl.can_publish("temp-01", "building/floor2/temperature/temp-02"))
        self.assertFalse(acl.can_subscribe("temp-01", "building/#"))
        self.assertTrue(acl.can_subscribe("cloud", "building/#"))
        self.assertTrue(acl.can_publish("cloud", "building/floor1/door_lock/lock-01/cmd"))
        self.assertFalse(acl.can_publish("stranger", "building/floor1/temperature/temp-01"))

    def test_rate_limiter(self):
        """A burst beyond capacity is refused; other clients are unaffected."""
        limiter = RateLimiter(capacity=5, rate=0.001)
        results = [limiter.allow("flooder") for _ in range(20)]
        self.assertEqual(sum(results), 5)
        self.assertTrue(limiter.allow("honest"))


class TestPrivacy(unittest.TestCase):
    """The four privacy techniques."""

    def test_pseudonym_keyed(self):
        """Same id + key -> same pseudonym; a dictionary attack finds nothing."""
        key = new_key()
        p = privacy.pseudonym("temp-01", key)
        self.assertEqual(p, privacy.pseudonym("temp-01", key))
        self.assertEqual(privacy.dictionary_attack([p], ["temp-01"]), 0)

    def test_aggregation_keeps_total(self):
        """Averaging windows keeps the overall mean."""
        values = [1, 2, 3, 4, 5, 6, 7, 8]
        self.assertEqual(privacy.aggregate(values, 4), [2.5, 6.5])

    def test_k_anonymity(self):
        """After anonymisation every group has at least K records."""
        kept, _ = privacy.k_anonymise(privacy.synthetic_access_log(), k=3)
        self.assertGreaterEqual(privacy.smallest_group(kept), 3)
        self.assertNotIn("name", kept[0])

    def test_dp_noise_is_unbiased_on_average(self):
        """Laplace noise averages out close to zero over many samples."""
        rng = random.Random(1)
        samples = [privacy.laplace_noise(2.0, rng) for _ in range(20000)]
        self.assertLess(abs(sum(samples) / len(samples)), 0.1)


class TestCloudHelpers(unittest.TestCase):
    """Input validation and encrypted fields."""

    def test_validation(self):
        """Bad input is rejected with reasons; good input passes."""
        self.assertTrue(validation.validate_login({"username": "x'; DROP", "password": "p"})[1])
        self.assertFalse(validation.validate_login({"username": "admin", "password": "p"})[1])
        self.assertTrue(validation.validate_readings_query({"limit": "999999"})[1])
        self.assertTrue(validation.validate_readings_query({"limit": "-1"})[1])
        self.assertEqual(validation.validate_readings_query({"limit": "5"})[0]["limit"], 5)

    def test_field_cipher(self):
        """Encrypted text hides the value and decrypts back; tampering is detected."""
        cipher = FieldCipher(new_key())
        token = cipher.encrypt("a@b.local")
        self.assertTrue(token.startswith("enc:v1:"))
        self.assertNotIn("a@b", token)
        self.assertEqual(cipher.decrypt(token), "a@b.local")
        tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
        with self.assertRaises(ValueError):
            cipher.decrypt(tampered)


if __name__ == "__main__":
    unittest.main()
