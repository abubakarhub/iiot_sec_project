"""
module3_access/registry.py - Registration and revocation of users and devices.

Users:   register (role check, password policy, bcrypt hash) / revoke (disable login)
Devices: register (database entry + fresh key from Module 2) / revoke (keys wiped,
         status 'revoked', so the gateway refuses it)
"""

import re

from config import device_topic
from module3_access.passwords import hash_password, policy_problems
from module3_access.rbac import ROLES

USERNAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,31}$")


class Registry:
    """The single place where users and devices are added and removed."""

    def __init__(self, db, key_manager=None, encrypt_field=None):
        """
        db: core.database.Database; key_manager: module2 KeyManager (for devices);
        encrypt_field: optional function(text) -> text used to encrypt e-mails
        (added by Module 4; None stores them as given).
        """
        self.db = db
        self.key_manager = key_manager
        self.encrypt_field = encrypt_field

    # ------------------------------------------------------------------ users
    def register_user(self, username, password, role, email, enforce_policy=True):
        """Create a user with a bcrypt hash. Raises ValueError if any input is invalid."""
        if not isinstance(username, str) or not USERNAME_PATTERN.match(username):
            raise ValueError("username must be 3-32 chars: lowercase letters, digits, _")
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        if enforce_policy:
            problems = policy_problems(password)
            if problems:
                raise ValueError("weak password - needs " + ", ".join(problems))
        stored_email = self.encrypt_field(email) if self.encrypt_field else email
        self.db.add_user(username, hash_password(password), role, stored_email)
        self.db.add_audit("user_registered", "admin", f"{username} ({role})")

    def revoke_user(self, username):
        """Disable a user account; future logins are refused with HTTP 403."""
        self.db.set_user_active(username, False)
        self.db.add_audit("user_revoked", "admin", username, "warning")

    # ------------------------------------------------------------------ devices
    def register_device(self, device_id, device_type, location):
        """Add (or re-add) a device and give it a fresh key. Returns (key_version, key)."""
        self.db.add_device(device_id, device_type, location,
                           device_topic(device_id, device_type, location), "active")
        version, key = self.key_manager.provision(device_id)
        self.db.add_audit("device_registered", "admin", f"{device_id} -> key v{version}")
        return version, key

    def revoke_device(self, device_id, reason="revoked by admin"):
        """Wipe a device's keys and mark it revoked."""
        self.key_manager.revoke(device_id, reason)
        self.db.set_device_status(device_id, "revoked")
        self.db.add_audit("device_revoked", "admin", f"{device_id}: {reason}", "warning")

    def rotate_device_key(self, device_id):
        """Give a device a new key version. Returns (key_version, key)."""
        version, key = self.key_manager.rotate(device_id)
        self.db.add_audit("key_rotated", "admin", f"{device_id} -> key v{version}")
        return version, key
