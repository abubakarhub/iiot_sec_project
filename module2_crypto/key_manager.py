"""
module2_crypto/key_manager.py - Key storage, rotation and revocation.

The KeyManager is the building's "key vault". It:
  * PROVISIONS a fresh random 256-bit key for every device (and the cloud),
  * STORES all keys in a file that is itself encrypted with AES-GCM under a
    master key (so stealing data/keystore.enc reveals nothing),
  * ROTATES a device key: a new version becomes current, the old version keeps
    working for a short grace period so in-flight messages are not lost,
  * REVOKES a device: its keys are wiped and it lands on the revocation list,
    so it can no longer authenticate or send valid messages,
  * holds the cloud's ECDSA signing key (stored PEM-encrypted).

Master key: taken from the environment variable SECURETEAM_MASTER_KEY (64 hex chars)
if set, otherwise generated once into data/master.key. In a real deployment the
master key would live in a TPM / HSM, not in a file.
"""

import base64
import json
import os
import threading
import time

from cryptography.hazmat.primitives import serialization

from module2_crypto import aes_gcm
from module2_crypto.keygen import new_ecdsa_private_key, new_key

DEFAULT_GRACE_SECONDS = 60


def load_or_create_master_key(path):
    """Return the 32-byte master key from SECURETEAM_MASTER_KEY or the key file (creating it)."""
    from_env = os.environ.get("SECURETEAM_MASTER_KEY")
    if from_env:
        return bytes.fromhex(from_env)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            return bytes.fromhex(handle.read().strip())
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = new_key()
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(key.hex())
    return key


class KeyManager:
    """Keeps every device key, with versions, rotation and a revocation list."""

    def __init__(self, store_path, master_key, grace_seconds=DEFAULT_GRACE_SECONDS):
        """Prepare an empty key vault that saves itself encrypted to store_path."""
        self.store_path = store_path
        self.master_key = master_key
        self.grace_seconds = grace_seconds
        self.devices = {}               # device_id -> key record (see provision())
        self.revocation_list = []       # history of revocations
        self._signing_pem = None
        self._signing_key = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ lifecycle
    def provision(self, device_id):
        """Give a device a brand-new key (also used to re-register a revoked device)."""
        with self._lock:
            old = self.devices.get(device_id)
            version = (old["current"] + 1) if old else 1
            key = new_key()
            self.devices[device_id] = {"current": version,
                                       "keys": {str(version): key.hex()},
                                       "retired": {},          # version -> expiry time
                                       "revoked": False,
                                       "created": time.time()}
            self.save()
            return version, key

    def rotate(self, device_id):
        """Make a new key version current; the old one stays valid for the grace period."""
        with self._lock:
            record = self._record(device_id)
            old_version = record["current"]
            new_version = old_version + 1
            key = new_key()
            record["keys"][str(new_version)] = key.hex()
            record["retired"][str(old_version)] = time.time() + self.grace_seconds
            record["current"] = new_version
            self.save()
            return new_version, key

    def revoke(self, device_id, reason="revoked by admin"):
        """Wipe a device's keys and put it on the revocation list."""
        with self._lock:
            record = self._record(device_id)
            record["keys"] = {}
            record["retired"] = {}
            record["revoked"] = True
            self.revocation_list.append({"device_id": device_id, "at": time.time(),
                                         "reason": reason})
            self.save()

    def is_revoked(self, device_id):
        """True if the device has been revoked (and not re-provisioned)."""
        record = self.devices.get(device_id)
        return bool(record and record["revoked"])

    # ------------------------------------------------------------------ lookup
    def lookup(self, device_id, version=None):
        """
        Return (version, key_bytes) for a device, or None if it is unknown,
        revoked, or the requested version has expired.
        version=None means "the current version".
        """
        with self._lock:
            record = self.devices.get(device_id)
            if record is None or record["revoked"]:
                return None
            if version is None:
                version = record["current"]
            version = str(version)
            if version not in record["keys"]:
                return None
            expiry = record["retired"].get(version)
            if expiry is not None and time.time() > expiry:
                del record["keys"][version]          # grace period over: wipe old key
                del record["retired"][version]
                return None
            return int(version), bytes.fromhex(record["keys"][version])

    def _record(self, device_id):
        """Return a device's key record or raise KeyError."""
        if device_id not in self.devices:
            raise KeyError(f"device {device_id} has no keys")
        return self.devices[device_id]

    # ------------------------------------------------------------------ signing key
    def signing_key(self):
        """Return the cloud's ECDSA private key, creating and storing it the first time."""
        with self._lock:
            if self._signing_key is None:
                self._signing_key = new_ecdsa_private_key()
                self._signing_pem = self._signing_key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.BestAvailableEncryption(self.master_key)).decode()
                self.save()
            return self._signing_key

    # ------------------------------------------------------------------ storage
    def save(self):
        """Write the whole vault to disk, encrypted with AES-GCM under the master key."""
        with self._lock:
            plain = json.dumps({"devices": self.devices,
                                "revocation_list": self.revocation_list,
                                "signing_key_pem": self._signing_pem}).encode()
            nonce, ciphertext = aes_gcm.encrypt(self.master_key, plain, aad=b"keystore")
            os.makedirs(os.path.dirname(self.store_path), exist_ok=True)
            with open(self.store_path, "w", encoding="utf-8") as handle:
                json.dump({"nonce": base64.b64encode(nonce).decode(),
                           "ct": base64.b64encode(ciphertext).decode()}, handle)

    def load(self):
        """Read and decrypt the vault from disk. Raises ValueError if it was tampered with."""
        with open(self.store_path, encoding="utf-8") as handle:
            blob = json.load(handle)
        plain = aes_gcm.decrypt(self.master_key, base64.b64decode(blob["nonce"]),
                                base64.b64decode(blob["ct"]), aad=b"keystore")
        if plain is None:
            raise ValueError("keystore failed its integrity check (wrong master key or tampered)")
        data = json.loads(plain)
        with self._lock:
            self.devices = data["devices"]
            self.revocation_list = data["revocation_list"]
            self._signing_pem = data["signing_key_pem"]
            self._signing_key = None
            if self._signing_pem:
                self._signing_key = serialization.load_pem_private_key(
                    self._signing_pem.encode(), password=self.master_key)

    def status(self):
        """Summary rows for printing / the dashboard (never includes key material)."""
        with self._lock:
            return [{"device_id": dev, "key_version": rec["current"],
                     "status": "revoked" if rec["revoked"] else "active"}
                    for dev, rec in sorted(self.devices.items())]
