"""
module2_crypto/secure_channel.py - The protected message format used in secure mode.

SecureChannel has the same four methods as core/channel.py's PlainChannel, so
devices and the cloud use it without any other code change.

Every published payload becomes an "envelope":

    {
      "hdr": {"from": "temp-01",   who sent it (must match the authenticated id)
              "dev":  "temp-01",   whose key protects it
              "seq":  17,          sequence number, always increasing   -> anti-replay
              "ts":   1763740000.1 send time, must be recent            -> anti-replay
              "kv":   1,           key version (changes after rotation)
              "nonce": "...."},    random 96-bit AES-GCM nonce
      "ct":  "....",               AES-256-GCM ciphertext + tag (header & topic as AAD)
      "mac": "...."                HMAC-SHA256 over header + topic + ciphertext
    }

The gateway checks "mac" (it has the mac key) WITHOUT being able to read the
data. Only the cloud and the device hold the "enc" key, so readings stay
secret even from the gateway (end-to-end confidentiality).

Whose key? A device always uses its own key. The cloud, when sending a
command to building/<loc>/<type>/<id>/cmd, uses the key of device <id>.
"""

import base64
import json
import threading
import time

from core.messages import make_frame
from module2_crypto import aes_gcm
from module2_crypto.challenge_response import compute_response
from module2_crypto.integrity import hmac_sha256, verify_hmac
from module2_crypto.keygen import derive_subkeys, new_nonce

HEADER_FIELDS = ("from", "dev", "seq", "ts", "kv", "nonce")


# ---------------------------------------------------------------------- shared helpers
def key_owner(sender_id, topic):
    """Return the device whose key protects a message (see module docstring)."""
    parts = topic.split("/")
    if topic.endswith("/cmd") and len(parts) == 5:
        return parts[3]
    return sender_id


def header_bytes(hdr, topic):
    """Canonical bytes of header + topic (used as AES-GCM AAD and inside the HMAC)."""
    return json.dumps({"hdr": hdr, "topic": topic}, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def mac_input(envelope, topic):
    """The bytes covered by the HMAC: header, topic and ciphertext."""
    return header_bytes(envelope["hdr"], topic) + b"|" + envelope["ct"].encode("ascii")


def is_envelope(data):
    """True if data has the shape of a secure envelope (fields present, right types)."""
    if not isinstance(data, dict):
        return False
    hdr = data.get("hdr")
    return (isinstance(hdr, dict) and all(field in hdr for field in HEADER_FIELDS)
            and isinstance(data.get("ct"), str) and isinstance(data.get("mac"), str)
            and isinstance(hdr["seq"], int) and isinstance(hdr["ts"], (int, float)))


def verify_envelope_mac(envelope, topic, mac_key):
    """Check the HMAC of an envelope (constant-time)."""
    return verify_hmac(mac_key, mac_input(envelope, topic), envelope["mac"])


class DeviceKeyring:
    """The key(s) stored inside ONE device. Acts as a key lookup function."""

    def __init__(self, device_id, version, key):
        """Install the device's first key (from provisioning)."""
        self.device_id = device_id
        self.current = version
        self.keys = {version: key}

    def install(self, version, key):
        """Install a new key version (after rotation or re-provisioning)."""
        self.keys[version] = key
        self.current = version

    def __call__(self, device_id, version=None):
        """Return (version, key) only for this device's own key."""
        if device_id != self.device_id:
            return None
        version = self.current if version is None else int(version)
        if version not in self.keys:
            return None
        return version, self.keys[version]


# ---------------------------------------------------------------------- the channel
class SecureChannel:
    """Encrypts, authenticates and numbers every message; answers challenges."""

    name = "secure"

    def __init__(self, client_id, key_lookup):
        """key_lookup(device_id, version=None) -> (version, master_key) or None."""
        self.client_id = client_id
        self.key_lookup = key_lookup
        self._seq = {}                     # key owner -> last sequence number sent
        self._lock = threading.Lock()
        self.dropped = 0                   # incoming messages that failed checks
        self.last_reason = ""

    def hello_fields(self, client_id):
        """The hello carries no secret - identity is proven by the challenge."""
        return {}

    def answer_challenge(self, client_id, challenge_frame):
        """Prove we hold our key by HMAC-ing the broker's random challenge."""
        found = self.key_lookup(client_id, None)
        if found is None:
            return None
        version, master_key = found
        auth_key = derive_subkeys(master_key)["auth"]
        response = compute_response(auth_key, client_id,
                                    str(challenge_frame.get("challenge", "")))
        return make_frame("response", client_id=client_id, response=response, kv=version)

    def wrap(self, client_id, topic, payload):
        """Turn a payload dictionary into an encrypted, MAC'd, numbered envelope."""
        owner = key_owner(client_id, topic)
        found = self.key_lookup(owner, None)
        if found is None:
            raise RuntimeError(f"{client_id} has no key for {owner}")
        version, master_key = found
        keys = derive_subkeys(master_key)
        with self._lock:
            seq = self._seq.get(owner, 0) + 1
            self._seq[owner] = seq
        nonce = new_nonce()
        hdr = {"from": client_id, "dev": owner, "seq": seq, "ts": round(time.time(), 3),
               "kv": version, "nonce": base64.b64encode(nonce).decode()}
        plaintext = json.dumps(payload, sort_keys=True).encode("utf-8")
        _, ciphertext = aes_gcm.encrypt(keys["enc"], plaintext,
                                        aad=header_bytes(hdr, topic), nonce=nonce)
        envelope = {"hdr": hdr, "ct": base64.b64encode(ciphertext).decode()}
        envelope["mac"] = hmac_sha256(keys["mac"], mac_input(envelope, topic))
        return envelope

    def unwrap(self, sender_id, topic, data):
        """Check and decrypt an envelope. Returns the payload dict, or None if anything is wrong."""
        if not is_envelope(data):
            return self._drop("not an envelope")
        hdr = data["hdr"]
        if hdr["from"] != sender_id:
            return self._drop("sender does not match header")
        found = self.key_lookup(hdr["dev"], hdr["kv"])
        if found is None:
            return self._drop("no valid key")
        keys = derive_subkeys(found[1])
        if not verify_envelope_mac(data, topic, keys["mac"]):
            return self._drop("HMAC mismatch")
        try:
            nonce = base64.b64decode(hdr["nonce"])
            ciphertext = base64.b64decode(data["ct"])
        except ValueError:
            return self._drop("bad base64")
        plaintext = aes_gcm.decrypt(keys["enc"], nonce, ciphertext, aad=header_bytes(hdr, topic))
        if plaintext is None:
            return self._drop("AES-GCM tag check failed")
        return json.loads(plaintext)

    def _drop(self, reason):
        """Count a rejected incoming message and remember why."""
        self.dropped += 1
        self.last_reason = reason
        return None
