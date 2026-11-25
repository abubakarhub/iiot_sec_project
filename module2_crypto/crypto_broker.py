"""
module2_crypto/crypto_broker.py - Broker with the cryptographic defences switched on.

CryptoBroker extends core.broker.InsecureBroker and overrides its hooks:

  on_hello      -> unknown / revoked device? refuse. Otherwise send a random challenge.
  on_response   -> check the HMAC answer to the challenge (challenge-response auth).
  allow_publish -> only authenticated clients, and every payload must be a valid
                   secure envelope:
                       * header 'from' = the authenticated id   (no impersonation)
                       * HMAC-SHA256 correct                     (no tampering)
                       * timestamp within 30 s                   (no old replays)
                       * sequence number higher than last time   (no recent replays)

Access-control rules (registry, topic ACL, rate limits) are added on top of this
class by module3_access/secure_broker.py.
"""

import logging
import threading
import time

from config import HOST, BROKER_PORT
from core.broker import InsecureBroker
from core.messages import make_frame
from module2_crypto.challenge_response import make_challenge, verify_response
from module2_crypto.keygen import derive_subkeys
from module2_crypto.secure_channel import is_envelope, key_owner, verify_envelope_mac

log = logging.getLogger("broker")

MAX_CLOCK_SKEW = 30          # seconds; older messages are treated as replays
CLOUD_ID = "cloud"           # the only client allowed to use another device's key


class CryptoBroker(InsecureBroker):
    """Broker enforcing challenge-response authentication, integrity and freshness."""

    def __init__(self, key_manager, host=HOST, port=BROKER_PORT):
        """Keep a reference to the key manager and an empty anti-replay table."""
        super().__init__(host, port)
        self.keys = key_manager
        self.last_seq = {}                       # (from, dev) -> highest sequence number seen
        self._seq_lock = threading.Lock()

    # ------------------------------------------------------------------ authentication
    def on_hello(self, session, frame):
        """Step 1: refuse unknown/revoked ids, otherwise send a one-time random challenge."""
        claimed = str(frame.get("client_id", ""))
        session.extra["last_claimed"] = claimed          # remembered for logging
        if self.keys.lookup(claimed) is None:
            self.reject(session, f"unknown or revoked device '{claimed}'", ref="hello")
            return
        session.extra["claimed_id"] = claimed
        session.extra["challenge"] = make_challenge()
        session.send(make_frame("challenge", challenge=session.extra["challenge"]))

    def on_other(self, session, frame):
        """Handle the 'response' frame; anything else is unknown."""
        if frame.get("type") == "response":
            self.on_response(session, frame)
        else:
            super().on_other(session, frame)

    def on_response(self, session, frame):
        """Step 2: verify the HMAC answer. The challenge is deleted so it can't be reused."""
        claimed = session.extra.pop("claimed_id", None)
        challenge = session.extra.pop("challenge", None)
        if claimed is None or frame.get("client_id") != claimed:
            self.reject(session, "unexpected challenge response", ref="hello")
            return
        found = self.keys.lookup(claimed, frame.get("kv"))
        if found is None or not verify_response(derive_subkeys(found[1])["auth"], claimed,
                                                challenge, frame.get("response")):
            self.reject(session, "challenge-response failed (wrong key)", ref="hello")
            return
        session.client_id = claimed
        session.authenticated = True
        session.send(make_frame("ack", ref="hello"))
        log.debug("%s authenticated (key v%s)", claimed, found[0])

    # ------------------------------------------------------------------ hooks
    def allow_subscribe(self, session, topic):
        """Only authenticated clients may subscribe."""
        if not session.authenticated:
            return False, "not authenticated"
        return True, ""

    def allow_publish(self, session, frame):
        """Only authenticated clients, and only valid, fresh, untampered envelopes."""
        if not session.authenticated:
            return False, "not authenticated"
        return self.check_envelope(session, str(frame.get("topic", "")), frame.get("payload"))

    def sender_name(self, session):
        """Messages are labelled with the PROVEN identity of the sender."""
        return session.client_id if session.authenticated else "unauthenticated"

    # ------------------------------------------------------------------ envelope checks
    def check_envelope(self, session, topic, envelope):
        """Run every cryptographic check on a published envelope. Returns (ok, reason)."""
        if not is_envelope(envelope):
            return False, "payload is not a secure envelope"
        hdr = envelope["hdr"]
        if hdr["from"] != session.client_id:
            return False, "header 'from' does not match authenticated id"
        if hdr["dev"] != session.client_id and session.client_id != CLOUD_ID:
            return False, "device may not use another device's key"
        if key_owner(hdr["from"], topic) != hdr["dev"]:
            return False, "key does not belong to this topic"
        found = self.keys.lookup(hdr["dev"], hdr["kv"])
        if found is None:
            return False, "key revoked or expired"
        if not verify_envelope_mac(envelope, topic, derive_subkeys(found[1])["mac"]):
            return False, "HMAC check failed (message modified)"
        if abs(time.time() - float(hdr["ts"])) > MAX_CLOCK_SKEW:
            return False, "stale timestamp (possible replay)"
        with self._seq_lock:
            key = (hdr["from"], hdr["dev"])
            if hdr["seq"] <= self.last_seq.get(key, 0):
                return False, "replayed message (old sequence number)"
            self.last_seq[key] = hdr["seq"]
        return True, ""

    # ------------------------------------------------------------------ revocation support
    def kick(self, client_id):
        """Disconnect every session of a client (used right after revoking it)."""
        with self._lock:
            victims = [s for s in self.sessions if s.client_id == client_id]
        for session in victims:
            session.close()
        return len(victims)
