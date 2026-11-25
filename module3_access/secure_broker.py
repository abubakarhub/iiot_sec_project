"""
module3_access/secure_broker.py - The fully secured gateway used in secure mode.

SecureBroker = Module 2's CryptoBroker + Module 3's access-control layers.
Order of checks for every published message (cheapest first):

    1. authenticated?             (challenge-response, Module 2)
    2. under the rate limit?      (token bucket per client)          -> stops flooding
    3. allowed on this topic?     (topic ACL)                        -> least privilege
    4. envelope valid?            (HMAC, timestamp, sequence; Module 2)

On hello it also checks the device registry: a device marked 'revoked' in
the database is refused even before the key check.

Every rejection is reported to an optional callback on_security_event
(client_id, reason) - Module 4 connects this to the audit log and alerts.
"""

import threading
import time

from config import HOST, BROKER_PORT
from module2_crypto.crypto_broker import CryptoBroker
from module3_access.rate_limit import RateLimiter
from module3_access.topic_acl import TopicACL

DEVICE_LIMIT = (20, 5.0)        # burst of 20 messages, then 5 per second
CLOUD_LIMIT = (200, 100.0)      # the cloud sends commands for the whole building
EVENT_INTERVAL = 1.0            # report the same (client, reason) at most once per second


class SecureBroker(CryptoBroker):
    """Gateway enforcing authentication, integrity, freshness, ACLs and rate limits."""

    def __init__(self, key_manager, db, acl=None, host=HOST, port=BROKER_PORT):
        """Add the device registry (db), topic ACL and rate limiter to the crypto broker."""
        super().__init__(key_manager, host, port)
        self.db = db
        self.acl = acl or TopicACL()
        self.limiter = RateLimiter(*DEVICE_LIMIT, overrides={"cloud": CLOUD_LIMIT})
        self.on_security_event = None          # set by Module 4: function(client_id, reason)
        self._last_event = {}
        self._event_lock = threading.Lock()

    # ------------------------------------------------------------------ registry
    def on_hello(self, session, frame):
        """Refuse devices that the registry marks as revoked, then do the crypto hello."""
        claimed = str(frame.get("client_id", ""))
        row = self.db.get_device(claimed)
        if row is not None and row["status"] != "active":
            self.reject(session, f"device '{claimed}' is {row['status']} in the registry",
                        ref="hello")
            return
        super().on_hello(session, frame)

    # ------------------------------------------------------------------ hooks
    def allow_subscribe(self, session, topic):
        """Authenticated AND allowed by the topic ACL."""
        allowed, reason = super().allow_subscribe(session, topic)
        if not allowed:
            return allowed, reason
        if not self.acl.can_subscribe(session.client_id, topic):
            return False, f"topic ACL: {session.client_id} may not subscribe to '{topic}'"
        return True, ""

    def allow_publish(self, session, frame):
        """Authentication -> rate limit -> topic ACL -> cryptographic envelope checks."""
        if not session.authenticated:
            return False, "not authenticated"
        if not self.limiter.allow(session.client_id):
            return False, "rate limit exceeded"
        topic = str(frame.get("topic", ""))
        if not self.acl.can_publish(session.client_id, topic):
            return False, f"topic ACL: {session.client_id} may not publish to '{topic}'"
        return self.check_envelope(session, topic, frame.get("payload"))

    # ------------------------------------------------------------------ reporting
    def reject(self, session, reason, ref=None):
        """Reject as usual, and report the event (at most once per second per reason)."""
        super().reject(session, reason, ref)
        callback = self.on_security_event
        if callback is None:
            return
        client = session.client_id or session.extra.get("last_claimed") or "unknown"
        key = (client, reason)
        now = time.time()
        with self._event_lock:
            if now - self._last_event.get(key, 0) < EVENT_INTERVAL:
                return
            self._last_event[key] = now
        callback(client, reason)
