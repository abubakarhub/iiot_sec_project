"""
module4_cloud/audit.py - Audit log and alerts for suspicious events.

AUDIT LOG: every security-relevant event (logins, denied requests, commands,
rejected broker messages, key changes...) is written to the audit_log table
with time, actor, event name, detail and severity.

ALERTS: simple rules watch the event stream. A rule fires when an event
happens at least `threshold` times within `window` seconds for the same actor
(for example 5 failed logins for operator1 within 60 s). A fired rule writes an
alert, shown on the dashboard. The same rule + actor fires at most once every
COOLDOWN seconds, so an attack produces a few clear alerts, not thousands.
"""

import logging
import threading
import time
from collections import defaultdict, deque

log = logging.getLogger("audit")

COOLDOWN = 30

# event name -> (alert title, threshold, window seconds)
ALERT_RULES = {
    "login_failed":         ("Possible password brute force", 5, 60),
    "account_locked":       ("Account locked after failed logins", 1, 60),
    "invalid_token":        ("Invalid or forged access token", 1, 60),
    "permission_denied":    ("Privilege escalation attempt (RBAC)", 1, 60),
    "rate_limited":         ("API flood - client rate limited", 10, 10),
    "broker_rate_limited":  ("Device flooding the gateway", 1, 10),
    "device_auth_failed":   ("Device authentication failed (spoofing?)", 1, 60),
    "replay_detected":      ("Replayed message detected", 1, 60),
    "tamper_detected":      ("Modified message detected (tampering)", 1, 60),
    "acl_denied":           ("Topic ACL violation", 1, 60),
}

# words in a broker rejection reason -> (event name, severity)
BROKER_REASONS = [
    ("rate limit", "broker_rate_limited", "warning"),
    ("challenge-response failed", "device_auth_failed", "critical"),
    ("unknown or revoked device", "device_auth_failed", "warning"),
    ("in the registry", "device_auth_failed", "warning"),
    ("not authenticated", "device_auth_failed", "warning"),
    ("replayed message", "replay_detected", "critical"),
    ("stale timestamp", "replay_detected", "critical"),
    ("HMAC check failed", "tamper_detected", "critical"),
    ("topic ACL", "acl_denied", "warning"),
]


class AuditLog:
    """Writes audit entries and raises alerts when a rule's threshold is reached."""

    def __init__(self, db):
        """Use the given database; start with empty event histories."""
        self.db = db
        self._history = defaultdict(deque)       # (event, actor) -> recent timestamps
        self._last_alert = {}                    # (event, actor) -> time of last alert
        self._lock = threading.Lock()

    def record(self, event, actor, detail="", severity="info"):
        """Write one audit entry, then check whether it should raise an alert."""
        self.db.add_audit(event, actor, detail, severity)
        rule = ALERT_RULES.get(event)
        if rule is None:
            return
        title, threshold, window = rule
        now = time.time()
        key = (event, actor)
        with self._lock:
            history = self._history[key]
            history.append(now)
            while history and now - history[0] > window:
                history.popleft()
            if len(history) < threshold or now - self._last_alert.get(key, 0) < COOLDOWN:
                return
            self._last_alert[key] = now
            count = len(history)
        self.db.add_alert(title, f"{actor}: {detail} ({count} event(s) in {window}s)")
        log.warning("ALERT %s - %s: %s", title, actor, detail)

    def on_broker_event(self, client_id, reason):
        """Callback for SecureBroker: turn a rejection reason into an audit event."""
        for words, event, severity in BROKER_REASONS:
            if words in reason:
                self.record(event, client_id, reason, severity)
                return
        self.record("broker_rejected", client_id, reason, "warning")
