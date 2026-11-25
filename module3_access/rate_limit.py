"""
module3_access/rate_limit.py - Token-bucket rate limiting.

Picture a bucket that holds at most `capacity` tokens and is refilled at
`rate` tokens per second. Every message (or HTTP request) costs one token.
  * normal traffic never empties the bucket,
  * short bursts are allowed (up to `capacity`),
  * a flood empties it and is then held to `rate` messages per second.

Used by the secure broker (per device) and the secure API (per user / IP).
"""

import threading
import time


class TokenBucket:
    """One bucket for one client."""

    def __init__(self, capacity, rate):
        """Start full: capacity tokens, refilled at rate tokens per second."""
        self.capacity = capacity
        self.rate = rate
        self.tokens = float(capacity)
        self.updated = time.monotonic()

    def allow(self):
        """Take one token if available. Returns True if the action is allowed."""
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class RateLimiter:
    """A separate token bucket for every client key (device id, username, IP...)."""

    def __init__(self, capacity, rate, overrides=None):
        """overrides: {key: (capacity, rate)} for clients that need other limits."""
        self.capacity = capacity
        self.rate = rate
        self.overrides = overrides or {}
        self._buckets = {}
        self._lock = threading.Lock()

    def allow(self, key):
        """True if this client may perform one more action right now."""
        with self._lock:
            if key not in self._buckets:
                capacity, rate = self.overrides.get(key, (self.capacity, self.rate))
                self._buckets[key] = TokenBucket(capacity, rate)
            return self._buckets[key].allow()
