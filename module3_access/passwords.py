"""
module3_access/passwords.py - Salted password hashing (bcrypt), policy and lockout.

bcrypt:
  * adds a random SALT to every password, so two users with the same password
    get completely different hashes (rainbow tables are useless),
  * is deliberately SLOW (cost factor 12 = 2^12 rounds), so a thief who steals
    the database can only test a few passwords per second per CPU core.

Lockout: after MAX_FAILED wrong passwords in a row the account is locked for
LOCKOUT_SECONDS. While locked, even the CORRECT password is refused. This is
what stops online brute force.
"""

import string
import time

import bcrypt

BCRYPT_ROUNDS = 12
MAX_FAILED = 5
LOCKOUT_SECONDS = 300
MIN_LENGTH = 12
BCRYPT_MAX_BYTES = 72                 # bcrypt only looks at the first 72 bytes
COMMON_PASSWORDS = {"password", "123456", "qwerty", "letmein", "sunshine1", "welcome",
                    "admin123", "iloveyou", "changeme", "password123"}


def hash_password(password):
    """Return a salted bcrypt hash (text) of a password."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(BCRYPT_ROUNDS)).decode()


def verify_password(password, stored_hash):
    """Check a password against a bcrypt hash. Never raises on bad input."""
    if not isinstance(password, str) or not isinstance(stored_hash, str):
        return False
    data = password.encode("utf-8")
    if len(data) > BCRYPT_MAX_BYTES:
        return False
    try:
        return bcrypt.checkpw(data, stored_hash.encode())
    except ValueError:                 # stored value is not a bcrypt hash
        return False


def policy_problems(password):
    """Return a list of reasons why a NEW password is too weak (empty list = OK)."""
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"at least {MIN_LENGTH} characters")
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        problems.append(f"at most {BCRYPT_MAX_BYTES} bytes")
    if not any(c.islower() for c in password):
        problems.append("a lowercase letter")
    if not any(c.isupper() for c in password):
        problems.append("an uppercase letter")
    if not any(c.isdigit() for c in password):
        problems.append("a digit")
    if not any(c in string.punctuation for c in password):
        problems.append("a symbol")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("not a common password")
    return problems


class LoginGuard:
    """Checks a login attempt with bcrypt and enforces the lockout rule."""

    def __init__(self, db):
        """Use the given database; pre-compute a dummy hash for unknown users."""
        self.db = db
        # Checking a dummy hash for unknown usernames makes the reply take the same
        # time as for real users, so attackers cannot discover valid usernames.
        self._dummy_hash = hash_password("dummy-password-for-timing")

    def check(self, username, password):
        """
        Return (user_row or None, http_status, message).
            200 ok | 401 wrong credentials | 403 account disabled | 423 account locked
        The 401 message is the same for unknown users and wrong passwords.
        """
        user = self.db.get_user(username) if isinstance(username, str) else None
        if user is None:
            verify_password(password if isinstance(password, str) else "", self._dummy_hash)
            return None, 401, "invalid username or password"
        if not user["active"]:
            return None, 403, "account disabled"
        now = time.time()
        if user["locked_until"] > now:
            return None, 423, "account locked after too many failed attempts"
        if not verify_password(password, user["password"]):
            failed = user["failed_attempts"] + 1
            locked_until = now + LOCKOUT_SECONDS if failed >= MAX_FAILED else 0
            self.db.set_login_state(user["username"], failed, locked_until)
            return None, 401, "invalid username or password"
        self.db.set_login_state(user["username"], 0, 0)
        return user, 200, "ok"
