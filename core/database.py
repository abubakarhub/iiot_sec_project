"""
core/database.py - The cloud's SQLite database.

Tables:
    devices    registered devices and whether they are active or revoked
    users      user accounts (insecure mode: plaintext password; secure: bcrypt hash)
    readings   every sensor reading the cloud received
    commands   every command the cloud sent to a device
    audit_log  security-relevant events (used by Module 4)
    alerts     suspicious events raised by alert rules (used by Module 4)

Each method opens its own short connection, so it is safe to call from the
broker / Flask threads at the same time.
"""

import json
import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id   TEXT PRIMARY KEY,
    device_type TEXT NOT NULL,
    location    TEXT NOT NULL,
    topic       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active'      -- 'active' or 'revoked'
);
CREATE TABLE IF NOT EXISTS users (
    username        TEXT PRIMARY KEY,
    password        TEXT NOT NULL,   -- INSECURE: plaintext.  SECURE: bcrypt hash
    role            TEXT NOT NULL,   -- admin / operator / viewer
    email           TEXT,            -- INSECURE: plaintext.  SECURE: AES-GCM encrypted
    active          INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS readings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT NOT NULL,
    topic       TEXT NOT NULL,
    payload     TEXT NOT NULL,       -- JSON text of the reading
    received_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS commands (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    command   TEXT NOT NULL,
    issued_by TEXT,
    sent_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       REAL NOT NULL,
    actor    TEXT,
    event    TEXT NOT NULL,
    detail   TEXT,
    severity TEXT NOT NULL DEFAULT 'info'
);
CREATE TABLE IF NOT EXISTS alerts (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     REAL NOT NULL,
    rule   TEXT NOT NULL,
    detail TEXT
);
"""

# Readings that reveal where people are (door activity, room occupancy).
SENSITIVE_READING_TYPES = {"door_lock", "motion"}


class Database:
    """Small helper around one SQLite file."""

    def __init__(self, path):
        """Remember where the database file lives."""
        self.path = path
        self._write_lock = threading.Lock()
        # Secure mode sets this to a module4_cloud FieldCipher. Readings of the
        # SENSITIVE_READING_TYPES are then stored encrypted and decrypted on read.
        self.field_cipher = None

    def _encode_payload(self, payload):
        """Turn a reading into the text stored in the DB (encrypted if sensitive)."""
        text = json.dumps(payload)
        if self.field_cipher and payload.get("device_type") in SENSITIVE_READING_TYPES:
            text = self.field_cipher.encrypt(text)
        return text

    def _decode_payload(self, text):
        """Turn stored text back into a reading dictionary (decrypting if needed)."""
        if self.field_cipher:
            try:
                text = self.field_cipher.decrypt(text)
            except ValueError:
                return {"error": "stored reading failed its integrity check"}
        return json.loads(text)

    # ------------------------------------------------------------------ basics
    def reset(self):
        """Delete any old database file and create fresh, empty tables."""
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(self.path + suffix):
                os.remove(self.path + suffix)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")   # lets readers and writers overlap
            conn.executescript(SCHEMA)

    def _connect(self):
        """Open a connection that returns rows as dictionaries-like objects."""
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return _ClosingConnection(conn)

    def execute(self, sql, params=()):
        """Run one INSERT/UPDATE/DELETE statement safely (parameterised)."""
        with self._write_lock, self._connect() as conn:
            conn.execute(sql, params)

    def query(self, sql, params=()):
        """Run a SELECT and return a list of dictionaries."""
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------ devices
    def add_device(self, device_id, device_type, location, topic, status="active"):
        """Register (or re-register) a device."""
        self.execute("INSERT OR REPLACE INTO devices VALUES (?, ?, ?, ?, ?)",
                     (device_id, device_type, location, topic, status))

    def set_device_status(self, device_id, status):
        """Mark a device as 'active' or 'revoked'."""
        self.execute("UPDATE devices SET status = ? WHERE device_id = ?", (status, device_id))

    def get_device(self, device_id):
        """Return one device row, or None if it is not registered."""
        rows = self.query("SELECT * FROM devices WHERE device_id = ?", (device_id,))
        return rows[0] if rows else None

    def list_devices(self):
        """Return all registered devices."""
        return self.query("SELECT * FROM devices ORDER BY device_id")

    # ------------------------------------------------------------------ users
    def add_user(self, username, password_field, role, email_field):
        """Store a user. The caller decides if the password is plaintext or a hash."""
        self.execute("INSERT OR REPLACE INTO users (username, password, role, email) "
                     "VALUES (?, ?, ?, ?)", (username, password_field, role, email_field))

    def get_user(self, username):
        """Return one user as a dictionary, or None if not found."""
        rows = self.query("SELECT * FROM users WHERE username = ?", (username,))
        return rows[0] if rows else None

    def set_login_state(self, username, failed_attempts, locked_until):
        """Update a user's failed-login counter and lockout time."""
        self.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
                     (failed_attempts, locked_until, username))

    def set_user_active(self, username, active):
        """Enable (True) or disable / revoke (False) a user account."""
        self.execute("UPDATE users SET active = ? WHERE username = ?",
                     (1 if active else 0, username))

    def list_users(self):
        """Return all users (including the stored password field!)."""
        return self.query("SELECT * FROM users ORDER BY username")

    # ------------------------------------------------------------------ readings
    def insert_reading(self, device_id, topic, payload):
        """Store one received reading (payload is a dictionary)."""
        self.execute("INSERT INTO readings (device_id, topic, payload, received_at) "
                     "VALUES (?, ?, ?, ?)",
                     (device_id, topic, self._encode_payload(payload), time.time()))

    def count_readings(self, device_id=None):
        """Count stored readings, optionally for just one device."""
        if device_id:
            rows = self.query("SELECT COUNT(*) AS n FROM readings WHERE device_id = ?",
                              (device_id,))
        else:
            rows = self.query("SELECT COUNT(*) AS n FROM readings")
        return rows[0]["n"]

    def get_readings(self, device_id=None, limit=50):
        """Return the newest readings (payload decoded back to a dictionary)."""
        if device_id:
            rows = self.query("SELECT * FROM readings WHERE device_id = ? "
                              "ORDER BY id DESC LIMIT ?", (device_id, limit))
        else:
            rows = self.query("SELECT * FROM readings ORDER BY id DESC LIMIT ?", (limit,))
        for row in rows:
            row["payload"] = self._decode_payload(row["payload"])
        return rows

    def last_reading_id(self):
        """Return the id of the newest reading (0 if there are none yet)."""
        return self.query("SELECT COALESCE(MAX(id), 0) AS n FROM readings")[0]["n"]

    def readings_after(self, last_id, device_id=None):
        """Return readings stored after a given id (oldest first), optionally for one device."""
        if device_id:
            rows = self.query("SELECT * FROM readings WHERE id > ? AND device_id = ? "
                              "ORDER BY id", (last_id, device_id))
        else:
            rows = self.query("SELECT * FROM readings WHERE id > ? ORDER BY id", (last_id,))
        for row in rows:
            row["payload"] = self._decode_payload(row["payload"])
        return rows

    def latest_per_device(self):
        """Return the most recent reading of every device."""
        rows = self.query("SELECT r.* FROM readings r JOIN (SELECT device_id, MAX(id) AS id "
                          "FROM readings GROUP BY device_id) last ON r.id = last.id "
                          "ORDER BY r.device_id")
        for row in rows:
            row["payload"] = self._decode_payload(row["payload"])
        return rows

    # ------------------------------------------------------------------ commands
    def insert_command(self, device_id, command, issued_by):
        """Record a command the cloud sent."""
        self.execute("INSERT INTO commands (device_id, command, issued_by, sent_at) "
                     "VALUES (?, ?, ?, ?)", (device_id, command, issued_by, time.time()))

    # ------------------------------------------------------------------ audit + alerts
    def add_audit(self, event, actor=None, detail="", severity="info"):
        """Write one line to the audit log."""
        self.execute("INSERT INTO audit_log (at, actor, event, detail, severity) "
                     "VALUES (?, ?, ?, ?, ?)", (time.time(), actor, event, detail, severity))

    def add_alert(self, rule, detail=""):
        """Record an alert raised by an alert rule."""
        self.execute("INSERT INTO alerts (at, rule, detail) VALUES (?, ?, ?)",
                     (time.time(), rule, detail))

    def get_audit(self, limit=100):
        """Return the newest audit log entries."""
        return self.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))

    def get_alerts(self, limit=100):
        """Return the newest alerts."""
        return self.query("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))


class _ClosingConnection:
    """'with' wrapper that commits on success and ALWAYS closes the connection."""

    def __init__(self, conn):
        """Wrap an open sqlite3 connection."""
        self.conn = conn

    def __enter__(self):
        """Give the raw connection to the 'with' block."""
        return self.conn

    def __exit__(self, exc_type, exc, tb):
        """Commit if no error happened, then close."""
        if exc_type is None:
            self.conn.commit()
        self.conn.close()
        return False
