"""
config.py - Central settings for secureTeam_SecureIoT-Sim.

Every other file imports its ports, paths and device list from here,
so there is only ONE place to change them.

SAFETY: every network address in this project is 127.0.0.1 (this laptop).
Nothing ever talks to a real network, website or device.
"""

import os

# ---------------------------------------------------------------------------
# Network (localhost only)
# ---------------------------------------------------------------------------
HOST = "127.0.0.1"          # loopback address - traffic never leaves the laptop
BROKER_PORT = 18830         # gateway / pub-sub broker (TCP)
MITM_PORT = 18840           # attacker's local relay (used in Module 1 attacks)
CLOUD_PORT = 5000           # cloud REST API + dashboard (Flask)
PANEL_PORT = 5050           # simulation control panel (live view + attack launcher)

# ---------------------------------------------------------------------------
# Folders
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Runtime files, recreated each run. SECUREIOT_DATA_DIR overrides it (Vercel: /tmp).
DATA_DIR = os.environ.get("SECUREIOT_DATA_DIR") or os.path.join(BASE_DIR, "data")
RESULTS_DIR = os.path.join(BASE_DIR, "results")   # CSVs and graphs we hand in
DOCS_DIR = os.path.join(BASE_DIR, "docs")


def db_path(mode):
    """Return the SQLite database file used by the cloud in the given mode."""
    return os.path.join(DATA_DIR, f"cloud_{mode}.db")


# ---------------------------------------------------------------------------
# Smart Building: 4 device types, 8 devices
# Each entry: (device_id, device_type, location)
# The MQTT-style topic is built from these: building/<location>/<type>/<id>
# ---------------------------------------------------------------------------
DEVICES = [
    ("temp-01",   "temperature", "floor1"),
    ("temp-02",   "temperature", "floor2"),
    ("lock-01",   "door_lock",   "floor1"),
    ("lock-02",   "door_lock",   "floor2"),
    ("energy-01", "energy",      "floor1"),
    ("energy-02", "energy",      "floor2"),
    ("motion-01", "motion",      "floor1"),
    ("motion-02", "motion",      "floor2"),
]


def device_topic(device_id, device_type, location):
    """Build the topic a device publishes its readings on."""
    return f"building/{location}/{device_type}/{device_id}"


def command_topic(device_id, device_type, location):
    """Build the topic a device listens on for commands (used by door locks)."""
    return device_topic(device_id, device_type, location) + "/cmd"


# ---------------------------------------------------------------------------
# Seed user accounts (TEST VALUES ONLY - made up for this simulation).
# operator1 deliberately has a WEAK password that appears in the attacker's
# wordlist, so the brute-force attack has something to find. The SAME
# password is used in secure mode, so if brute force fails there it is
# because of the real defences (lockout / rate limit), not a changed password.
# ---------------------------------------------------------------------------
SEED_USERS = [
    # (username,   password,            role,       email)
    ("admin",     "Adm1n!Building#2026", "admin",    "admin@building.local"),
    ("operator1", "sunshine1",           "operator", "operator1@building.local"),
    ("viewer1",   "viewer-Pass-77",      "viewer",   "viewer1@building.local"),
]

# ---------------------------------------------------------------------------
# Simulation settings
# ---------------------------------------------------------------------------
SIM_ROUNDS = 5              # how many times each sensor publishes in a normal run
LIVE_INTERVAL = 2.0         # seconds between readings while the live simulation runs
RANDOM_SEED = 42            # fixed seed so sensor values are repeatable
