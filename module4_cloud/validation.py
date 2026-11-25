"""
module4_cloud/validation.py - Input validation for the secure API.

Rule: never trust the client. Every value is checked for TYPE, FORMAT and
RANGE before it is used, using allow-lists (only known-good values pass).
Each function returns (clean_data, errors). If errors is not empty the API
answers HTTP 400 and does nothing.
"""

import re

USERNAME = re.compile(r"^[a-z][a-z0-9_]{2,31}$")
DEVICE_ID = re.compile(r"^[a-z]+-\d{2}$")
EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,180}\.[A-Za-z]{2,10}$")
COMMANDS = {"lock", "unlock"}
ROLES = {"admin", "operator", "viewer"}
MAX_PASSWORD = 72
MAX_LIMIT = 200


def _object(data):
    """Return an error list unless data is a JSON object (dictionary)."""
    return [] if isinstance(data, dict) else ["body must be a JSON object"]


def validate_login(data):
    """username + password, both strings of sensible length."""
    errors = _object(data)
    if errors:
        return None, errors
    username, password = data.get("username"), data.get("password")
    if not isinstance(username, str) or not USERNAME.match(username):
        errors.append("username: 3-32 chars, lowercase letters, digits or _")
    if not isinstance(password, str) or not 1 <= len(password) <= MAX_PASSWORD:
        errors.append(f"password: string of 1-{MAX_PASSWORD} characters")
    return ({"username": username, "password": password} if not errors else None), errors


def validate_command(data, db):
    """device_id must be a registered, active door lock; command must be lock/unlock."""
    errors = _object(data)
    if errors:
        return None, errors
    device_id, command = data.get("device_id"), data.get("command")
    if not isinstance(device_id, str) or not DEVICE_ID.match(device_id):
        errors.append("device_id: format like 'lock-01'")
    else:
        device = db.get_device(device_id)
        if device is None:
            errors.append("device_id: unknown device")
        elif device["device_type"] != "door_lock":
            errors.append("device_id: only door locks accept commands")
        elif device["status"] != "active":
            errors.append("device_id: device is revoked")
    if command not in COMMANDS:
        errors.append(f"command: one of {sorted(COMMANDS)}")
    return ({"device_id": device_id, "command": command} if not errors else None), errors


def validate_readings_query(args):
    """Optional limit (1-200, default 20) and optional device_id filter."""
    errors = []
    raw_limit = args.get("limit", "20")
    limit = None
    if not raw_limit.isdigit() or not 1 <= int(raw_limit) <= MAX_LIMIT:
        errors.append(f"limit: whole number 1-{MAX_LIMIT}")
    else:
        limit = int(raw_limit)
    device_id = args.get("device_id")
    if device_id is not None and not DEVICE_ID.match(device_id):
        errors.append("device_id: format like 'temp-01'")
    return ({"limit": limit, "device_id": device_id} if not errors else None), errors


def validate_new_user(data):
    """username, password (policy is checked later by the registry), role, email."""
    errors = _object(data)
    if errors:
        return None, errors
    clean, errors = validate_login(data)
    role, email = data.get("role"), data.get("email")
    if role not in ROLES:
        errors.append(f"role: one of {sorted(ROLES)}")
    if not isinstance(email, str) or not EMAIL.match(email):
        errors.append("email: valid e-mail address")
    if errors:
        return None, errors
    clean.update({"role": role, "email": email})
    return clean, []
