"""
module4_cloud/demo.py - Shows Module 4 working inside the running secure building.

Printed by main.py --mode secure:
  1. JWT login: what the token contains, and that it is signed
  2. token checks: missing token, tampered token, wrong role
  3. input validation: malicious / out-of-range input and an oversized body
  4. encrypted storage: raw SQLite shows ciphertext, the API shows plaintext to admins
After the attacks, print_alert_summary() lists the alerts that were raised.
"""

import base64
import json
import sqlite3
from collections import Counter

import jwt

import config
from core.http_util import http_json


def _login(building, username):
    """Log in a seed user through the API and return the JWT."""
    password = next(u[1] for u in config.SEED_USERS if u[0] == username)
    _, body = http_json("POST", f"{building.api_url}/api/login",
                        {"username": username, "password": password})
    return body.get("token")


def _tamper_role(token, new_role):
    """Change the role inside a JWT's payload but keep the old signature."""
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["role"] = new_role
    new_payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{new_payload}.{signature}"


def show_jwt(building):
    """Print the parts and claims of a real token."""
    token = _login(building, "admin")
    claims = jwt.decode(token, options={"verify_signature": False})   # just to LOOK inside
    print(f"  admin JWT: {token[:40]}...  ({len(token)} chars, 3 parts: header.claims.signature)")
    print(f"  claims: sub={claims['sub']}, role={claims['role']}, valid for "
          f"{claims['exp'] - claims['iat']} s, jti={claims['jti']}  (HS256-signed)")
    return token


def show_token_checks(building):
    """Call protected endpoints with bad tokens and print the answers."""
    api = building.api_url
    viewer = _login(building, "viewer1")
    status_none, _ = http_json("GET", f"{api}/api/readings")
    status_fake, _ = http_json("GET", f"{api}/api/audit", token=_tamper_role(viewer, "admin"))
    status_role, body = http_json("GET", f"{api}/api/audit", token=viewer)
    print(f"  no token                       -> HTTP {status_none}")
    print(f"  viewer token edited to 'admin' -> HTTP {status_fake} (signature no longer matches)")
    print(f"  real viewer token on /api/audit -> HTTP {status_role} ({body.get('error')})")


def show_validation(building, admin_token):
    """Send malicious and out-of-range input."""
    api = building.api_url
    status, body = http_json("POST", f"{api}/api/command",
                             {"device_id": "lock-01'; DROP TABLE users;--", "command": "explode"},
                             token=admin_token)
    print(f"  command with SQL-injection id + bad command -> HTTP {status}: {body.get('details')}")
    status, body = http_json("GET", f"{api}/api/readings?limit=999999", token=admin_token)
    print(f"  readings?limit=999999                        -> HTTP {status}: {body.get('details')}")
    status, body = http_json("POST", f"{api}/api/login", {"username": "a" * 6000, "password": "x"})
    print(f"  6 KB login body                              -> HTTP {status}: {body.get('error')}")


def show_encrypted_storage(building, admin_token):
    """Compare what is inside the SQLite file with what the API returns."""
    conn = sqlite3.connect(building.db.path)
    raw_email = conn.execute("SELECT email FROM users WHERE username='operator1'").fetchone()[0]
    raw_lock = conn.execute("SELECT payload FROM readings WHERE device_id='lock-01' "
                            "ORDER BY id DESC LIMIT 1").fetchone()[0]
    raw_temp = conn.execute("SELECT payload FROM readings WHERE device_id='temp-01' "
                            "ORDER BY id DESC LIMIT 1").fetchone()[0]
    conn.close()
    _, users = http_json("GET", f"{building.api_url}/api/users", token=admin_token)
    api_email = next(u["email"] for u in users if u["username"] == "operator1")
    print(f"  in SQLite file: operator1 email = {raw_email[:38]}...")
    print(f"  in SQLite file: lock-01 reading = {raw_lock[:38]}...")
    print(f"  in SQLite file: temp-01 reading = {raw_temp[:60]}... (not sensitive, plain)")
    print(f"  through API as admin: operator1 email = {api_email}")


def run(building):
    """Run all Module 4 demonstrations against a running secure building."""
    admin_token = show_jwt(building)
    show_token_checks(building)
    show_validation(building, admin_token)
    show_encrypted_storage(building, admin_token)
    print(f"  dashboard: {building.api_url}/dashboard  (run with --serve to keep it open)")


def print_alert_summary(building):
    """Print how many audit entries and which alerts were produced (e.g. by the attacks)."""
    audit_rows = building.db.get_audit(100000)
    alerts = building.db.get_alerts(1000)
    events = Counter(row["event"] for row in audit_rows)
    print(f"  audit log: {len(audit_rows)} entries; most common events: "
          + ", ".join(f"{name} x{n}" for name, n in events.most_common(6)))
    print(f"  alerts raised: {len(alerts)}")
    for rule, count in Counter(a["rule"] for a in alerts).most_common():
        example = next(a["detail"] for a in alerts if a["rule"] == rule)
        print(f"    {count} x {rule:<42} e.g. {example[:70]}")
