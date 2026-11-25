"""
module3_access/demo.py - Shows Module 3 working inside the running secure building.

Printed by main.py --mode secure:
  1. passwords are bcrypt-hashed and salted
  2. the password policy rejects weak passwords for NEW accounts
  3. a user is registered, logs in, is revoked, and is then refused
  4. the role / permission matrix (RBAC)
  5. topic ACL: a device cannot publish on another device's topic or subscribe to '#'
  6. privacy techniques + before/after graph + anonymised export
"""

import secrets
import time

import config
from core.http_util import http_json
from module3_access import privacy
from module3_access.passwords import hash_password, verify_password
from module3_access.rbac import ROLES, permission_matrix


def show_passwords(building):
    """Show the stored hash and that the same password gives different salted hashes."""
    stored = building.db.get_user("operator1")["password"]
    print(f"  operator1 stored as: {stored[:29]}...  (bcrypt, cost 12, salt inside)")
    start = time.perf_counter()
    first, second = hash_password("same-password!"), hash_password("same-password!")
    ms = (time.perf_counter() - start) / 2 * 1000
    print(f"  same password hashed twice -> different hashes: {first != second}; "
          f"both verify: {verify_password('same-password!', first) and verify_password('same-password!', second)}"
          f"; {ms:.0f} ms per hash")


def show_policy(building):
    """Try to create a new account with a weak password."""
    try:
        building.registry.register_user("new_tech", "sunshine1", "operator", "t@building.local")
        print("  weak password for new account: ACCEPTED")
    except ValueError as err:
        print(f"  weak password for new account -> refused: {err}")


def show_user_lifecycle(building):
    """Register a contractor, log in, revoke the account, log in again."""
    password = "Ct-" + secrets.token_urlsafe(12) + "9!"
    building.registry.register_user("contractor1", password, "operator", "c1@contractor.local")
    url = f"{building.api_url}/api/login"
    status_1, _ = http_json("POST", url, {"username": "contractor1", "password": password})
    building.registry.revoke_user("contractor1")
    status_2, body = http_json("POST", url, {"username": "contractor1", "password": password})
    print(f"  contractor1 registered -> login HTTP {status_1}; revoked -> login HTTP {status_2} "
          f"({body.get('error')})")


def show_rbac():
    """Print which role has which permission."""
    print(f"  {'permission':<16}" + "".join(f"{role:>10}" for role in ROLES))
    for permission, by_role in permission_matrix():
        print(f"  {permission:<16}" + "".join(f"{'yes' if by_role[r] else '-':>10}" for r in ROLES))


def show_topic_acl(building):
    """Let temp-01 try two things its ACL does not allow and show the broker's answer."""
    device = building.device("temp-01")
    before = len(building.broker.rejections)
    device.publish("building/floor2/temperature/temp-02",
                   {"device_id": "temp-01", "temperature_c": 5.0, "ts": time.time()})
    time.sleep(0.2)
    reasons = [r for _, r in building.broker.rejections[before:]]
    print(f"  temp-01 publishes on temp-02's topic -> {reasons[0] if reasons else 'ACCEPTED'}")
    allowed = device.subscribe("building/#")
    print(f"  temp-01 subscribes to 'building/#'  -> "
          f"{'ACCEPTED' if allowed else device.last_error}")


def show_privacy(building):
    """Run the four privacy techniques and print the before/after numbers."""
    s = privacy.run(config.RESULTS_DIR, db=building.db)
    print(f"  pseudonymisation : dictionary attack re-identifies {s['pseudonyms_reidentified_unkeyed']}"
          f"/{s['devices']} unkeyed SHA-256 ids vs {s['pseudonyms_reidentified_keyed']}"
          f"/{s['devices']} keyed HMAC pseudonyms")
    print(f"  aggregation      : {s['energy_points_before']} -> {s['energy_points_after']} points, "
          f"peak {s['energy_max_before']} -> {s['energy_max_after']} W, total "
          f"{s['energy_total_kwh_before']} = {s['energy_total_kwh_after']} kWh (kept)")
    print(f"  diff. privacy    : epsilon={privacy.EPSILON}, mean error {s['dp_mean_abs_error']} "
          f"people/room, total {s['dp_total_true']} -> {s['dp_total_noisy']}")
    print(f"  k-anonymity      : k {s['k_before']} -> {s['k_after']}, unique records "
          f"{s['unique_before']}/{s['records']} -> 0, {s['suppressed']} suppressed")
    print("  saved: privacy_before_after.png, analytics_export.csv (real readings, pseudonymised)")


def run(building):
    """Run all Module 3 demonstrations against a running secure building."""
    show_passwords(building)
    show_policy(building)
    show_user_lifecycle(building)
    show_rbac()
    show_topic_acl(building)
    show_privacy(building)
