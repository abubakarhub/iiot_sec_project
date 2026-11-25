"""
module1_attacks/unauthorised_command.py - Privilege escalation: open a door you may not open.

Story: a user with only a "viewer" account (allowed to look at readings,
NOT to control doors) tries four ways to unlock door lock-02:
    1. POST /api/command with their own viewer token
    2. POST /api/command with no token at all
    3. POST /api/command with a forged admin token (unsigned JWT, alg = "none")
    4. publish an unlock frame straight to the lock's command topic on the broker

Measured: how many of the four tries actually unlocked lock-02.
Expected defence in secure mode: JWT verification + role-based access control
at the API, topic ACL at the broker, and the lock's ECDSA signature check.
"""

import base64
import json
import time

import config
from core.channel import PlainChannel
from core.client import BrokerClient
from core.http_util import http_json
from module1_attacks.common import broker_reasons, make_result

TARGET_LOCK = "lock-02"
TARGET_TOPIC = "building/floor2/door_lock/lock-02/cmd"


def forged_admin_token():
    """Build an unsigned JWT that claims to be the admin (a classic 'alg: none' forgery)."""
    def b64(data):
        """base64url-encode a dictionary without padding, as JWTs do."""
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    header = {"alg": "none", "typ": "JWT"}
    claims = {"sub": "admin", "role": "admin", "exp": int(time.time()) + 3600}
    return f"{b64(header)}.{b64(claims)}."


def run(building):
    """Try four ways to unlock lock-02 as a viewer and count the ones that worked."""
    lock = building.device(TARGET_LOCK)
    rejections_before = len(building.broker.rejections)
    viewer = next(u for u in config.SEED_USERS if u[0] == "viewer1")
    _, login = http_json("POST", f"{building.api_url}/api/login",
                         {"username": viewer[0], "password": viewer[1]})
    command = {"device_id": TARGET_LOCK, "command": "unlock", "issued_by": viewer[0]}

    attempts = []                                    # list of (name, worked, reply)

    def try_api(name, token):
        """Call /api/command with a given token and record whether the door opened."""
        before = lock.unlock_count
        status, _ = http_json("POST", f"{building.api_url}/api/command", command, token=token)
        time.sleep(0.3)
        attempts.append((name, lock.unlock_count > before, f"HTTP {status}"))

    try_api("viewer token", login.get("token"))
    try_api("no token", None)
    try_api("forged admin JWT", forged_admin_token())

    # 4. Straight to the broker, bypassing the cloud entirely.
    before = lock.unlock_count
    rogue = BrokerClient("viewer1-laptop", channel=PlainChannel())
    hello_ok = rogue.connect(timeout=2.0)
    rogue.publish(TARGET_TOPIC, {"command": "unlock", "issued_by": viewer[0],
                                 "ts": round(time.time(), 3)})
    time.sleep(0.4)
    rogue.close()
    attempts.append(("direct broker publish", lock.unlock_count > before,
                     "hello " + ("accepted" if hello_ok else "refused")))

    building.bridge.send_command(TARGET_LOCK, "lock", issued_by="system")   # tidy up
    time.sleep(0.2)

    successes = sum(1 for _, worked, _ in attempts if worked)
    evidence = "; ".join(f"{name}: {'UNLOCKED' if worked else 'refused'} ({reply})"
                         for name, worked, reply in attempts)
    refused = [f"{name} -> {reply}" for name, worked, reply in attempts if not worked]
    defence = ""
    if refused:
        defence = "; ".join(refused)
        reasons = broker_reasons(building, rejections_before)
        if reasons:
            defence += f"; broker: {reasons}"
    return make_result("unauthorised_command", building.mode, len(attempts), successes,
                       defence, evidence)
