"""
module1_attacks/sniffing.py - Passive eavesdropping (confidentiality attack).

Story: the attacker controls the network path of four devices (one of each
type) and silently records everything they send to the gateway.

Measured: of all captured 'publish' frames, how many reveal a sensor value
(temperature, power, door state, motion) in readable form.
Expected defence in secure mode: AES-GCM encryption of the payload.
"""

import time

from config import BROKER_PORT, MITM_PORT
from module1_attacks.common import make_result
from module1_attacks.mitm_proxy import MitmProxy

VICTIMS = ["temp-01", "energy-01", "motion-01", "lock-01"]
READINGS_PER_VICTIM = 5
# Field names that would leak private / sensitive building information.
SENSITIVE_KEYS = {"temperature_c", "power_w", "total_kwh", "state", "motion", "occupancy"}


def _leaked_fields(payload):
    """Return the sensitive field names an eavesdropper can read in a payload."""
    if not isinstance(payload, dict):
        return set()
    return SENSITIVE_KEYS.intersection(payload.keys())


def run(building):
    """Record the victims' traffic through the relay and count readable readings."""
    proxy = MitmProxy(MITM_PORT, BROKER_PORT).start()
    victims = [building.device(v) for v in VICTIMS]
    try:
        for device in victims:
            building.reroute(device, MITM_PORT)
        for _ in range(READINGS_PER_VICTIM):
            for device in victims:
                device.publish_reading()
            time.sleep(0.05)
        time.sleep(0.5)
    finally:
        for device in victims:
            building.reroute(device, BROKER_PORT)
        proxy.stop()

    captured = proxy.frames("up", "publish")
    readable = [frame for _, frame, _ in captured if _leaked_fields(frame.get("payload"))]
    if readable:
        example = readable[0]["payload"]
        shown = {k: example[k] for k in sorted(_leaked_fields(example))}
        evidence = f"captured {len(captured)} frames; readable example: {shown}"
        defence = ""
    else:
        sample = captured[0][2][:90].decode(errors="replace") if captured else "nothing"
        evidence = f"captured {len(captured)} frames; none readable. sample: {sample}..."
        defence = "payload unreadable on the wire (encrypted)"
    return make_result("sniffing", building.mode, len(captured), len(readable), defence, evidence)
