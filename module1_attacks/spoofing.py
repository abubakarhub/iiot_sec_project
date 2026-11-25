"""
module1_attacks/spoofing.py - Pretend to be a real device (authentication attack).

Story: the attacker connects its own laptop to the gateway, claims to be
temperature sensor "temp-01", and publishes fake readings of 99.9 °C.
The attacker does not have temp-01's secret key. If the gateway sends a
challenge, the attacker answers with random bytes (a guess).
Even if the gateway refuses the hello, the attacker keeps sending publish
frames on the open socket to see if the broker checks them anyway.

Measured: how many fake readings the cloud stored as coming from temp-01.
Expected defence in secure mode: challenge-response device authentication.
"""

import secrets
import time

from config import BROKER_PORT, HOST
from core.channel import PlainChannel
from core.client import BrokerClient
from core.messages import make_frame
from module1_attacks.common import broker_reasons, make_result
from module1_attacks.safety import assert_local

VICTIM_ID = "temp-01"
VICTIM_TOPIC = "building/floor1/temperature/temp-01"
FAKE_VALUE = 99.9
FAKE_READINGS = 10


class GuessingChannel(PlainChannel):
    """Attacker's channel: no keys, so it answers any challenge with random bytes."""

    def answer_challenge(self, client_id, challenge_frame):
        """Reply to the broker's challenge with a random (wrong) answer."""
        return make_frame("response", client_id=client_id, response=secrets.token_hex(32))


def run(building):
    """Connect as 'temp-01' without its key and try to inject fake readings."""
    assert_local(HOST)
    last_id = building.db.last_reading_id()
    rejections_before = len(building.broker.rejections)

    attacker = BrokerClient(VICTIM_ID, channel=GuessingChannel(), host=HOST, port=BROKER_PORT)
    accepted_hello = attacker.connect(timeout=2.0)
    sent = 0
    for _ in range(FAKE_READINGS):
        fake = {"device_id": VICTIM_ID, "device_type": "temperature",
                "temperature_c": FAKE_VALUE, "ts": round(time.time(), 3)}
        attacker.publish(VICTIM_TOPIC, fake)      # tried even if hello was refused
        sent += 1
        time.sleep(0.03)
    time.sleep(0.6)
    attacker.close()

    stored = [r for r in building.db.readings_after(last_id, VICTIM_ID)
              if r["payload"].get("temperature_c") == FAKE_VALUE]
    evidence = (f"hello as {VICTIM_ID} {'ACCEPTED' if accepted_hello else 'REFUSED'}; "
                f"sent {sent} fake readings, cloud stored {len(stored)}")
    defence = "" if stored else (broker_reasons(building, rejections_before)
                                 or attacker.last_error or "fake readings dropped")
    return make_result("spoofing", building.mode, sent, len(stored), defence, evidence)
