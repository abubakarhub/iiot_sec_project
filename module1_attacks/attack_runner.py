"""
module1_attacks/attack_runner.py - Runs every attack against a running building.

    results = run_all(building)          # list of result dictionaries
    write_csv(results, "results/before.csv")
    print_table(results)

The SAME attack code runs against insecure and secure mode. Only the system
under attack changes, so any difference in the results comes from the defences.
"""

import csv
import logging
import os
import time

from module1_attacks import (brute_force, flooding, replay, sniffing, spoofing, tampering,
                             unauthorised_command)
from module1_attacks.common import make_result

log = logging.getLogger("attacks")

# (name, function) in the order they run.
ATTACKS = [
    ("sniffing", sniffing.run),
    ("tampering", tampering.run),
    ("replay", replay.run),
    ("spoofing", spoofing.run),
    ("brute_force", brute_force.run),
    ("flooding_broker", flooding.run_broker),
    ("flooding_api", flooding.run_api),
    ("unauthorised_command", unauthorised_command.run),
]

# Short descriptions shown next to the buttons on the live control panel.
ATTACK_DESCRIPTIONS = {
    "sniffing": "Listen to the traffic between devices and the gateway and read the readings.",
    "tampering": "Sit in the middle and change temperature values before they reach the cloud.",
    "replay": "Record a real 'unlock lock-01' command and send it again later.",
    "spoofing": "Pretend to be sensor temp-01 and push fake readings into the cloud.",
    "brute_force": "Guess operator1's password from a list of 99 common passwords.",
    "flooding_broker": "A hijacked energy meter sends 1000 messages as fast as it can.",
    "flooding_api": "10 threads fire 300 API requests with a viewer's login token.",
    "unauthorised_command": "A viewer (or no login, or a forged token) tries to unlock lock-02.",
}

CSV_COLUMNS =["attack", "mode", "attempts", "successes", "success_rate_pct", "outcome",
               "observed_defence", "evidence", "timestamp"]


def run_all(building):
    """Run every attack one after another and return the list of results."""
    results = []
    for name, attack in ATTACKS:
        log.info("running attack: %s", name)
        try:
            result = attack(building)
        except Exception as err:                  # one broken attack must not stop the rest
            log.exception("attack %s crashed", name)
            result = make_result(name, building.mode, 0, 0, "", f"attack crashed: {err}")
        results.append(result)
        log.info("  -> %s (%s%%)", result["outcome"], result["success_rate_pct"])
        time.sleep(0.3)                           # let the system settle between attacks
    return results


def write_csv(results, path):
    """Save results to a CSV file (creates the folder if needed)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(results)


def print_table(results):
    """Print a compact results table to the console."""
    print(f"  {'attack':<22} {'attempts':>8} {'success':>8} {'rate %':>7}  outcome")
    for r in results:
        print(f"  {r['attack']:<22} {r['attempts']:>8} {r['successes']:>8} "
              f"{r['success_rate_pct']:>7}  {r['outcome']}")
    print()
    for r in results:
        print(f"  [{r['attack']}] {r['evidence']}")
