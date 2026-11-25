"""
module1_attacks/common.py - Small helpers shared by all attacks.

Every attack returns a result dictionary built by make_result(). The columns
are the same as in results/before.csv and results/after.csv:

    attack            short name, e.g. "replay"
    mode              "insecure" or "secure"
    attempts          how many malicious actions were tried
    successes         how many of them achieved their goal
    success_rate_pct  successes / attempts * 100  (see each attack for details)
    outcome           SUCCEEDED (100%), BLOCKED (0%) or PARTIAL (in between);
                      ERROR if the attack could not run at all (0 attempts measured)
    observed_defence  what the system actually said / did when it refused
    evidence          short proof taken from the running system
"""

import time


def make_result(attack, mode, attempts, successes, observed_defence, evidence, rate=None):
    """Build one result row. rate overrides the default successes/attempts percentage."""
    if rate is None:
        rate = (successes / attempts * 100) if attempts else 0.0
    rate = round(rate, 1)
    if attempts == 0:
        outcome = "ERROR"               # nothing was measured, so it is NOT a defence
    elif rate >= 100:
        outcome = "SUCCEEDED"
    elif rate <= 0:
        outcome = "BLOCKED"
    else:
        outcome = "PARTIAL"
    return {
        "attack": attack,
        "mode": mode,
        "attempts": attempts,
        "successes": successes,
        "success_rate_pct": rate,
        "outcome": outcome,
        "observed_defence": observed_defence or "none - attack was not stopped",
        "evidence": evidence,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def wait_until_stable(read_value, timeout=15.0, quiet_time=0.6):
    """
    Wait until read_value() stops changing (e.g. the cloud finished storing a flood).

    Returns the final value. Stops after `timeout` seconds at the latest.
    """
    deadline = time.time() + timeout
    last = read_value()
    last_change = time.time()
    while time.time() < deadline:
        time.sleep(0.1)
        current = read_value()
        if current != last:
            last, last_change = current, time.time()
        elif time.time() - last_change >= quiet_time:
            break
    return last


def broker_reasons(building, since_index=0, limit=3):
    """Return the distinct reasons the broker gave for rejecting frames (newest list part)."""
    reasons = []
    for _client, reason in building.broker.rejections[since_index:]:
        if reason not in reasons:
            reasons.append(reason)
    return "; ".join(reasons[:limit])
