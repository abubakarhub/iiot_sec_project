"""
api/run.py - Vercel serverless function: run ONE real attack against a fresh building.

    GET /api/run?mode=insecure|secure&attack=<name>

Vercel cannot keep a simulation running between requests, so every call does the
whole thing inside the function: start a fresh SmartBuilding (broker, 8 devices,
cloud) on 127.0.0.1 inside the function, run the real Module 1 attack against it,
collect the measured result, a sample of the gateway traffic and the alerts, then
shut everything down. It is the same code as `python main.py`, nothing is faked.
"""

import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("SECUREIOT_DATA_DIR", "/tmp/secureiot-data" if os.name != "nt" else os.path.join(ROOT, "data"))

from flask import Flask, jsonify, request                      # noqa: E402

from core.simulation import SmartBuilding                     # noqa: E402
from module1_attacks.attack_runner import ATTACK_DESCRIPTIONS, ATTACKS   # noqa: E402

app = Flask(__name__)
ATTACK_FUNCTIONS = dict(ATTACKS)
RUN_LOCK = threading.Lock()      # one building at a time per instance (fixed local ports)


@app.get("/api/run")
def run():
    """Build a fresh building in the given mode, run one attack, return what was measured."""
    mode = request.args.get("mode", "")
    attack = request.args.get("attack", "")
    if mode not in ("insecure", "secure") or attack not in ATTACK_FUNCTIONS:
        return jsonify({"error": "use ?mode=insecure|secure&attack=" + "|".join(ATTACK_FUNCTIONS)}), 400
    with RUN_LOCK:
        started = time.time()
        with SmartBuilding(mode) as building:
            online = building.start()
            building.run_rounds(2)
            result = ATTACK_FUNCTIONS[attack](building)
            with building.broker._lock:
                feed = list(building.broker.feed)[-8:]
                totals = dict(building.broker.totals)
            alerts = building.db.get_alerts(6) if mode == "secure" else []
    return jsonify({
        "mode": mode, "attack": attack, "description": ATTACK_DESCRIPTIONS.get(attack, ""),
        "devices_online": online, "seconds": round(time.time() - started, 1),
        "result": result, "gateway": totals, "feed": list(reversed(feed)), "alerts": alerts,
    })
