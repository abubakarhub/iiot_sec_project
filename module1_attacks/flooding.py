"""
module1_attacks/flooding.py - Denial-of-service by flooding (availability attack).

Two variants, reported as two separate rows:

1. flooding_broker - Story: malware has taken over energy meter energy-02
   (like the Mirai botnet did to real IoT devices) and makes it publish as
   fast as it can. While the flood runs, honest sensor temp-02 keeps sending
   normal readings so we can see if real traffic still gets through.
   Measured: share of flood messages the gateway accepted and the cloud stored.
   Expected defence: per-device rate limit (token bucket) at the broker.

2. flooding_api - Story: an attacker with a stolen low-privilege (viewer)
   account hammers the cloud API with requests from many threads.
   Measured: share of flood requests the API actually served (HTTP 200).
   Expected defence: API rate limiting (HTTP 429).
"""

import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import config
from core.http_util import http_json
from module1_attacks.common import broker_reasons, make_result, wait_until_stable

FLOOD_DEVICE = "energy-02"
HONEST_DEVICE = "temp-02"
FLOOD_MESSAGES = 1000
HONEST_MESSAGES = 10
API_REQUESTS = 300
API_THREADS = 10


def run_broker(building):
    """Make a hijacked device flood the broker while an honest device keeps reporting."""
    db = building.db
    flooder = building.device(FLOOD_DEVICE)
    honest = building.device(HONEST_DEVICE)
    last_id = db.last_reading_id()
    rejections_before = len(building.broker.rejections)

    def flood():
        """Publish FLOOD_MESSAGES junk readings back-to-back."""
        for i in range(FLOOD_MESSAGES):
            flooder.publish(flooder.topic, {"device_id": FLOOD_DEVICE, "device_type": "energy",
                                            "power_w": 99999.0, "flood_seq": i,
                                            "ts": round(time.time(), 3)})

    start = time.time()
    flood_thread = threading.Thread(target=flood)
    flood_thread.start()
    for _ in range(HONEST_MESSAGES):                 # honest traffic during the flood
        honest.publish_reading()
        time.sleep(0.02)
    flood_thread.join()
    flood_seconds = time.time() - start

    def count(device_id):
        """Number of readings stored for one device since the attack began."""
        return len(db.readings_after(last_id, device_id))

    flood_stored = wait_until_stable(lambda: count(FLOOD_DEVICE))
    honest_stored = count(HONEST_DEVICE)
    if not flooder.connected:                        # the broker may have kicked it off
        flooder.connect()

    evidence = (f"{FLOOD_MESSAGES} msgs sent in {flood_seconds:.2f}s, cloud stored "
                f"{flood_stored}; honest {HONEST_DEVICE}: {honest_stored}/{HONEST_MESSAGES} "
                f"readings arrived")
    defence = broker_reasons(building, rejections_before)
    return make_result("flooding_broker", building.mode, FLOOD_MESSAGES, flood_stored,
                       defence, evidence)


def run_api(building):
    """Log in with a viewer account and fire API_REQUESTS requests in parallel."""
    viewer = next(u for u in config.SEED_USERS if u[0] == "viewer1")
    _, body = http_json("POST", f"{building.api_url}/api/login",
                        {"username": viewer[0], "password": viewer[1]})
    token = body.get("token")
    url = f"{building.api_url}/api/readings?limit=5"

    def one_request(_):
        """Send one GET request and return its HTTP status code."""
        return http_json("GET", url, token=token)[0]

    start = time.time()
    with ThreadPoolExecutor(max_workers=API_THREADS) as pool:
        statuses = Counter(pool.map(one_request, range(API_REQUESTS)))
    seconds = time.time() - start

    served = statuses.get(200, 0)
    replies = ", ".join(f"HTTP {code} x{n}" for code, n in sorted(statuses.items()))
    evidence = f"{API_REQUESTS} requests in {seconds:.2f}s: {replies}"
    refused = {code: n for code, n in statuses.items() if code != 200}
    defence = ("refused: " + ", ".join(f"HTTP {c} x{n}" for c, n in sorted(refused.items()))
               if refused else "")
    return make_result("flooding_api", building.mode, API_REQUESTS, served, defence, evidence)
