"""
core/live.py - Keeps the Smart Building running "live" after start-up.

A normal run sends a few rounds of readings, runs the attacks once and stops.
In live mode (python main.py --mode secure --live) this controller instead:

  * keeps every device publishing a reading every LIVE_INTERVAL seconds,
    so the cloud dashboard keeps changing;
  * lets you launch any Module 1 attack on demand from the control panel
    (core/control_panel.py) and records the measured result;
  * can SWITCH the building between insecure and secure mode: the running
    building is stopped and a fresh one is started in the other mode on the
    same ports, so the very same attacks can be shown "before" and "after";
  * keeps the results of both modes for the before/after table, and can run the
    whole before/after comparison with one click;
  * in secure mode, lets you rotate, revoke and restore device keys live.

Only one "job" (an attack, a mode switch or the full comparison) runs at a time.
While a job runs, the background traffic is paused: each attack makes its own
traffic, so its success rate is measured exactly as in the batch run.
"""

import logging
import threading
import time
from collections import deque

import config
from core.simulation import SmartBuilding
from module1_attacks.attack_runner import ATTACK_DESCRIPTIONS, ATTACKS
from module1_attacks.common import make_result

log = logging.getLogger("live")
ATTACK_NAMES = [name for name, _ in ATTACKS]
ATTACK_FUNCTIONS = dict(ATTACKS)
MODES = ("insecure", "secure")


def short_result(result):
    """The few fields of an attack result shown in the before/after table."""
    if result is None:
        return None
    return {"outcome": result["outcome"], "rate": result["success_rate_pct"],
            "successes": result["successes"], "attempts": result["attempts"],
            "defence": result["observed_defence"] or result["evidence"]}


class LiveSimulation:
    """Background traffic, on-demand attacks and mode switching for a running building."""

    def __init__(self, building, interval=config.LIVE_INTERVAL, panel_url=None):
        """Remember the building; nothing runs until start()."""
        self.building = building
        self.interval = interval
        self.panel_url = panel_url              # shown as a button on the cloud dashboard
        self.running = False
        self.paused = False                     # True = devices stop sending (Pause button)
        self.stop_requested = threading.Event() # set by the "Stop simulation" button
        self.current_attack = None              # name of the attack running right now
        self.busy = None                        # description of the job in progress
        self.results = deque(maxlen=100)        # finished attacks of BOTH modes, newest last
        self.events = deque(maxlen=40)          # short human-readable activity log
        self.started_at = time.time()
        self._traffic_lock = threading.Lock()   # held by a traffic round OR a job step
        self._job_lock = threading.Lock()       # only one job at a time
        self._link_dashboard(building)

    def _link_dashboard(self, building):
        """Tell the building's cloud dashboard where the control panel is."""
        if self.panel_url:
            building.web.server.app.config["PANEL_URL"] = self.panel_url

    # ------------------------------------------------------------------ traffic
    def start(self):
        """Start the background thread that keeps the devices publishing."""
        self.running = True
        threading.Thread(target=self._traffic_loop, name="live-traffic", daemon=True).start()
        self.add_event("system", f"live simulation started ({self.building.mode} mode)")
        log.info("live traffic: every device publishes every %.1f s", self.interval)

    def stop(self):
        """Stop the background traffic."""
        self.running = False

    def set_paused(self, paused):
        """Pause or resume the device traffic (attacks can still be launched)."""
        self.paused = paused
        self.add_event("system", "device traffic paused" if paused else "device traffic resumed")
        log.info("live traffic %s", "paused" if paused else "resumed")

    def request_stop(self):
        """Ask main.py to shut the whole simulation down (same as Ctrl+C)."""
        self.add_event("system", "stop requested from the control panel")
        log.info("stop requested from the control panel")
        self.stop_requested.set()

    def _traffic_loop(self):
        """Every interval, each connected device publishes one reading (skipped during jobs)."""
        while self.running:
            if not self.paused and self._traffic_lock.acquire(blocking=False):
                try:
                    for device in self.building.devices:
                        if device.connected:
                            device.publish_reading()
                finally:
                    self._traffic_lock.release()
            time.sleep(self.interval)

    # ------------------------------------------------------------------ jobs
    def _start_job(self, label, target, *args):
        """Run target(*args) in the background unless another job is running."""
        if not self._job_lock.acquire(blocking=False):
            return False, f"busy ({self.busy}) - wait for it to finish"
        self.busy = label

        def runner():
            """Run the job and always free the job slot afterwards."""
            try:
                target(*args)
            except Exception as err:            # a failed job must not kill the live system
                log.exception("%s failed", label)
                self.add_event("system", f"{label} failed: {err}")
            finally:
                self.current_attack = None
                self.busy = None
                self._job_lock.release()

        threading.Thread(target=runner, name="live-job", daemon=True).start()
        return True, f"started: {label}"

    def missing_devices(self):
        """Devices that are revoked or offline (the attacks need all 8)."""
        return [row["device_id"] for row in self.device_rows()
                if row["status"] != "active" or not row["online"]]

    # ------------------------------------------------------------------ attacks
    def start_attack(self, name):
        """Launch one attack (or "all") in the background. Returns (started, message)."""
        names = ATTACK_NAMES if name == "all" else [name]
        if any(n not in ATTACK_FUNCTIONS for n in names):
            return False, f"unknown attack '{name}'"
        # The attacks expect the full building (e.g. replay/unauthorised command target
        # the door locks), so refuse while a device is revoked or offline.
        missing = self.missing_devices()
        if missing:
            return False, ("restore " + ", ".join(missing) + " first - the attacks need "
                           "all 8 devices online")
        label = "all 8 attacks" if name == "all" else name.replace("_", " ")
        return self._start_job(f"attack: {label} ({self.building.mode} mode)",
                               self._run_attacks, names)

    def _run_attacks(self, names):
        """Run several attacks one after another."""
        for name in names:
            self._run_one(name)

    def _run_one(self, name):
        """Run one attack with normal traffic paused, and store its measured result."""
        building = self.building
        self.current_attack = name
        self.add_event("attack", f"attack '{name}' started ({building.mode} mode)")
        with self._traffic_lock:
            started = time.time()
            try:
                result = ATTACK_FUNCTIONS[name](building)
            except Exception as err:              # reported as ERROR, never as BLOCKED
                log.exception("attack %s crashed", name)
                result = make_result(name, building.mode, 0, 0, "", f"attack crashed: {err}")
            result = dict(result, started=started, seconds=round(time.time() - started, 1))
        self.results.append(result)
        self.add_event("result", f"{name} ({building.mode}): {result['outcome']} "
                                 f"({result['success_rate_pct']}% succeeded)")
        log.info("live attack %s (%s) -> %s (%s%%)", name, building.mode, result["outcome"],
                 result["success_rate_pct"])
        self.current_attack = None
        time.sleep(0.3)

    # ------------------------------------------------------------------ mode switching
    def switch_mode(self, mode):
        """Replace the running building with a fresh one in the other mode."""
        if mode not in MODES:
            return False, f"unknown mode '{mode}'"
        if mode == self.building.mode:
            return False, f"already running in {mode} mode"
        return self._start_job(f"switching to {mode} mode", self._switch, mode)

    def _switch(self, mode):
        """Stop the current building and start a new one (same ports) in `mode`."""
        with self._traffic_lock:
            old = self.building
            self.add_event("system", f"stopping the {old.mode} building")
            log.info("switching %s -> %s", old.mode, mode)
            old.stop()
            try:
                new = self._build(mode)
            except Exception as err:
                log.exception("could not start %s mode", mode)
                self.add_event("system", f"could not start {mode} mode ({err}); "
                                         f"restarting {old.mode} mode")
                new = self._build(old.mode)
            self.building = new
        self.add_event("system", f"now running in {self.building.mode} mode")

    def _build(self, mode):
        """Create, start and warm up a fresh building."""
        building = SmartBuilding(mode)
        building.start()
        building.run_rounds(1)
        self._link_dashboard(building)
        return building

    # ------------------------------------------------------------------ before/after
    def start_comparison(self):
        """Run all attacks in insecure mode, switch to secure, run them all again."""
        return self._start_job("full before/after comparison", self._comparison)

    def _comparison(self):
        """The comparison job (see start_comparison)."""
        for mode in MODES:
            if self.building.mode != mode:
                self.busy = f"comparison: switching to {mode} mode"
                self._switch(mode)
            for number, name in enumerate(ATTACK_NAMES, 1):
                self.busy = (f"comparison: {mode} mode, attack {number}/{len(ATTACK_NAMES)} "
                             f"({name.replace('_', ' ')})")
                self._run_one(name)
        self.add_event("system", "before/after comparison finished")

    def before_after(self):
        """Newest result of every attack in each mode, for the before/after table."""
        latest = {}
        for result in self.results:            # oldest first, so newer ones overwrite
            latest[(result["attack"], result["mode"])] = result
        return [{"attack": name, "description": ATTACK_DESCRIPTIONS.get(name, ""),
                 "before": short_result(latest.get((name, "insecure"))),
                 "after": short_result(latest.get((name, "secure")))}
                for name in ATTACK_NAMES]

    # ------------------------------------------------------------------ device actions (secure)
    def device_action(self, device_id, action):
        """Rotate / revoke / restore a device key (secure mode). Returns (ok, message)."""
        building = self.building
        if self.busy:
            return False, f"busy ({self.busy}) - wait for it to finish"
        if building.mode != "secure":
            return False, "key management only exists in secure mode"
        if device_id not in [d.device_id for d in building.devices]:
            return False, f"unknown device '{device_id}'"
        if action not in ("rotate", "revoke", "restore"):
            return False, f"unknown action '{action}'"
        with self._traffic_lock:
            try:
                if action == "rotate":
                    version = building.rotate_device_key(device_id)
                    message = f"{device_id}: key rotated to v{version}"
                elif action == "revoke":
                    building.revoke_device(device_id, "revoked from the control panel")
                    message = f"{device_id}: revoked and disconnected"
                else:
                    ok = building.reprovision_device(device_id)
                    version = building.keyrings[device_id].current
                    message = (f"{device_id}: re-registered with new key v{version}, "
                               f"{'reconnected' if ok else 'could NOT reconnect'}")
            except Exception as err:               # e.g. rotating a revoked device
                return False, f"{device_id}: {action} refused ({err})"
        self.add_event("keys", message)
        log.info("key management: %s", message)
        return True, message

    # ------------------------------------------------------------------ state for the panel
    def add_event(self, kind, text):
        """Add one line to the activity log shown on the control panel."""
        self.events.append({"at": time.time(), "kind": kind, "text": text})

    def device_rows(self):
        """One row per device: online, registry status, key version, last reading."""
        building = self.building
        rows = []
        for device in building.devices:
            record = building.db.get_device(device.device_id) or {}
            row = {"device_id": device.device_id, "device_type": device.device_type,
                   "location": device.location, "online": bool(device.connected),
                   "status": record.get("status", "?"), "sent": device.readings_sent,
                   "reading": device.last_reading, "state": getattr(device, "state", None),
                   "key_version": None}
            if building.mode == "secure":
                row["key_version"] = building.keyrings[device.device_id].current
            rows.append(row)
        return rows

    def snapshot(self):
        """Everything the control panel shows, as one dictionary."""
        building = self.building
        broker = building.broker
        with broker._lock:
            feed = list(broker.feed)[-30:]
            totals = dict(broker.totals)
        return {
            "mode": building.mode,
            "uptime": round(time.time() - self.started_at),
            "interval": self.interval,
            "paused": self.paused,
            "busy": self.busy,
            "dashboard_url": f"{building.api_url}/dashboard",
            "cloud_received": building.bridge.received,
            "broker": totals,
            "feed": list(reversed(feed)),
            "devices": self.device_rows(),
            "attacks": [{"name": n, "description": ATTACK_DESCRIPTIONS.get(n, "")}
                        for n in ATTACK_NAMES],
            "current_attack": self.current_attack,
            "results": list(reversed(self.results)),
            "before_after": self.before_after(),
            "events": list(reversed(self.events)),
            "alerts": building.db.get_alerts(8) if building.mode == "secure" else [],
        }
