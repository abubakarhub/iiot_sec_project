"""
core/control_panel.py - The simulation control panel (http://127.0.0.1:5050).

This is the "lab view" of the simulation, NOT part of the building's cloud:
    * live view of the 8 devices and their latest readings,
    * live traffic feed: every frame that crossed the gateway, accepted or rejected
      (in insecure mode you can read the payloads; in secure mode they are ciphertext),
    * buttons that launch the real Module 1 attacks against the running system,
    * an insecure <-> secure switch and a before/after table (with a one-click
      full comparison),
    * (secure mode) buttons to rotate / revoke / restore device keys.

It is kept separate from the cloud API on purpose: the cloud (port 5000) is the
system under test, and this panel plays the role of the attacker's laptop and
the lab instructor. It only listens on 127.0.0.1 and only accepts requests from
this computer.
"""

import os

from flask import Flask, abort, jsonify, render_template, request

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_ADDRESSES = {"127.0.0.1", "::1"}
PANEL_HEADER = "X-Panel-Request"     # custom header -> other websites cannot POST here


def create_control_panel(live):
    """Build the control-panel Flask app for a running LiveSimulation."""
    app = Flask("control_panel", template_folder=os.path.join(HERE, "templates"))

    @app.before_request
    def only_this_computer():
        """Refuse anything not coming from this laptop; POSTs must carry the panel header."""
        if request.remote_addr not in LOCAL_ADDRESSES:
            abort(403)
        if request.method == "POST" and request.headers.get(PANEL_HEADER) != "1":
            abort(403)

    @app.get("/")
    def panel_page():
        """The control panel HTML page."""
        return render_template("control_panel.html", mode=live.building.mode)

    @app.get("/api/state")
    def state():
        """Live state: devices, traffic feed, attack results, alerts."""
        return jsonify(live.snapshot())

    @app.post("/api/attack/<name>")
    def launch_attack(name):
        """Start one attack (or 'all') in the background."""
        started, message = live.start_attack(name)
        return jsonify({"started": started, "message": message}), (202 if started else 409)

    @app.post("/api/device/<device_id>/<action>")
    def device_action(device_id, action):
        """Rotate / revoke / restore a device key (secure mode only)."""
        ok, message = live.device_action(device_id, action)
        return jsonify({"ok": ok, "message": message}), (200 if ok else 400)

    @app.post("/api/mode/<mode>")
    def switch_mode(mode):
        """Restart the building in the other mode (insecure <-> secure)."""
        started, message = live.switch_mode(mode)
        return jsonify({"started": started, "message": message}), (202 if started else 409)

    @app.post("/api/compare")
    def compare():
        """Run all attacks on insecure, switch to secure, run them all again."""
        started, message = live.start_comparison()
        return jsonify({"started": started, "message": message}), (202 if started else 409)

    @app.post("/api/traffic/<action>")
    def traffic(action):
        """Pause or resume the devices' background traffic."""
        if action not in ("pause", "resume"):
            return jsonify({"ok": False, "message": "use pause or resume"}), 400
        live.set_paused(action == "pause")
        return jsonify({"ok": True, "message": f"device traffic {action}d"})

    @app.post("/api/stop")
    def stop():
        """Shut the whole simulation down (main.py notices and stops everything)."""
        live.request_stop()
        return jsonify({"ok": True, "message": "simulation is stopping"})

    @app.after_request
    def no_framing(response):
        """Basic protective headers."""
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    return app
