"""
core/cloud_insecure.py - The INSECURE cloud REST API (Flask + SQLite).

Endpoints:
    GET  /                 list of endpoints
    GET  /dashboard        web dashboard (no login)
    GET  /api/dashboard    dashboard data (open to anyone)
    POST /api/login        {"username", "password"} -> token
    GET  /api/devices      registered devices
    GET  /api/readings     newest readings (?device_id=...&limit=...)
    POST /api/command      {"device_id", "command"} -> sends lock/unlock

Deliberate weaknesses (fixed by module4_cloud/secure_api.py):
  * passwords stored and compared in PLAINTEXT
  * no login attempt limit, no lockout, no rate limiting   -> brute force, flooding
  * "token" is just "insecure-<username>" - anyone can forge it
  * /api/command does not check who is asking              -> unauthorised commands
  * no input validation (limit / device_id used as given)
  * different error messages reveal whether a username exists
"""

import os

from flask import Flask, jsonify, render_template, request

from config import BASE_DIR

# The dashboard page itself is Module 4's; the insecure cloud reuses it without login.
DASHBOARD_TEMPLATES = os.path.join(BASE_DIR, "module4_cloud", "templates")


def plaintext_password_check(db, username, password):
    """INSECURE login check: plaintext comparison, and the reply reveals which part was wrong."""
    user = db.get_user(username)
    if user is None:
        return None, 401, "no such user"                 # leaks valid usernames
    if user["password"] != password:                     # plaintext comparison
        return None, 401, "wrong password"
    return user, 200, "ok"


def create_insecure_app(db, bridge, password_check=None):
    """
    Build the insecure Flask app that reads/writes the given database.
    password_check(username, password) -> (user, status, message) can be swapped
    for a safer one; by default the plaintext check above is used.
    """
    app = Flask("insecure_cloud", template_folder=DASHBOARD_TEMPLATES)
    check = password_check or (lambda u, p: plaintext_password_check(db, u, p))

    @app.get("/dashboard")
    def dashboard_page():
        """The shared dashboard page, in insecure mode (no login)."""
        return render_template("dashboard.html", secure=False,
                               panel_url=app.config.get("PANEL_URL"))

    @app.get("/api/mode")
    def mode():
        """Which mode this cloud runs in (lets an open dashboard notice a switch)."""
        return jsonify({"mode": "insecure"})

    @app.get("/api/dashboard")
    def dashboard_api():
        """Dashboard data - open to anyone, and there is no alerting in the baseline."""
        return jsonify({"mode": "insecure", "user": None, "role": None,
                        "devices": db.list_devices(), "latest": db.latest_per_device(),
                        "alerts": []})

    @app.get("/")
    def index():
        """Show which endpoints exist."""
        return jsonify({"service": "SecureIoT-Sim cloud (INSECURE mode)",
                        "endpoints": ["POST /api/login", "GET /api/devices",
                                      "GET /api/readings", "POST /api/command"]})

    @app.post("/api/login")
    def login():
        """Check username/password in plaintext and hand out a forgeable token."""
        data = request.get_json(silent=True) or {}
        user, status, message = check(data.get("username"), data.get("password"))
        if user is None:
            return jsonify({"error": message}), status
        return jsonify({"token": f"insecure-{user['username']}", "role": user["role"]})

    @app.get("/api/devices")
    def devices():
        """List all devices - no login required."""
        return jsonify(db.list_devices())

    @app.get("/api/readings")
    def readings():
        """Return readings - no login required, 'limit' not validated."""
        limit = int(request.args.get("limit", 20))
        return jsonify(db.get_readings(request.args.get("device_id"), limit))

    @app.post("/api/command")
    def command():
        """Send a command to a device - ANYONE can do this, no token checked."""
        data = request.get_json(silent=True) or {}
        try:
            sent = bridge.send_command(data.get("device_id"), data.get("command"),
                                       issued_by=data.get("issued_by", "anonymous"))
        except ValueError as err:
            return jsonify({"error": str(err)}), 400
        return jsonify({"status": "sent", "command": sent})

    return app
