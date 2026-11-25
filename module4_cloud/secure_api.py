"""
module4_cloud/secure_api.py - The SECURE cloud REST API (Flask + SQLite).

Same job as core/cloud_insecure.py, but every weakness is fixed:

  Authentication  POST /api/login checks bcrypt + lockout (Module 3) and returns a
                  JWT (HS256, signed with a random 256-bit secret, valid 15 min).
                  Every other endpoint needs "Authorization: Bearer <JWT>".
                  Tokens with a wrong signature, alg "none", expired, or of a
                  revoked user are refused (401). POST /api/logout revokes a token.
  Authorisation   each endpoint needs a permission; the user's role must have it
                  (RBAC, Module 3) or the answer is 403.
  Validation      every body / query parameter is checked (validation.py) -> 400.
  Rate limiting   login: 10 tries per (IP, username), refilling 1 per 10 s;
                  API: 20-request burst, then 5 per second per user  -> 429.
  Encrypted data  e-mails and sensitive readings are stored AES-GCM encrypted.
  Audit + alerts  every security decision is written to the audit log (audit.py).
  Hardening       4 KB max request body, security headers, JSON errors (no stack traces),
                  "issued_by" comes from the token, never from the client.

Endpoints (permission needed):
    POST   /api/login                  -
    POST   /api/logout                 any valid token
    GET    /api/devices                read_readings
    GET    /api/readings               read_readings
    GET    /api/dashboard              read_readings (alerts only with view_audit)
    POST   /api/command                send_command
    GET    /api/alerts, /api/audit     view_audit
    GET    /api/users                  manage_users
    POST   /api/users                  manage_users
    DELETE /api/users/<username>       manage_users
    GET    /dashboard                  HTML page (logs in with the API)
"""

import functools
import os
import secrets
import time

import jwt
from flask import Flask, g, jsonify, render_template, request

from module3_access.rate_limit import RateLimiter
from module3_access.rbac import (MANAGE_USERS, READ_READINGS, SEND_COMMAND, VIEW_AUDIT,
                                 has_permission)
from module4_cloud import validation

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_MINUTES = 15
ISSUER = "secureteam-securiot-cloud"
REQUIRED_CLAIMS = ["exp", "iat", "sub", "role", "jti", "iss"]


def error(status, message, details=None):
    """Return a JSON error response."""
    body = {"error": message}
    if details:
        body["details"] = details
    return jsonify(body), status


def create_secure_app(db, bridge, login_guard, registry, audit, field_cipher):
    """Build the secure Flask app. All arguments are the running building's components."""
    app = Flask("secure_cloud", template_folder=os.path.join(HERE, "templates"))
    app.config["MAX_CONTENT_LENGTH"] = 4 * 1024           # reject bodies over 4 KB (413)
    jwt_secret = secrets.token_bytes(32)                   # new random secret every start
    login_limiter = RateLimiter(10, 0.1)                   # per (IP, username)
    api_limiter = RateLimiter(20, 5.0)                     # per logged-in user
    revoked_tokens = set()                                 # jti values of logged-out tokens

    # ------------------------------------------------------------------ helpers
    def issue_token(user):
        """Create a signed JWT for a user."""
        now = int(time.time())
        claims = {"sub": user["username"], "role": user["role"], "iat": now,
                  "exp": now + TOKEN_MINUTES * 60, "jti": secrets.token_hex(8), "iss": ISSUER}
        return jwt.encode(claims, jwt_secret, algorithm="HS256")

    def authenticate():
        """Check the Bearer token. Returns (claims, None) or (None, error_response)."""
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            audit.record("missing_token", request.remote_addr, request.path, "info")
            return None, error(401, "missing bearer token")
        token = header[len("Bearer "):]
        try:
            # algorithms=["HS256"] means tokens claiming alg "none" or anything else are refused.
            claims = jwt.decode(token, jwt_secret, algorithms=["HS256"], issuer=ISSUER,
                                options={"require": REQUIRED_CLAIMS})
        except jwt.ExpiredSignatureError:
            audit.record("invalid_token", request.remote_addr, "expired token", "warning")
            return None, error(401, "token expired")
        except jwt.InvalidTokenError as err:
            audit.record("invalid_token", request.remote_addr, type(err).__name__, "warning")
            return None, error(401, "invalid token")
        if claims["jti"] in revoked_tokens:
            return None, error(401, "token has been logged out")
        user = db.get_user(claims["sub"])
        if user is None or not user["active"]:
            audit.record("invalid_token", claims["sub"], "account disabled", "warning")
            return None, error(401, "account disabled")
        return claims, None

    def require(permission):
        """Decorator: valid token + role has `permission` + under the rate limit."""
        def decorator(view):
            """Wrap one endpoint function with the checks."""
            @functools.wraps(view)
            def wrapper(*args, **kwargs):
                """Run token, permission and rate-limit checks, then the endpoint."""
                claims, failure = authenticate()
                if failure:
                    return failure
                if permission and not has_permission(claims["role"], permission):
                    audit.record("permission_denied", claims["sub"],
                                 f"{claims['role']} tried {request.method} {request.path}",
                                 "warning")
                    return error(403, f"role '{claims['role']}' lacks permission '{permission}'")
                if not api_limiter.allow(claims["sub"]):
                    audit.record("rate_limited", claims["sub"], request.path, "warning")
                    return error(429, "too many requests - slow down")
                g.user = claims
                return view(*args, **kwargs)
            return wrapper
        return decorator

    def dashboard_data(include_alerts):
        """Devices, newest reading per device, and (for admins) alerts."""
        return {"mode": "secure", "user": g.user["sub"], "role": g.user["role"],
                "devices": db.list_devices(), "latest": db.latest_per_device(),
                "alerts": db.get_alerts(20) if include_alerts else []}

    # ------------------------------------------------------------------ authentication
    @app.post("/api/login")
    def login():
        """Validate input, rate-limit, check bcrypt + lockout, issue a JWT."""
        data, errors = validation.validate_login(request.get_json(silent=True))
        if errors:
            return error(400, "invalid input", errors)
        if not login_limiter.allow((request.remote_addr, data["username"])):
            audit.record("rate_limited", data["username"], "login", "warning")
            return error(429, "too many login attempts - try later")
        user, status, message = login_guard.check(data["username"], data["password"])
        if user is None:
            event = {401: "login_failed", 423: "account_locked", 403: "login_disabled"}[status]
            audit.record(event, data["username"], message, "warning")
            return error(status, message)
        audit.record("login_ok", user["username"], f"role={user['role']}")
        return jsonify({"token": issue_token(user), "role": user["role"],
                        "expires_in": TOKEN_MINUTES * 60})

    @app.post("/api/logout")
    @require(None)
    def logout():
        """Revoke the current token (its jti) before it expires."""
        revoked_tokens.add(g.user["jti"])
        audit.record("logout", g.user["sub"])
        return jsonify({"status": "logged out"})

    # ------------------------------------------------------------------ data
    @app.get("/api/devices")
    @require(READ_READINGS)
    def devices():
        """List registered devices."""
        return jsonify(db.list_devices())

    @app.get("/api/readings")
    @require(READ_READINGS)
    def readings():
        """Newest readings, with validated limit / device filter."""
        query, errors = validation.validate_readings_query(request.args)
        if errors:
            return error(400, "invalid input", errors)
        return jsonify(db.get_readings(query["device_id"], query["limit"]))

    @app.get("/api/dashboard")
    @require(READ_READINGS)
    def dashboard_api():
        """Everything the dashboard shows (alerts only for roles that may see them)."""
        return jsonify(dashboard_data(has_permission(g.user["role"], VIEW_AUDIT)))

    # ------------------------------------------------------------------ commands
    @app.post("/api/command")
    @require(SEND_COMMAND)
    def command():
        """Send a signed lock/unlock command. 'issued_by' is taken from the token."""
        data, errors = validation.validate_command(request.get_json(silent=True), db)
        if errors:
            audit.record("invalid_input", g.user["sub"], "; ".join(errors), "info")
            return error(400, "invalid input", errors)
        sent = bridge.send_command(data["device_id"], data["command"], issued_by=g.user["sub"])
        audit.record("command_sent", g.user["sub"], f"{data['command']} {data['device_id']}")
        return jsonify({"status": "sent", "cmd_id": sent["cmd_id"]})

    # ------------------------------------------------------------------ admin
    @app.get("/api/alerts")
    @require(VIEW_AUDIT)
    def alerts():
        """Newest alerts."""
        return jsonify(db.get_alerts(100))

    @app.get("/api/audit")
    @require(VIEW_AUDIT)
    def audit_log():
        """Newest audit-log entries."""
        return jsonify(db.get_audit(200))

    @app.get("/api/users")
    @require(MANAGE_USERS)
    def list_users():
        """Users with decrypted e-mail; password hashes are never returned."""
        return jsonify([{"username": u["username"], "role": u["role"],
                         "email": field_cipher.decrypt(u["email"]),
                         "active": bool(u["active"])} for u in db.list_users()])

    @app.post("/api/users")
    @require(MANAGE_USERS)
    def add_user():
        """Register a user (validation + password policy + bcrypt + encrypted e-mail)."""
        data, errors = validation.validate_new_user(request.get_json(silent=True))
        if errors:
            return error(400, "invalid input", errors)
        if db.get_user(data["username"]):
            return error(409, "username already exists")
        try:
            registry.register_user(data["username"], data["password"], data["role"],
                                   data["email"])
        except ValueError as err:
            return error(400, str(err))
        return jsonify({"status": "created", "username": data["username"]}), 201

    @app.delete("/api/users/<username>")
    @require(MANAGE_USERS)
    def revoke_user(username):
        """Disable a user account."""
        if db.get_user(username) is None:
            return error(404, "no such user")
        registry.revoke_user(username)
        return jsonify({"status": "revoked", "username": username})

    # ------------------------------------------------------------------ pages + hardening
    @app.get("/")
    def index():
        """Short description of the service."""
        return jsonify({"service": "SecureIoT-Sim cloud (SECURE mode)",
                        "dashboard": "/dashboard", "login": "POST /api/login"})

    @app.get("/api/mode")
    def mode():
        """Which mode this cloud runs in (public; lets an open dashboard notice a switch)."""
        return jsonify({"mode": "secure"})

    @app.get("/dashboard")
    def dashboard_page():
        """The dashboard HTML; it logs in through the API, data needs a JWT."""
        return render_template("dashboard.html", secure=True,
                               panel_url=app.config.get("PANEL_URL"))

    @app.after_request
    def security_headers(response):
        """Add standard protective HTTP headers to every response."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'")
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    for code, message in [(400, "bad request"), (404, "not found"),
                          (405, "method not allowed"), (413, "request body too large"),
                          (500, "internal server error")]:
        app.register_error_handler(code, lambda _err, c=code, m=message: error(c, m))

    return app
