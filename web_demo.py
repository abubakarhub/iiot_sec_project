"""
web_demo.py - Hosted live demo of SecureIoT-Sim (for example on Render).

    PANEL_PASSWORD=<choose one> python web_demo.py

Runs the same live simulation as `python main.py --mode insecure --live`, but puts
both web pages behind ONE public port (the PORT environment variable):

    /            -> redirects to the control panel
    /panel/      -> control panel (password protected: user any, password PANEL_PASSWORD)
    /dashboard   -> cloud dashboard (and its /api/... endpoints)

Inside the server nothing changes: broker, devices, cloud and every attack still
use 127.0.0.1 only, so the attacks only ever hit this simulation.
"""

import logging
import os
import sys

from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple
from werkzeug.utils import redirect

from core.control_panel import create_control_panel
from core.live import LiveSimulation
from core.simulation import SmartBuilding


class CurrentCloud:
    """WSGI app that forwards each request to the cloud of whichever building runs now."""

    def __init__(self, live):
        """Remember the live simulation (its building changes on a mode switch)."""
        self.live = live

    def __call__(self, environ, start_response):
        """Send the request to the current building's Flask cloud app."""
        path = environ.get("PATH_INFO", "")
        if path in ("", "/", "/panel"):
            return redirect("/panel/")(environ, start_response)
        return self.live.building.web.server.app(environ, start_response)


def main():
    """Start the building, the live simulation and the public web server."""
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(asctime)s [%(name)s] %(message)s", datefmt="%H:%M:%S")
    os.environ["SECUREIOT_PUBLIC"] = "1"
    if not os.environ.get("PANEL_PASSWORD"):
        print("Set the PANEL_PASSWORD environment variable first (the control panel needs it).")
        return 1
    mode = os.environ.get("START_MODE", "insecure")
    building = SmartBuilding(mode)
    building.start()
    building.run_rounds(1)
    live = LiveSimulation(building, panel_url="/panel/", dashboard_url="/dashboard")
    live.start()
    app = DispatcherMiddleware(CurrentCloud(live), {"/panel": create_control_panel(live)})
    port = int(os.environ.get("PORT", "8000"))
    print(f"SecureIoT-Sim hosted demo on port {port}: /panel/ (control panel), /dashboard", flush=True)
    run_simple("0.0.0.0", port, app, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
