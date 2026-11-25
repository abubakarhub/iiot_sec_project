"""
core/webserver.py - Runs a Flask app in a background thread.

Flask's normal app.run() blocks forever. For the simulation we need the cloud
API running WHILE devices and attacks run in the main thread, and we need to be
able to stop it cleanly, so we use Werkzeug's make_server in a thread.
"""

import logging
import threading

from werkzeug.serving import make_server

log = logging.getLogger("webserver")

# Hide Werkzeug's one-line-per-request log (it floods the console during attacks).
logging.getLogger("werkzeug").setLevel(logging.WARNING)


class ServerThread:
    """Start/stop wrapper around a Werkzeug HTTP server."""

    def __init__(self, app, host, port, name="cloud API"):
        """Create (but do not start) a threaded server for the Flask app."""
        self.host = host
        self.port = port
        self.name = name
        self.server = make_server(host, port, app, threaded=True)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       name=name.replace(" ", "-"), daemon=True)

    def start(self):
        """Begin serving HTTP requests in the background."""
        self.thread.start()
        log.info("%s listening on http://%s:%d", self.name, self.host, self.port)

    def stop(self):
        """Stop serving and free the port."""
        if self.thread.is_alive():          # shutdown() would hang if never started
            self.server.shutdown()
        self.server.server_close()
        log.info("%s stopped", self.name)
