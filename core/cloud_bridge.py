"""
core/cloud_bridge.py - Connects the cloud to the building gateway.

The bridge is a broker client called "cloud" that:
  * subscribes to every building topic ("building/#"),
  * saves each reading it receives into the cloud database,
  * publishes commands (e.g. "unlock") to a door lock's command topic.
"""

import logging
import secrets
import threading
import time

from config import DEVICES, HOST, BROKER_PORT, command_topic
from core.client import BrokerClient

log = logging.getLogger("cloud-bridge")


class CloudBridge(BrokerClient):
    """The cloud's connection to the broker."""

    def __init__(self, db, channel=None, host=HOST, port=BROKER_PORT):
        """Create the bridge; it writes into the given Database."""
        super().__init__("cloud", channel=channel, host=host, port=port)
        self.db = db
        self.received = 0
        self._count_lock = threading.Lock()
        # Optional function(payload) -> payload that adds protection to outgoing
        # commands (Module 2 uses it to add an ECDSA signature). None = send as-is.
        self.command_signer = None

    def on_connected(self):
        """Subscribe to all building traffic once the broker accepts us."""
        if not self.subscribe("building/#"):
            log.error("cloud could not subscribe: %s", self.last_error)

    def on_message(self, topic, sender, payload):
        """Store every reading in the database (commands on /cmd topics are skipped)."""
        if topic.endswith("/cmd"):
            return
        # The broker tells us who sent it. In insecure mode that is simply the
        # name the sender CLAIMED in its hello - nobody checked it.
        self.db.insert_reading(sender, topic, payload)
        with self._count_lock:
            self.received += 1

    def send_command(self, device_id, command, issued_by="system"):
        """Publish a lock/unlock command to one device. Returns the payload sent."""
        entry = next((d for d in DEVICES if d[0] == device_id), None)
        if entry is None:
            raise ValueError(f"unknown device {device_id}")
        payload = {"command": command, "issued_by": issued_by,
                   "cmd_id": secrets.token_hex(4), "ts": round(time.time(), 3)}
        if self.command_signer is not None:
            payload = self.command_signer(payload)
        self.publish(command_topic(*entry), payload)
        self.db.insert_command(device_id, command, issued_by)
        log.info("command %r sent to %s (issued by %s)", command, device_id, issued_by)
        return payload

    def wait_for_readings(self, expected_total, timeout=5.0):
        """Wait until at least expected_total readings have been stored. Returns the count."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._count_lock:
                if self.received >= expected_total:
                    break
            time.sleep(0.02)
        return self.received
