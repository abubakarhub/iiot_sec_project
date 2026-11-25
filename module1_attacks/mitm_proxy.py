"""
module1_attacks/mitm_proxy.py - The attacker's man-in-the-middle relay.

Real-world picture: the attacker controls the Wi-Fi access point or a switch
between a device and the gateway, so every byte passes through them.

In the simulation: a victim client is reconnected to 127.0.0.1:18840 (this
relay) instead of the broker. The relay forwards every line to the real broker
and back, and while doing so it can:
  * record every frame              -> sniffing, and capturing frames for replay
  * change frames on the way        -> tampering
  * inject extra frames             -> replay (into the victim's own session)
"""

import logging
import socket
import threading

from config import HOST, BROKER_PORT, MITM_PORT
from core.messages import decode_frame, encode_frame
from module1_attacks.safety import assert_local

log = logging.getLogger("attacker-mitm")


class MitmProxy:
    """A line-by-line TCP relay that can record, modify and inject frames."""

    def __init__(self, listen_port=MITM_PORT, target_port=BROKER_PORT, tamper=None):
        """tamper is an optional function(frame) -> frame used on client->broker frames."""
        assert_local(HOST)
        self.listen_port = listen_port
        self.target_port = target_port
        self.tamper = tamper
        self.captured = []          # list of (link_number, direction, raw_bytes)
        self.tampered = 0           # how many frames we modified
        self._links = []            # list of (client_socket, broker_socket, send_lock)
        self._server = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ start / stop
    def start(self):
        """Start listening for victims."""
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.bind((HOST, self.listen_port))
        self._server.listen(20)
        threading.Thread(target=self._accept_loop, daemon=True, name="mitm-accept").start()
        log.info("MITM relay listening on %s:%d -> broker %d", HOST, self.listen_port,
                 self.target_port)
        return self

    def stop(self):
        """Close the relay and every link through it."""
        if self._server:
            self._server.close()
        for client_sock, broker_sock, _ in self._links:
            for sock in (client_sock, broker_sock):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()

    # ------------------------------------------------------------------ relaying
    def _accept_loop(self):
        """For each victim connection, open a matching connection to the real broker."""
        while True:
            try:
                client_sock, _ = self._server.accept()
            except OSError:
                break
            broker_sock = socket.create_connection((HOST, self.target_port))
            with self._lock:
                link = len(self._links)
                self._links.append((client_sock, broker_sock, threading.Lock()))
            threading.Thread(target=self._pump, args=(link, client_sock, broker_sock, "up"),
                             daemon=True).start()
            threading.Thread(target=self._pump, args=(link, broker_sock, client_sock, "down"),
                             daemon=True).start()

    def _pump(self, link, src, dst, direction):
        """Copy lines from src to dst, recording them and (upstream) maybe tampering."""
        send_lock = self._links[link][2] if direction == "up" else threading.Lock()
        try:
            for line in src.makefile("rb"):
                with self._lock:
                    self.captured.append((link, direction, line))
                if direction == "up" and self.tamper is not None:
                    line = self._maybe_tamper(line)
                with send_lock:
                    dst.sendall(line)
        except (OSError, ValueError):
            pass
        finally:
            try:                                 # one side hung up -> hang up the other
                dst.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _maybe_tamper(self, line):
        """Run the tamper function on a frame; re-encode it if it changed."""
        frame = decode_frame(line)
        if frame is None:
            return line
        changed = self.tamper(dict(frame))
        if changed is not None and changed != frame:
            self.tampered += 1
            return encode_frame(changed)
        return line

    # ------------------------------------------------------------------ attacker tools
    def frames(self, direction="up", frame_type="publish"):
        """Return captured frames (as dictionaries) with their link number."""
        result = []
        with self._lock:
            captured = list(self.captured)
        for link, dirn, raw in captured:
            if dirn != direction:
                continue
            frame = decode_frame(raw)
            if frame and frame.get("type") == frame_type:
                result.append((link, frame, raw))
        return result

    def inject(self, link, raw_line):
        """Send raw bytes to the broker inside an existing victim connection."""
        _, broker_sock, send_lock = self._links[link]
        with send_lock:
            broker_sock.sendall(raw_line)
