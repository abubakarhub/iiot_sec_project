"""
core/client.py - A generic broker client (the "MQTT client" of this project).

Devices, the cloud bridge and some attacks all reuse this class.
It handles: connecting, the hello handshake, answering challenges (secure mode),
subscribing, publishing, and a background thread that reads incoming frames.
"""

import logging
import socket
import threading

from config import HOST, BROKER_PORT
from core.channel import PlainChannel
from core.messages import decode_frame, encode_frame, make_frame

log = logging.getLogger("client")


class BrokerClient:
    """Connects to the broker and exchanges frames through a channel."""

    def __init__(self, client_id, channel=None, host=HOST, port=BROKER_PORT):
        """Remember who we are and how to reach the broker (nothing is sent yet)."""
        self.client_id = client_id
        self.channel = channel or PlainChannel()
        self.host = host
        self.port = port
        self.sock = None
        self.connected = False
        self.last_error = None
        self._send_lock = threading.Lock()
        self._hello_done = threading.Event()
        self._sub_done = threading.Event()
        self._sub_ok = False

    # ------------------------------------------------------------------ connection
    def connect(self, timeout=5.0):
        """Open the TCP connection and do the hello handshake. Returns True if accepted."""
        self.connected = False
        self.last_error = None
        self._hello_done.clear()                       # allows reconnecting later
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        self.sock.settimeout(None)                     # blocking reads from now on
        threading.Thread(target=self._reader_loop, args=(self.sock,),
                         name=f"rx-{self.client_id}", daemon=True).start()
        hello = make_frame("hello", client_id=self.client_id,
                           **self.channel.hello_fields(self.client_id))
        self.send_frame(hello)
        self._hello_done.wait(timeout)
        if self.connected:
            self.on_connected()
        return self.connected

    def on_connected(self):
        """Called once the broker accepts us. Subclasses subscribe here."""

    def close(self):
        """Disconnect from the broker."""
        self.connected = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()

    # ------------------------------------------------------------------ sending
    def send_frame(self, frame):
        """Send one frame to the broker (thread-safe). Returns False if the link is down."""
        try:
            with self._send_lock:
                self.sock.sendall(encode_frame(frame))
            return True
        except (OSError, AttributeError):
            return False

    def subscribe(self, pattern, timeout=3.0):
        """Ask the broker for messages matching pattern. Returns True if allowed."""
        self._sub_done.clear()
        self._sub_ok = False
        self.send_frame(make_frame("subscribe", topic=pattern))
        self._sub_done.wait(timeout)
        return self._sub_ok

    def publish(self, topic, payload):
        """Protect the payload with our channel and publish it on a topic."""
        wrapped = self.channel.wrap(self.client_id, topic, payload)
        return self.send_frame(make_frame("publish", topic=topic, payload=wrapped))

    # ------------------------------------------------------------------ receiving
    def _reader_loop(self, sock):
        """Background thread: read frames from one socket until it closes."""
        try:
            reader = sock.makefile("rb")
            for line in reader:
                frame = decode_frame(line)
                if frame is not None:
                    self._handle_frame(frame)
        except (OSError, ValueError):
            pass
        finally:
            if self.sock is sock:                     # ignore old sockets after a reconnect
                self.connected = False
                self._hello_done.set()                # unblock connect() if still waiting

    def _handle_frame(self, frame):
        """React to one frame from the broker."""
        kind = frame.get("type")
        ref = frame.get("ref")
        if kind == "ack" and ref == "hello":
            self.connected = True
            self._hello_done.set()
        elif kind == "ack" and ref == "subscribe":
            self._sub_ok = True
            self._sub_done.set()
        elif kind == "error":
            self.last_error = frame.get("reason")
            if ref == "hello":
                self._hello_done.set()                # handshake refused
            elif ref == "subscribe":
                self._sub_done.set()                  # subscription refused
            self.on_error(frame)
        elif kind == "challenge":
            answer = self.channel.answer_challenge(self.client_id, frame)
            if answer is not None:
                self.send_frame(answer)
        elif kind == "message":
            payload = self.channel.unwrap(frame.get("sender"), frame.get("topic"),
                                          frame.get("payload"))
            if payload is not None:
                self.on_message(frame.get("topic"), frame.get("sender"), payload)

    def on_message(self, topic, sender, payload):
        """Called for every delivered message that passed channel.unwrap(). Override me."""

    def on_error(self, frame):
        """Called when the broker rejects something we sent. Override if needed."""
        log.debug("%s got error: %s", self.client_id, frame.get("reason"))
