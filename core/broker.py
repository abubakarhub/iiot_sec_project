"""
core/broker.py - The building gateway: an INSECURE publish/subscribe broker.

It works like a tiny MQTT broker over TCP on 127.0.0.1:
  * clients connect and say "hello" with a client id,
  * subscribers register topic patterns,
  * publishers send payloads that the broker forwards to matching subscribers.

Deliberate weaknesses (this is the baseline we attack in Module 1):
  * it believes any client id it is told (no authentication)   -> spoofing
  * anyone may publish/subscribe to any topic, even '#'          -> sniffing, unauthorised commands
  * no limit on message rate                                     -> flooding
  * no check for repeated or modified messages                   -> replay, tampering

The secure broker in module3_access/secure_broker.py subclasses this class and
overrides the "hook" methods (on_hello, allow_publish, allow_subscribe).
"""

import json
import logging
import socket
import threading
import time
from collections import deque

from config import HOST, BROKER_PORT
from core.messages import decode_frame, encode_frame, make_frame, topic_matches

log = logging.getLogger("broker")
FEED_SIZE = 80                  # how many recent frames the live traffic feed keeps


class ClientSession:
    """One connected client (device, cloud bridge or attacker) as seen by the broker."""

    def __init__(self, sock, address):
        """Store the socket and start with an unknown, unauthenticated identity."""
        self.sock = sock
        self.address = address
        self.client_id = None
        self.authenticated = False
        self.subscriptions = []
        self.alive = True
        self.extra = {}                 # scratch space for the secure broker
        self._send_lock = threading.Lock()

    def send(self, frame):
        """Send one frame to this client; mark the session dead if the socket broke."""
        try:
            with self._send_lock:
                self.sock.sendall(encode_frame(frame))
        except OSError:
            self.alive = False

    def close(self):
        """Close the connection to this client."""
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class InsecureBroker:
    """A minimal TCP publish/subscribe broker with NO security."""

    def __init__(self, host=HOST, port=BROKER_PORT):
        """Prepare the broker; call start() to begin listening."""
        self.host = host
        self.port = port
        self.sessions = []
        self.running = False
        self._lock = threading.Lock()
        self._server_sock = None
        # Counters used by the attacks to measure what got through.
        self.stats = {"accepted": 0, "rejected": 0, "delivered": 0}
        self.rejections = []            # list of (client_id, reason) for evidence
        # Live view (control panel): totals that are never reset, and the most
        # recent frames exactly as they crossed the gateway.
        self.totals = {"accepted": 0, "rejected": 0}
        self.feed = deque(maxlen=FEED_SIZE)

    # ------------------------------------------------------------------ start / stop
    def start(self):
        """Open the listening socket and accept clients in a background thread."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(100)
        self.running = True
        threading.Thread(target=self._accept_loop, name="broker-accept", daemon=True).start()
        log.info("%s listening on %s:%d", type(self).__name__, self.host, self.port)

    def stop(self):
        """Stop accepting clients and disconnect everyone."""
        self.running = False
        if self._server_sock:
            self._server_sock.close()
        with self._lock:
            sessions = list(self.sessions)
            self.sessions.clear()
        for session in sessions:
            session.close()
        log.info("broker stopped")

    # ------------------------------------------------------------------ network loops
    def _accept_loop(self):
        """Wait for new TCP connections and give each one its own thread."""
        while self.running:
            try:
                conn, address = self._server_sock.accept()
            except OSError:
                break                   # socket was closed by stop()
            session = ClientSession(conn, address)
            with self._lock:
                self.sessions.append(session)
            threading.Thread(target=self._client_loop, args=(session,), daemon=True).start()

    def _client_loop(self, session):
        """Read frames from one client line by line until it disconnects."""
        reader = session.sock.makefile("rb")
        try:
            for line in reader:
                frame = decode_frame(line)
                if frame is None:
                    self.reject(session, "malformed frame")
                else:
                    self.handle_frame(session, frame)
                if not session.alive:
                    break
        except (OSError, ValueError):
            pass                        # connection closed
        finally:
            with self._lock:
                if session in self.sessions:
                    self.sessions.remove(session)
            session.close()

    # ------------------------------------------------------------------ frame handling
    def handle_frame(self, session, frame):
        """Send each frame type to the method that handles it."""
        kind = frame.get("type")
        if kind == "hello":
            self.on_hello(session, frame)
        elif kind == "subscribe":
            self.on_subscribe(session, frame)
        elif kind == "publish":
            self.on_publish(session, frame)
        else:
            self.on_other(session, frame)

    def on_hello(self, session, frame):
        """INSECURE: believe whatever client id the client claims - no proof needed."""
        session.client_id = str(frame.get("client_id") or f"anon-{session.address[1]}")
        session.authenticated = True
        session.send(make_frame("ack", ref="hello"))
        log.debug("hello from %s", session.client_id)

    def on_subscribe(self, session, frame):
        """Register a topic pattern for this client if allow_subscribe() says yes."""
        topic = str(frame.get("topic", ""))
        allowed, reason = self.allow_subscribe(session, topic)
        if not allowed:
            self.reject(session, reason, ref="subscribe")
            return
        session.subscriptions.append(topic)
        session.send(make_frame("ack", ref="subscribe", topic=topic))

    def on_publish(self, session, frame):
        """Forward a published payload to every matching subscriber if allowed."""
        topic = str(frame.get("topic", ""))
        allowed, reason = self.allow_publish(session, frame)
        if not allowed:
            self.reject(session, reason, ref="publish")
            return
        with self._lock:
            self.stats["accepted"] += 1
        self.record_traffic(self.sender_name(session), topic, "accepted",
                            json.dumps(frame.get("payload"), default=str))
        self.deliver(topic, frame.get("payload"), self.sender_name(session))

    def on_other(self, session, frame):
        """Reject frame types the broker does not understand."""
        self.reject(session, "unknown frame type")

    # ------------------------------------------------------------------ security hooks
    def allow_subscribe(self, session, topic):
        """INSECURE: anyone may subscribe to anything, even '#' (all traffic)."""
        return True, ""

    def allow_publish(self, session, frame):
        """INSECURE: anyone may publish anything to any topic, as often as they like."""
        return True, ""

    def sender_name(self, session):
        """The name the broker attaches to messages from this client."""
        return session.client_id or "anonymous"

    # ------------------------------------------------------------------ helpers
    def deliver(self, topic, payload, sender):
        """Send a 'message' frame to every client subscribed to a matching pattern."""
        frame = make_frame("message", topic=topic, payload=payload, sender=sender)
        with self._lock:
            targets = [s for s in self.sessions
                       if s.alive and any(topic_matches(p, topic) for p in s.subscriptions)]
        for target in targets:
            target.send(frame)
        with self._lock:
            self.stats["delivered"] += len(targets)

    def reject(self, session, reason, ref=None):
        """Count a rejected frame, remember why, and tell the client."""
        with self._lock:
            self.stats["rejected"] += 1
            self.rejections.append((session.client_id, reason))
        who = session.client_id or session.extra.get("last_claimed") or "unknown"
        self.record_traffic(who, ref or "-", "rejected", reason)
        log.debug("rejected frame from %s: %s", session.client_id, reason)
        session.send(make_frame("error", reason=reason, ref=ref))

    def record_traffic(self, sender, topic, verdict, detail):
        """Add one frame to the live traffic feed (what crossed the gateway, and the verdict)."""
        with self._lock:
            self.totals[verdict] += 1
            self.feed.append({"at": time.time(), "sender": sender, "topic": topic,
                              "verdict": verdict, "detail": detail[:160]})

    def reset_stats(self):
        """Zero the counters (used before each attack so results are separate)."""
        with self._lock:
            self.stats = {"accepted": 0, "rejected": 0, "delivered": 0}
            self.rejections = []
