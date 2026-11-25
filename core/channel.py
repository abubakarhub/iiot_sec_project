"""
core/channel.py - The "channel" decides how a payload is protected on the wire.

Every client (device, cloud bridge) owns a channel object. Before sending, the
client calls channel.wrap(); after receiving, it calls channel.unwrap().

PlainChannel (this file) is the INSECURE baseline: it sends readable JSON and
checks nothing. Module 2 provides a SecureChannel with the same four methods
that adds AES-GCM encryption, HMAC, sequence numbers and challenge-response.
"""


class PlainChannel:
    """Insecure channel: no encryption, no integrity check, no authentication."""

    name = "plain"

    def hello_fields(self, client_id):
        """Extra fields to put in the hello frame. Plain mode sends no proof of identity."""
        return {}

    def answer_challenge(self, client_id, challenge_frame):
        """Plain mode never receives challenges, so there is nothing to answer."""
        return None

    def wrap(self, client_id, topic, payload):
        """Return the payload unchanged - anyone on the network can read it."""
        return payload

    def unwrap(self, sender_id, topic, data):
        """Accept whatever arrived as long as it looks like a dictionary."""
        if isinstance(data, dict):
            return data
        return None
