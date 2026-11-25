"""
module3_access/topic_acl.py - Topic-level permissions for the pub/sub broker.

Least privilege for every client:
    a device   may PUBLISH only on its own topic   building/<loc>/<type>/<id>
               may SUBSCRIBE only to its own commands building/<loc>/<type>/<id>/cmd
    the cloud  may PUBLISH only commands            building/+/+/+/cmd
               may SUBSCRIBE to all building data   building/#
    anyone else: nothing (default deny)

So a hacked temperature sensor cannot fake an energy meter's readings,
cannot send door commands, and cannot subscribe to '#' to eavesdrop.
"""

from config import DEVICES, command_topic, device_topic
from core.messages import topic_matches


def _is_wildcard(pattern):
    """True if a topic pattern contains MQTT wildcards."""
    return "+" in pattern or "#" in pattern


class TopicACL:
    """Allow-list of publish / subscribe patterns per client id."""

    def __init__(self, devices=DEVICES):
        """Build the default rules for every device in config plus the cloud."""
        self.rules = {"cloud": {"publish": ["building/+/+/+/cmd"],
                                "subscribe": ["building/#"]}}
        for device_id, device_type, location in devices:
            self.rules[device_id] = {
                "publish": [device_topic(device_id, device_type, location)],
                "subscribe": [command_topic(device_id, device_type, location)],
            }

    def can_publish(self, client_id, topic):
        """True if client_id may publish on this exact topic."""
        if _is_wildcard(topic):
            return False
        allowed = self.rules.get(client_id, {}).get("publish", [])
        return any(topic_matches(pattern, topic) for pattern in allowed)

    def can_subscribe(self, client_id, pattern):
        """
        True if the requested pattern is no wider than an allowed one:
        either identical to an allowed pattern, or a plain topic inside one.
        """
        allowed = self.rules.get(client_id, {}).get("subscribe", [])
        for rule in allowed:
            if pattern == rule:
                return True
            if not _is_wildcard(pattern) and topic_matches(rule, pattern):
                return True
        return False
