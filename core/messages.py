"""
core/messages.py - The message ("frame") format used on the simulated network.

Every message is ONE line of JSON followed by a newline, for example:
    {"type": "publish", "topic": "building/floor1/temperature/temp-01", "payload": {...}}

Frame types used in this project:
    hello      client -> broker   "I am <client_id>"
    challenge  broker -> client   (secure mode only) "prove it"
    response   client -> broker   (secure mode only) answer to the challenge
    subscribe  client -> broker   "send me messages on this topic pattern"
    publish    client -> broker   "deliver this payload on this topic"
    message    broker -> client   a delivered publish
    ack        broker -> client   "OK" (for hello / subscribe)
    error      broker -> client   "rejected" + reason
"""

import json


def make_frame(kind, **fields):
    """Create a frame dictionary of the given type with extra fields."""
    frame = {"type": kind}
    frame.update(fields)
    return frame


def encode_frame(frame):
    """Turn a frame dictionary into bytes ready to send (JSON + newline)."""
    text = json.dumps(frame, separators=(",", ":"), sort_keys=True)
    return (text + "\n").encode("utf-8")


def decode_frame(line):
    """Turn one received line (bytes) back into a dictionary, or None if invalid."""
    try:
        frame = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(frame, dict):
        return None
    return frame


def topic_matches(pattern, topic):
    """
    Check if a topic matches a subscription pattern (MQTT-style wildcards).

    '+' matches exactly one level, '#' matches everything below.
    Examples:
        building/+/temperature/#  matches  building/floor1/temperature/temp-01
        building/#                matches  every building topic
    """
    pattern_parts = pattern.split("/")
    topic_parts = topic.split("/")
    for i, part in enumerate(pattern_parts):
        if part == "#":
            return True                      # rest of the topic is accepted
        if i >= len(topic_parts):
            return False                     # topic is shorter than pattern
        if part != "+" and part != topic_parts[i]:
            return False                     # this level does not match
    return len(pattern_parts) == len(topic_parts)
