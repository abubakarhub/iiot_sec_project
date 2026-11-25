"""
core/devices.py - The 4 types of virtual Smart Building devices.

    TemperatureSensor  publishes room temperature (°C)
    DoorLock           publishes its state AND obeys "lock"/"unlock" commands
    EnergyMeter        publishes power (W) and total energy (kWh)
    MotionSensor       publishes motion yes/no and an occupancy count

Every device is a BrokerClient, so it connects to the gateway and publishes on
its own topic, e.g. building/floor1/temperature/temp-01.
Sensor values come from a seeded random generator so runs are repeatable.
"""

import logging
import random
import time

from config import HOST, BROKER_PORT, command_topic, device_topic
from core.client import BrokerClient

log = logging.getLogger("device")


class Device(BrokerClient):
    """Common behaviour of every device: identity, topic, and publishing readings."""

    device_type = "generic"

    def __init__(self, device_id, location, channel=None, host=HOST, port=BROKER_PORT, seed=0):
        """Create a device with its id, location and a repeatable random generator."""
        super().__init__(device_id, channel=channel, host=host, port=port)
        self.device_id = device_id
        self.location = location
        self.topic = device_topic(device_id, self.device_type, location)
        self.rng = random.Random(seed)
        self.readings_sent = 0
        self.last_reading = None            # shown on the live control panel

    def read_sensor(self):
        """Return this device's current measurement as a dictionary. Subclasses override."""
        raise NotImplementedError

    def publish_reading(self):
        """Take a measurement and publish it on the device's topic."""
        payload = {"device_id": self.device_id,
                   "device_type": self.device_type,
                   "ts": round(time.time(), 3)}
        payload.update(self.read_sensor())
        if self.publish(self.topic, payload):
            self.readings_sent += 1
            self.last_reading = payload
        log.debug("%s -> %s", self.device_id, payload)
        return payload


class TemperatureSensor(Device):
    """Room temperature sensor that drifts slowly around 22 °C."""

    device_type = "temperature"

    def __init__(self, *args, **kwargs):
        """Start at a comfortable room temperature."""
        super().__init__(*args, **kwargs)
        self.current = 21.5 + self.rng.uniform(-1, 1)

    def read_sensor(self):
        """Drift the temperature a little and return it."""
        self.current += self.rng.uniform(-0.3, 0.3)
        return {"temperature_c": round(self.current, 2)}


class EnergyMeter(Device):
    """Electricity meter: instantaneous power and cumulative energy."""

    device_type = "energy"

    def __init__(self, *args, **kwargs):
        """Start the cumulative energy counter at a random value."""
        super().__init__(*args, **kwargs)
        self.total_kwh = round(self.rng.uniform(1000, 5000), 2)

    def read_sensor(self):
        """Return power in watts and total kWh (assuming 15 minutes per reading)."""
        power_w = self.rng.uniform(800, 2500)
        self.total_kwh += power_w / 1000 * 0.25
        return {"power_w": round(power_w, 1), "total_kwh": round(self.total_kwh, 3)}


class MotionSensor(Device):
    """PIR motion sensor that also estimates how many people are in the room."""

    device_type = "motion"

    def read_sensor(self):
        """Return whether motion was seen and a rough occupancy count."""
        motion = self.rng.random() < 0.5
        occupancy = self.rng.randint(1, 6) if motion else 0
        return {"motion": motion, "occupancy": occupancy}


class DoorLock(Device):
    """Smart door lock: reports its state and obeys lock/unlock commands."""

    device_type = "door_lock"

    def __init__(self, *args, **kwargs):
        """Start locked, with an empty command history."""
        super().__init__(*args, **kwargs)
        self.state = "locked"
        self.unlock_count = 0               # attacks check this to see if a door opened
        self.command_log = []               # every command the lock acted on
        self.rejected_commands = 0
        self.cmd_topic = command_topic(self.device_id, self.device_type, self.location)
        # Optional function(payload) -> bool. None means "trust every command"
        # (INSECURE). Module 2 sets this to an ECDSA signature check.
        self.command_verifier = None

    def on_connected(self):
        """As soon as we are accepted, subscribe to our command topic."""
        if not self.subscribe(self.cmd_topic):
            log.warning("%s could not subscribe to %s (%s)",
                        self.device_id, self.cmd_topic, self.last_error)

    def read_sensor(self):
        """Report whether the door is locked and how often it has been unlocked."""
        return {"state": self.state, "unlock_count": self.unlock_count}

    def on_message(self, topic, sender, payload):
        """Carry out a lock/unlock command (after the optional verifier approves it)."""
        command = payload.get("command")
        if command not in ("lock", "unlock"):
            return
        if self.command_verifier is not None and not self.command_verifier(payload):
            self.rejected_commands += 1
            log.info("%s REJECTED command %r from %s (%s)", self.device_id, command, sender,
                     getattr(self.command_verifier, "last_reason", ""))
            return
        self.state = "unlocked" if command == "unlock" else "locked"
        if command == "unlock":
            self.unlock_count += 1
        self.command_log.append({"command": command, "sender": sender,
                                 "issued_by": payload.get("issued_by"), "at": time.time()})
        log.info("%s is now %s (command from %s)", self.device_id, self.state.upper(), sender)
        self.publish_reading()              # report the new state straight away


# Map the type names used in config.DEVICES to the classes above.
DEVICE_CLASSES = {
    "temperature": TemperatureSensor,
    "door_lock": DoorLock,
    "energy": EnergyMeter,
    "motion": MotionSensor,
}


def make_device(device_id, device_type, location, channel=None, seed=0,
                host=HOST, port=BROKER_PORT):
    """Create the right device object for a config.DEVICES entry."""
    cls = DEVICE_CLASSES[device_type]
    return cls(device_id, location, channel=channel, host=host, port=port, seed=seed)
