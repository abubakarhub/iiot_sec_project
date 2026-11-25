"""
core/simulation.py - Builds and runs the whole Smart Building.

SmartBuilding wires everything together for one mode:
    database  ->  broker  ->  cloud bridge  ->  cloud API  ->  8 devices

Usage:
    with SmartBuilding("insecure") as building:
        building.start()
        building.run_rounds(5)

The attacks in Module 1 receive this object so they can reach the broker,
the devices and the database of the running system.
"""

import logging
import os
import time

import config
from core.broker import InsecureBroker
from core.channel import PlainChannel
from core.cloud_bridge import CloudBridge
from core.cloud_insecure import create_insecure_app
from core.database import Database
from core.devices import make_device
from core.webserver import ServerThread

log = logging.getLogger("simulation")


class SmartBuilding:
    """One complete simulated system (insecure or secure)."""

    def __init__(self, mode="insecure"):
        """Create every component for the chosen mode (nothing starts yet)."""
        if mode not in ("insecure", "secure"):
            raise ValueError("mode must be 'insecure' or 'secure'")
        self.mode = mode
        self.stopped = False
        self.api_url = f"http://{config.HOST}:{config.CLOUD_PORT}"
        os.makedirs(config.DATA_DIR, exist_ok=True)

        # 1. Fresh database with the registered devices and seed users.
        self.db = Database(config.db_path(mode))
        self.db.reset()
        for device_id, device_type, location in config.DEVICES:
            self.db.add_device(device_id, device_type, location,
                               config.device_topic(device_id, device_type, location))

        if mode == "insecure":
            self._build_insecure()
        else:
            self._build_secure()

    # ------------------------------------------------------------------ builders
    def _build_insecure(self):
        """Wire up the baseline: plain channels, insecure broker and insecure API."""
        for username, password, role, email in config.SEED_USERS:
            self.db.add_user(username, password, role, email)        # PLAINTEXT!

        self.broker = InsecureBroker(config.HOST, config.BROKER_PORT)
        self.bridge = CloudBridge(self.db, channel=PlainChannel())
        self.web = ServerThread(create_insecure_app(self.db, self.bridge),
                                config.HOST, config.CLOUD_PORT)
        self.devices = [make_device(dev_id, dev_type, loc, channel=PlainChannel(), seed=i)
                        for i, (dev_id, dev_type, loc) in enumerate(config.DEVICES)]

    def _build_secure(self):
        """
        Wire up the secured system. Defences come from the module packages:
          Module 2: keys, SecureChannel (AES-GCM + HMAC + seq/ts), challenge-response,
                    CryptoBroker, ECDSA-signed door commands
          Module 3: registry, bcrypt users + lockout, SecureBroker (topic ACL, rate limit)
          Module 4: secure REST API (JWT, validation, rate limit), encrypted DB fields,
                    audit log + alerts, dashboard
        """
        from module2_crypto.key_manager import KeyManager, load_or_create_master_key
        from module2_crypto.secure_channel import DeviceKeyring, SecureChannel
        from module2_crypto.signatures import CommandSigner, CommandVerifier
        from module3_access.passwords import LoginGuard
        from module3_access.registry import Registry
        from module3_access.secure_broker import SecureBroker
        from module4_cloud.audit import AuditLog
        from module4_cloud.field_crypto import FieldCipher, derive_field_key
        from module4_cloud.secure_api import create_secure_app

        # Key vault: one random key per device + the cloud, stored encrypted.
        master_key = load_or_create_master_key(os.path.join(config.DATA_DIR, "master.key"))
        self.key_manager = KeyManager(os.path.join(config.DATA_DIR, "keystore.enc"), master_key)
        self.key_manager.provision("cloud")
        signing_key = self.key_manager.signing_key()       # cloud's ECDSA private key
        cloud_public_key = signing_key.public_key()        # given to every door lock

        # Encrypted storage (Module 4): e-mails and sensitive readings are AES-GCM
        # encrypted in the database with a key derived from the master key.
        self.field_cipher = FieldCipher(derive_field_key(master_key))
        self.db.field_cipher = self.field_cipher
        self.audit = AuditLog(self.db)

        # Users: bcrypt-hashed through the registry. The seed accounts are treated
        # as legacy accounts imported from the old system, so the password policy is
        # not applied to them (operator1 keeps its weak password on purpose - see config).
        self.registry = Registry(self.db, self.key_manager, encrypt_field=self.field_cipher.encrypt)
        for username, password, role, email in config.SEED_USERS:
            self.registry.register_user(username, password, role, email, enforce_policy=False)
        self.login_guard = LoginGuard(self.db)

        self.broker = SecureBroker(self.key_manager, self.db, host=config.HOST,
                                   port=config.BROKER_PORT)
        self.broker.on_security_event = self.audit.on_broker_event      # gateway -> audit log
        self.bridge = CloudBridge(self.db, channel=SecureChannel("cloud", self.key_manager.lookup))
        self.bridge.command_signer = CommandSigner(signing_key)
        self.web = ServerThread(create_secure_app(self.db, self.bridge, self.login_guard,
                                                  self.registry, self.audit, self.field_cipher),
                                config.HOST, config.CLOUD_PORT)

        self.devices = []
        self.keyrings = {}                                 # the key stored inside each device
        for i, (dev_id, dev_type, loc) in enumerate(config.DEVICES):
            version, key = self.key_manager.provision(dev_id)
            self.keyrings[dev_id] = DeviceKeyring(dev_id, version, key)
            device = make_device(dev_id, dev_type, loc,
                                 channel=SecureChannel(dev_id, self.keyrings[dev_id]), seed=i)
            if dev_type == "door_lock":
                device.command_verifier = CommandVerifier(cloud_public_key)
            self.devices.append(device)

    # ------------------------------------------------------------------ key management (secure)
    def rotate_device_key(self, device_id):
        """Rotate a device key (registry + vault) and install the new key on the device."""
        version, key = self.registry.rotate_device_key(device_id)
        self.keyrings[device_id].install(version, key)
        return version

    def revoke_device(self, device_id, reason="revoked by admin"):
        """Revoke a device through the registry and disconnect it from the gateway."""
        self.registry.revoke_device(device_id, reason)
        self.broker.kick(device_id)

    def reprovision_device(self, device_id):
        """Register a (replacement) device again with a brand-new key and reconnect it."""
        entry = next(d for d in config.DEVICES if d[0] == device_id)
        version, key = self.registry.register_device(*entry)
        self.keyrings[device_id].install(version, key)
        return self.device(device_id).connect()

    # ------------------------------------------------------------------ lifecycle
    def start(self):
        """Start broker, cloud and connect all devices. Returns number of devices online."""
        self.broker.start()
        if not self.bridge.connect():
            raise RuntimeError(f"cloud bridge could not connect: {self.bridge.last_error}")
        self.web.start()
        online = 0
        for device in self.devices:
            if device.connect():
                online += 1
            else:
                log.warning("%s failed to connect: %s", device.device_id, device.last_error)
        log.info("%d/%d devices online (%s mode)", online, len(self.devices), self.mode)
        return online

    def run_rounds(self, rounds=config.SIM_ROUNDS, delay=0.05):
        """Every device publishes one reading per round. Returns readings stored by the cloud."""
        start_count = self.bridge.received
        for _ in range(rounds):
            for device in self.devices:
                device.publish_reading()
            time.sleep(delay)
        expected = start_count + rounds * len(self.devices)
        return self.bridge.wait_for_readings(expected) - start_count

    def stop(self):
        """Disconnect devices and shut down cloud and broker (safe to call twice)."""
        if self.stopped:
            return
        self.stopped = True
        for device in self.devices:
            device.close()
        self.bridge.close()
        self.web.stop()
        self.broker.stop()

    # ------------------------------------------------------------------ helpers
    def reroute(self, client, port):
        """
        Reconnect a device or the cloud bridge through a different port.

        Module 1 uses this to put a client "behind" the attacker's relay
        (like an attacker controlling the Wi-Fi access point), and to put it
        back afterwards. Returns True if the broker accepted the reconnection.
        """
        client.close()
        time.sleep(0.05)
        client.port = port
        return client.connect()

    def device(self, device_id):
        """Find a device object by its id."""
        return next(d for d in self.devices if d.device_id == device_id)

    def __enter__(self):
        """Allow 'with SmartBuilding(...) as b:' so stop() always runs."""
        return self

    def __exit__(self, exc_type, exc, tb):
        """Stop everything when the 'with' block ends (even after an error)."""
        try:
            self.stop()
        except Exception as err:                     # never hide the original error
            log.warning("error during shutdown: %s", err)
        return False
