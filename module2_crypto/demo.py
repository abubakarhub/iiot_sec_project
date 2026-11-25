"""
module2_crypto/demo.py - Shows Module 2 working inside the running secure building.

Printed by main.py --mode secure:
  1. what a protected message looks like on the wire
  2. the key vault on disk is encrypted (no key bytes visible in the file)
  3. key ROTATION: temp-01 gets key v2 and keeps working
  4. key REVOCATION: motion-02 is revoked, kicked off and refused; then a
     replacement is re-registered with a fresh key
"""

import json
import time


def _count_new(building, device_id, last_id):
    """Return how many readings of a device were stored after last_id."""
    return len(building.db.readings_after(last_id, device_id))


def show_envelope(building):
    """Print an example envelope exactly as it travels to the gateway."""
    device = building.device("temp-01")
    envelope = device.channel.wrap(device.device_id, device.topic,
                                   {"device_id": "temp-01", "temperature_c": 22.4})
    text = json.dumps(envelope)
    print(f"  on the wire: {text[:150]}...")
    print(f"  ({len(text)} bytes; reading is inside 'ct', AES-256-GCM; 'mac' is HMAC-SHA256)")


def show_keystore_encrypted(building):
    """Prove the key file contains no readable key material."""
    km = building.key_manager
    with open(km.store_path, encoding="utf-8") as handle:
        on_disk = handle.read()
    leaked = [dev for dev in km.devices
              if km.lookup(dev) and km.lookup(dev)[1].hex() in on_disk]
    print(f"  keystore.enc: {len(on_disk)} bytes, {len(km.devices)} device keys inside, "
          f"key bytes visible in file: {'YES' if leaked else 'none'}")
    km.load()                                   # decrypt + integrity check round trip
    print("  keystore decrypts and passes its AES-GCM integrity check: yes")


def show_rotation(building):
    """Rotate temp-01's key and show the device keeps working with the new version."""
    device = building.device("temp-01")
    old = building.key_manager.lookup("temp-01")[0]
    new = building.rotate_device_key("temp-01")
    last_id = building.db.last_reading_id()
    device.publish_reading()
    time.sleep(0.3)
    stored = _count_new(building, "temp-01", last_id)
    print(f"  temp-01 key rotated v{old} -> v{new}; reading sent with v{new} "
          f"stored by cloud: {'yes' if stored else 'NO'}")


def show_revocation(building):
    """Revoke motion-02, show it is refused, then re-register a replacement."""
    device = building.device("motion-02")
    building.revoke_device("motion-02", "device reported stolen")
    time.sleep(0.2)
    print(f"  motion-02 revoked -> still connected: {'yes' if device.connected else 'no'}")
    accepted = device.connect()
    print(f"  motion-02 tries to reconnect -> {'ACCEPTED' if accepted else 'refused'}"
          f" ({device.last_error})")
    print(f"  revocation list: {[r['device_id'] for r in building.key_manager.revocation_list]}")

    ok = building.reprovision_device("motion-02")
    last_id = building.db.last_reading_id()
    device.publish_reading()
    time.sleep(0.3)
    stored = _count_new(building, "motion-02", last_id)
    version = building.key_manager.lookup("motion-02")[0]
    print(f"  replacement motion-02 registered with key v{version}: connected="
          f"{'yes' if ok else 'no'}, reading stored={'yes' if stored else 'NO'}")


def run(building):
    """Run all Module 2 demonstrations against a running secure building."""
    show_envelope(building)
    show_keystore_encrypted(building)
    show_rotation(building)
    show_revocation(building)
