"""
module1_attacks - Threats and attacks against the simulated Smart Building.

Every attack is a function run(building) that really executes against the
running system (insecure OR secure) and measures what actually happened.
Nothing here is hardcoded: results come from the database, the devices and
the replies of the broker / API.

SAFETY: all attacks are limited to 127.0.0.1 (see safety.py).
"""
