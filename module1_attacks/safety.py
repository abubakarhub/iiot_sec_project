"""
module1_attacks/safety.py - Guard rail: attacks may only target this laptop.

Every attack calls assert_local() before it opens a connection. If someone
changes config.HOST to a real address, the attacks refuse to run.
"""

import ipaddress


def assert_local(host):
    """Raise an error unless host is the loopback address (127.x.x.x / localhost)."""
    if host == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise PermissionError(f"Attack target {host!r} is not localhost - refusing to run. "
                          "Attacks are only allowed against our own simulation.")
