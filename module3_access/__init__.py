"""
module3_access - Access control and privacy for the secure Smart Building.

    passwords.py     bcrypt salted hashing, password policy, account lockout
    rbac.py          roles (admin / operator / viewer) and their permissions
    registry.py      register and revoke users and devices
    rate_limit.py    token-bucket rate limiter (also used by Module 4's API)
    topic_acl.py     which client may publish / subscribe to which topic
    secure_broker.py broker = Module 2 crypto checks + registry + ACL + rate limit
    privacy.py       pseudonymisation, aggregation, differential privacy, k-anonymity
    demo.py          access-control and privacy demo printed by main.py
"""
