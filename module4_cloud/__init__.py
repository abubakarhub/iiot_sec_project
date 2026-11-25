"""
module4_cloud - Cloud security for the Smart Building.

    secure_api.py   Flask REST API: JWT auth, RBAC, input validation, rate limiting
    validation.py   strict checks on every request body / query parameter
    field_crypto.py AES-GCM encryption of sensitive database fields
    audit.py        audit log + alert rules for suspicious events
    demo.py         cloud-security demo printed by main.py
    templates/      the web dashboard (devices, readings, alerts)
"""
