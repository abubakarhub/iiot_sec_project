# secureTeam_SecureIoT-Sim – Architecture

Smart Building simulation: 8 virtual devices (4 types), a gateway/broker and a
cloud server, all running on one laptop and bound only to `127.0.0.1`.

## Components

```
  8 DEVICES (threads)                 GATEWAY / BROKER              CLOUD SERVER
  temp-01, temp-02                    TCP pub/sub on                Flask REST API + SQLite
  lock-01, lock-02      ──publish──►  127.0.0.1:18830   ──bridge──► /api/login, /api/readings,
  energy-01, energy-02                topics like                   /api/devices, /api/command
  motion-01, motion-02  ◄─commands──  building/floor1/temperature/  /dashboard (HTML)
                                      temp-01
                                            ▲                             ▲
                                            │                             │
                         ATTACKER (module1) ┘── MITM relay, raw sockets ──┘── HTTP brute force / flood
```

| Component | File | Role |
|---|---|---|
| Devices | `core/devices.py` | Temperature sensor, door lock, energy meter, motion sensor |
| Broker | `core/broker.py` | MQTT-style publish/subscribe over TCP (newline-delimited JSON) |
| Cloud bridge | `core/cloud_bridge.py` | Subscribes to `building/#`, stores readings, sends commands |
| Cloud API | `core/cloud_insecure.py` / `module4_cloud/secure_api.py` | REST API for users |
| Database | `core/database.py` | SQLite tables: devices, readings, users, commands, audit_log, alerts |
| Secure broker | `module2_crypto/crypto_broker.py` → `module3_access/secure_broker.py` | Crypto checks, then registry, rate limit (`module3_access/rate_limit.py`) and topic ACL |
| Dashboard | `module4_cloud/templates/dashboard.html` | Devices, latest readings, alerts (shared by both modes) |
| Comparison | `compare.py` | Runs every attack against both modes, writes the comparison table and chart |
| Live simulation | `core/live.py` | `--live`: devices keep publishing; attacks and key actions on demand |
| Control panel | `core/control_panel.py` (port 5050) | Lab/attacker view: live devices, gateway traffic feed, attack buttons. Kept separate from the cloud API on purpose |

## Insecure vs secure mode

**Insecure (baseline):** plain JSON frames, broker accepts any client and any
topic, API has no authentication, plaintext passwords, no rate limiting.

**Secure:** the same components with defences plugged in:

```
Device ──[challenge-response handshake]──► SecureBroker (device registry + revocation list)
Device ──{hdr: id, seq, ts, key_version | AES-GCM(payload) | HMAC-SHA256(hdr)}──► SecureBroker
        SecureBroker: HMAC → timestamp window → seq/nonce cache → topic ACL → rate limit
Cloud  ──{command + ECDSA signature}──► DoorLock (verifies before acting)
User   ──bcrypt login + lockout──► JWT ──► API (validation, rate limit, RBAC)
        ──► SQLite (sensitive fields AES-GCM encrypted)
Every rejection ──► audit log ──► alert rules ──► dashboard
```

## Attack → defence map

| Attack | Success means | Secure-mode defence |
|---|---|---|
| Sniffing | Reading visible in plaintext | AES-GCM (M2) |
| Tampering | Modified value stored by cloud | GCM tag + HMAC (M2) |
| Replay | Captured "unlock" works again | Timestamp window + seq/nonce cache (M2/M3) |
| Spoofing | Fake device's reading stored | Challenge-response + registry (M2/M3) |
| Brute force | Valid login token obtained | bcrypt + lockout + rate limit (M3/M4) |
| Flooding | Flood accepted, legit traffic hurt | Auth + token bucket + alert (M3/M4) |
| Unauthorised command | Viewer unlocks a door | RBAC + topic ACL (M3) |

## Team and ownership (group secureTeam · class IIOT-B2 · IIOT Security, ARI421 · faculty: Mr. Arun Kumar)

| Member | Enrollment no. | Module | Folders |
|---|---|---|---|
| Vansh Dabas | 09519051723 | Module 1: Threats and attacks | `core/`, `module1_attacks/` |
| Sadia Mohd. Khan | 12219051723 | Module 2: Cryptography | `module2_crypto/` |
| Abubakar Siddiqui | 08019051723 | Module 3: Access control and privacy | `module3_access/` |
| Vedant Mishra | 11819051723 | Module 4: Cloud security and case study | `module4_cloud/`, `docs/case_study.md` |
| All | | Integration | `main.py`, `compare.py`, `README.md` |
