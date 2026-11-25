# Security Requirements – secureTeam_SecureIoT-Sim (Smart Building)

**Assets:** door locks (physical access), sensor data (temperature, energy, motion =
occupancy / privacy), user accounts, device keys, the cloud database, and service
availability.

**Attacker model:** someone on the building network (Wi-Fi / LAN) who can listen,
change and inject traffic; an outsider guessing passwords; a hijacked device; and an
insider with a low-privilege (viewer) account. All attacks run only against our own
simulation on `127.0.0.1`.

## Requirements table

| ID | Property | Requirement | Threat / attack it addresses | Insecure baseline | Secure-mode control (module) | Verified by |
|---|---|---|---|---|---|---|
| SR-01 | Confidentiality | Sensor readings and commands must be unreadable to network eavesdroppers. | Sniffing | Plain JSON on the wire | AES-GCM payload encryption (M2) | `sniffing` |
| SR-02 | Integrity | Any change to a message in transit must be detected, and the message dropped. | Tampering | No integrity check | AES-GCM tag + HMAC-SHA256 (M2) | `tampering` |
| SR-03 | Freshness | An old (captured) message must never be accepted a second time. | Replay | No timestamps / nonces | Timestamp window + nonce / sequence cache (M2, M3) | `replay` |
| SR-04 | Device authentication | Only registered devices that prove they hold their secret key may connect. | Spoofing | Broker believes any client id | Challenge-response with per-device keys (M2), device registry (M3) | `spoofing` |
| SR-05 | Non-repudiation / command authenticity | Door locks must act only on commands signed by the cloud. | Forged / spoofed commands | Lock trusts every command | ECDSA P-256 signatures (M2) | `unauthorised_command`, `replay` |
| SR-06 | User authentication | Passwords must be stored salted and hashed, and online guessing must be limited. | Brute force, DB theft | Plaintext passwords, unlimited tries | bcrypt + account lockout (M3), login rate limit (M4) | `brute_force` |
| SR-07 | Authorisation | Users and devices may only do what their role allows (least privilege). | Unauthorised commands, wildcard eavesdropping | No roles, any topic | RBAC admin/operator/viewer (M3), topic-level ACL (M3), JWT (M4) | `unauthorised_command` |
| SR-08 | Availability | A single client must not be able to exhaust the gateway or the API. | Flooding (DoS) | No limits | Token-bucket rate limits at broker (M3) and API (M4) | `flooding_broker`, `flooding_api` |
| SR-09 | Key management | Keys must come from a secure random source, be stored protected, be rotatable, and be revocable. | Key theft, compromised device | No keys at all | `secrets` / `os.urandom`, encrypted keystore, rotation, revocation list (M2) | Phase 3 tests |
| SR-10 | Data protection at rest | Sensitive database fields must be encrypted. | Database theft | Plaintext emails / secrets | AES-GCM field encryption (M4) | Phase 5 check |
| SR-11 | Privacy | Data shared for analytics must not identify individual rooms, devices or people. | Re-identification, profiling | Raw data with real ids | Pseudonymisation, aggregation, differential-privacy noise, k-anonymity (M3) | Privacy graph |
| SR-12 | Accountability | Security-relevant events must be logged, and suspicious patterns must raise alerts. | All attacks (detection) | No logging | Audit log + alert rules + dashboard (M4) | Phase 5 check |
| SR-13 | Input validation | The API must reject malformed or out-of-range input. | Injection, crashes | No validation | Input validation on every endpoint (M4) | Phase 5 check |

## Mapping to the attack tree and fault tree

* `results/attack_tree.png` – every green **[A]** leaf is broken by at least one
  requirement above. For example, "Re-send it; no freshness check" is countered by SR-03,
  and "Claim a trusted id; no device auth" by SR-04.
* `results/fault_tree.png` – security controls (SR-02, SR-03, SR-05, SR-08) remove the
  malicious basic events. The accidental ones (battery, crash, link down) need
  reliability measures and are listed as future work.
