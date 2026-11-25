# Viva preparation: secureTeam · SecureIoT-Sim (class IIOT-B2)

The brief says every member must be able to explain **the whole project** and **their
own module**, line by line. Read Part A together, then your own section in Part B, and
open the files it names while you practise.

## Part A: questions anyone may be asked

| Question | Short answer |
|---|---|
| What does the project do? | It simulates a Smart Building (8 devices, a gateway, a cloud) in Python. We attack it while insecure, secure it, then re-run the same attacks and measure the difference. |
| Are the results faked? | No. Each attack really runs and counts what happened: database rows, lock state, broker counters and HTTP replies (`module1_attacks/common.py` → `make_result`). A crashed attack is reported as ERROR, never as BLOCKED. |
| How do you run it? | `python main.py --mode insecure`, `--mode secure`, `--compare`, or `--mode secure --live` for the browser demo. |
| Why is flooding 2% and 12%, not 0%? | A token bucket lets a short burst through (20 at the gateway), then refuses the rest. That way a normal device is never blocked by a small spike. |
| Why didn't brute force work even with the same weak password? | Lockout after 5 wrong tries (HTTP 423) plus the login rate limit (HTTP 429). We kept `sunshine1` on purpose to prove that the defences, not a changed password, stopped it. |
| Is anything attacked outside your laptop? | No. Everything uses `127.0.0.1`, and `module1_attacks/safety.py` refuses any other address. |
| How did you use AI? | Declared in the report's Appendix B and in `docs/ai_use_log.md`. The code and documents were generated with an AI assistant, then run, checked and studied by us. |
| What is the main limitation? | It is a simulation: there is no real firmware, no internet-scale traffic, and our own message format instead of TLS. See the report's future work. |
| What is the case study? | Mirai (2016): IoT devices hacked with 62 default passwords over Telnet, then used for record DDoS attacks (Dyn, OVH, Krebs). Our brute-force and flooding attacks are small versions of it. |

## Part B: per-member questions

### Vansh Dabas: Module 1, threats and attacks (`core/`, `module1_attacks/`)

| Question | Answer |
|---|---|
| How does the broker work? | `core/broker.py`: a TCP server on port 18830. Each client sends JSON lines (`hello`, `subscribe`, `publish`), and the broker forwards each publish to every matching subscriber (`topic_matches` supports `+` and `#`). |
| How does the MITM attack get between device and gateway? | `module1_attacks/mitm_proxy.py` is a relay on port 18840. `building.reroute()` reconnects a device through it, like an attacker controlling the Wi-Fi. The relay can record, tamper with or inject frames. |
| How is replay measured? | It captures a real "unlock lock-01" frame, waits, re-sends it 5 times, and checks whether `lock.unlock_count` went up. |
| What is in the attack tree? | Goal: unlock lock-01. OR of: forged command, replayed command (AND: path + capture + no freshness), account takeover, impersonating the cloud. |
| Fault tree vs attack tree? | The attack tree models a deliberate attacker. The fault tree models any failure, including accidents (battery, crash, link down). |
| Why 8 attacks when the brief asks for 4? | To cover every security property in the requirements table (confidentiality, integrity, freshness, authentication, authorisation and availability). |

### Sadia Mohd. Khan: Module 2, cryptography (`module2_crypto/`)

| Question | Answer |
|---|---|
| Why AES-GCM and not AES-CBC? | GCM is authenticated encryption: it encrypts *and* detects changes with a 16-byte tag, in one step. CBC needs a separate MAC. |
| Why also an HMAC if GCM has a tag? | The gateway checks the HMAC (separate MAC key) without decrypting. It also binds header and topic, so a frame cannot be moved to another topic. |
| What is the nonce and why must it be unique? | 12 random bytes per message. Re-using a nonce with the same key in GCM breaks both secrecy and integrity. |
| How does challenge-response work? | The gateway sends a random challenge, and the device replies HMAC(auth key, "id\|challenge"). The key is never sent, and a replayed answer fails because the challenge changes every time. |
| Why ECDSA signatures on door commands? | Proof that the cloud sent the command. Even if a forged command reached the lock, the lock verifies the signature, the 30 s age and a never-seen `cmd_id`. |
| How are keys stored, rotated, revoked? | `key_manager.py`: an AES-GCM-encrypted keystore under a master key. Rotation keeps the old key valid for 60 s. Revocation deletes the keys and adds the device to the revocation list. |
| What did the cipher benchmark show? | AES-GCM was 1.2× to 2.5× faster here because of AES-NI. Both add 28 bytes. ChaCha20 is better on chips without AES hardware. |

### Abubakar Siddiqui: Module 3, access control and privacy (`module3_access/`)

| Question | Answer |
|---|---|
| Why bcrypt and not SHA-256 for passwords? | bcrypt is deliberately slow (cost 12, about 0.2 s) and salted, so stolen hashes are expensive to crack. SHA-256 is fast, which helps the attacker. |
| What does the salt do? | It makes the same password hash differently for each user, so precomputed tables do not work. Our test checks that hashing twice gives different hashes. |
| How does lockout work? | `passwords.py` → `LoginGuard`: 5 failures lock the account for 300 s (HTTP 423). Unknown users get the same message and a dummy bcrypt check, so they cannot be told apart. |
| Explain RBAC in your system. | Three roles. viewer: read only. operator: + send commands. admin: + manage users/devices + audit log (`rbac.py`). |
| What is the topic ACL? | `topic_acl.py`: a device may publish only on its own topic, a lock may subscribe only to its own `/cmd` topic, and only the cloud may use `building/#`. |
| Explain the token bucket. | Each client has a bucket of N tokens that refills at R per second. Each message costs one token; with an empty bucket the request is refused. Gateway devices: 20 tokens at 5/s. |
| Your four privacy techniques? | Keyed pseudonyms (HMAC), hourly aggregation, Laplace noise with ε = 0.5 (differential privacy), and k-anonymity with k = 3. Each has before/after numbers in the privacy graph. |
| What does ε mean? | The privacy budget. A smaller ε means more noise and more privacy, but less accuracy. With ε = 0.5 our counts were off by about 1.7 people on average. |

### Vedant Mishra: Module 4, cloud security and case study (`module4_cloud/`, `docs/case_study.*`)

| Question | Answer |
|---|---|
| What is in your JWT? | `sub`, `role`, `iat`, `exp` (15 min), `jti`, `iss`. It is HS256-signed with a random 256-bit secret created at each start. |
| How do you stop the `alg: none` attack? | `jwt.decode(..., algorithms=["HS256"])` accepts only HS256, so an unsigned token is rejected with 401. |
| How does logout work if JWTs are stateless? | The token's `jti` is added to a revoked set and checked on every request. |
| What input validation do you do? | Allow-lists in `validation.py`: device id format, command lock/unlock, limit 1–200, plus a 4 KB body limit (413). |
| What is encrypted in the database? | E-mails and door-lock/motion readings (`enc:v1:` + AES-GCM). Temperature and energy data are not personal, so they stay plain. |
| How do alerts work? | `audit.py`: every security event is logged. Ten rules with a threshold and window (e.g. 5 failed logins in 60 s) create an alert, with a 30 s cooldown. |
| How does the dashboard avoid XSS? | It inserts every value with `textContent`, never `innerHTML`, and keeps the JWT only in memory. |
| How does Mirai compare to our project? | Same weakness as our brute force (default and weak passwords, no lockout) and our floods. Our defences (unique keys, bcrypt, lockout, rate limits, alerts) are what Mirai's victims lacked. |

## Part C: demo script (about 3 minutes)

1. `python main.py --mode insecure --live`, then open http://127.0.0.1:5050.
2. Show the live devices and the readable traffic feed.
3. Click **Run full before/after comparison**. While it runs, explain the busy bar.
4. Point at the **Before vs after** table: 8/8 succeeded, then 6 blocked and 2 limited.
5. Click **Cloud dashboard ↗**, sign in as `admin`, and show the alerts. Sign in as
   `viewer1` and try *unlock*: refused with 403.
6. Click **Stop simulation**.
