# secureTeam_SecureIoT-Sim

**A Python-based simulated IoT security framework – Smart Building scenario.**

A software-only Smart Building (8 devices of 4 types, a gateway/broker and a cloud
server) is first run **insecure** and attacked, then run **secure** with cryptography,
access control, privacy techniques and cloud security. The **same attack code** is then
re-run against both versions, and the before/after results are compared.

**Group secureTeam · Class IIOT-B2 · Subject: IIOT Security (ARI421) · Faculty: Mr. Arun Kumar**

| Member | Enrollment no. | Module |
|---|---|---|
| Vansh Dabas | 09519051723 | 1: Threats and attacks |
| Sadia Mohd. Khan | 12219051723 | 2: Cryptography |
| Abubakar Siddiqui | 08019051723 | 3: Access control and privacy |
| Vedant Mishra | 11819051723 | 4: Cloud security and case study |

> **Safety:** everything runs on `127.0.0.1` (this laptop). The attacks only target
> this simulation, and the attack code refuses to contact any other address. No real
> network, website or device is ever touched.

---

## 1. Requirements

* Python **3.9.2 or newer**. Tested on Windows 11 with Python 3.12 and 3.11; the pinned
  libraries also ship wheels for 3.9 and 3.10.
* No hardware, no internet connection after installation, and no admin rights needed.
* Libraries (pinned in `requirements.txt`): `cryptography`, `PyJWT`, `bcrypt`, `Flask`,
  `matplotlib`, `networkx`. Everything else is the Python standard library (`sqlite3`,
  `socket`, `secrets`, `hmac`, ...).

## 2. Installation

**Windows (PowerShell)**
```powershell
cd secureTeam_SecureIoT-Sim
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**macOS / Linux**
```bash
cd secureTeam_SecureIoT-Sim
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 3. Running

| Command | What it does | Time |
|---|---|---|
| `python main.py --mode insecure` | Runs the baseline building, shows its weaknesses, draws the attack and fault trees, runs every attack and writes `results/before.csv`. | ~25 s |
| `python main.py --mode secure` | Runs the secured building with the cipher benchmark and the Module 2, 3 and 4 demos. It then runs every attack, writes `results/after.csv` and lists the alerts the attacks raised. | ~30 s |
| `python main.py --compare` | Runs **all attacks against both modes** in fresh buildings and writes `results/comparison.csv`, `comparison.md` and `before_after.png`. It also regenerates every other file in `results/`. | ~55 s |
| `python main.py --mode secure --live` | **Live simulation in the browser** (see below). Use `--mode insecure --live` for the baseline. | starts in ~3 s, runs until Ctrl+C |
| `python -m unittest discover -s tests -v` | Runs 21 unit tests of the security building blocks. | ~5 s |

### Live simulation (`--live`)

The building keeps running: every device sends a reading every 2 seconds until you
press Ctrl+C. Open two browser tabs:

* **Control panel: http://127.0.0.1:5050.** This is the lab / attacker view. It shows:
  * the 8 devices with their live values;
  * the gateway traffic feed: every frame as it crossed the broker, accepted or
    rejected. You can read the payloads in insecure mode; in secure mode they are
    ciphertext;
  * an **attack lab** with a *Run* button per attack, plus *Run all 8 attacks*. Each
    button runs the same Module 1 code against the running system, and the measured
    result appears in the results table;
  * in secure mode, *rotate key*, *revoke* and *restore* buttons on every device
    (Module 2/3 key management), and the security alerts;
  * an **Insecure · before / Secure · after** switch in the header. It stops the
    running building and starts a fresh one in the other mode on the same ports. The
    dashboard reloads by itself;
  * a **Before vs after** table with the newest measured result of every attack in both
    modes. **Run full before/after comparison** fills it with one click: all 8 attacks
    on insecure, then an automatic switch to secure and all 8 again (~1 minute);
  * header buttons:
    * **☾ Dark mode / ☀ Light mode** (also on the dashboard; your choice is
      remembered);
    * **Pause traffic / Resume traffic** freezes the devices, e.g. while you explain a
      screen;
    * **Stop simulation** shuts everything down, the same as Ctrl+C;
    * **Cloud dashboard ↗** opens the dashboard (which has a matching
      **Control panel ↗** button).
* **Cloud dashboard: http://127.0.0.1:5000/dashboard.** This is the building owner's
  view of the cloud:
  * live readings and alerts;
  * a **door control** card. In secure mode, sign in with a seed test account from
    `config.py`:
    * `admin` sees alerts and can open doors;
    * `operator1` can open doors;
    * `viewer1` can only read. Pressing *unlock* is refused with HTTP 403 (RBAC).

Normal traffic pauses while an attack runs, because each attack generates its own
traffic. That keeps every measured success rate the same as in the batch run.

Useful options:

* `--serve` does the full console run (demos and all attacks) first, then continues
  with the same live simulation as `--live`.
* `--no-attacks` runs only the normal simulation.
* `--rounds N` sets how many readings each device sends (default 5).
* `--verbose` shows every message.

Example: `python main.py --mode secure --live`

### Hosted live demo (Render)

`web_demo.py` runs the same live simulation on one public port: `/panel/` is the
control panel (password-protected; the password comes from the `PANEL_PASSWORD`
environment variable) and `/dashboard` is the cloud dashboard. Stop is disabled
there. Inside the server everything still uses `127.0.0.1`, so the attacks only hit
the simulation. Deploy with `render.yaml`: on render.com choose **New → Blueprint**,
pick this repository, and type a password when asked.

### Vercel

Vercel cannot keep a program running, so the Vercel site (`site/` + `api/run.py`)
runs the project **on demand**: every "Run" click calls `/api/run`, which starts a
fresh building inside the function, runs the real attack against it and returns the
measured result, gateway traffic and alerts. Import the repository on vercel.com and
deploy; `vercel.json` sets everything up.

## 4. Results (`results/`)

| File | Content |
|---|---|
| `before.csv` / `after.csv` | Each attack's attempts, successes, success rate, outcome, the defence observed, and evidence. |
| `comparison.csv` / `comparison.md` | Before vs after for every attack (the Markdown version is ready for the report). |
| `before_after.png` | Bar chart of attack success rate, insecure vs secure. |
| `attack_tree.png` / `fault_tree.png` | Attack tree ("unlock a door without authorisation") and fault tree ("door access control fails"). |
| `cipher_benchmark.png` / `.csv` | AES-256-GCM vs ChaCha20-Poly1305: throughput and bytes on the wire. |
| `privacy_before_after.png` | Aggregation, differential privacy, k-anonymity and pseudonymisation, before vs after. |
| `analytics_export.csv` | Privacy-safe export of the real readings (pseudonymised device ids). |
| `dashboard_secure_admin_*.jpg` | Screenshots of the dashboard after the attacks. |
| `screenshots/1-8_*.jpg` | Before (insecure) and after (secure) screenshots of the live control panel, traffic feed, dashboard and the before-vs-after table. |
| `sample_output_*.txt` | Console output of the three commands from the final test run. |

Typical result of `--compare`:

| Attack | Insecure | Secure | Stopped by |
|---|---|---|---|
| sniffing | 100 % | 0 % | AES-256-GCM payload encryption |
| tampering | 100 % | 0 % | HMAC-SHA256 (+ GCM tag) |
| replay | 100 % | 0 % | sequence numbers + timestamp window (+ signed command ids) |
| spoofing | 100 % | 0 % | challenge-response device authentication |
| brute_force | 100 % | 0 % | bcrypt + account lockout + login rate limit |
| flooding_broker | 100 % | ~2 % | per-device token-bucket rate limit at the gateway |
| flooding_api | 100 % | ~12 % | per-user API rate limit (HTTP 429) |
| unauthorised_command | 100 % | 0 % | JWT + RBAC at the API, topic ACL + device auth at the broker |

The flooding rows show ~2 % and ~12 % rather than 0 % on purpose: a rate limiter
lets a small burst through by design. All numbers are measured from the running
system; none are typed in.

## 5. Project structure (one package per module)

```
secureTeam_SecureIoT-Sim/
├── main.py                 single entry point (--mode insecure | secure, --compare)
├── compare.py              before/after experiment, comparison table + chart
├── config.py               ports, paths, the 8 devices, seed test accounts
├── make_submission_zip.py  builds secureTeam_SecureIoT-Sim.zip without venv / caches
├── core/                   simulated building (insecure baseline)        – Vansh Dabas
│   devices.py  broker.py  client.py  channel.py  messages.py  database.py
│   cloud_bridge.py  cloud_insecure.py  webserver.py  simulation.py  http_util.py  chart_style.py
│   live.py  control_panel.py  templates/control_panel.html   (live simulation + control panel)
├── module1_attacks/        threats & attacks                             – Vansh Dabas
│   sniffing.py  tampering.py  replay.py  spoofing.py  brute_force.py  flooding.py
│   unauthorised_command.py  mitm_proxy.py  attack_runner.py  trees.py  safety.py
├── module2_crypto/         cryptography                                  – Sadia Mohd. Khan
│   aes_gcm.py  integrity.py  signatures.py  keygen.py  key_manager.py
│   challenge_response.py  secure_channel.py  crypto_broker.py  benchmark.py  demo.py
├── module3_access/         access control & privacy                      – Abubakar Siddiqui
│   passwords.py  rbac.py  registry.py  rate_limit.py  topic_acl.py
│   secure_broker.py  privacy.py  demo.py
├── module4_cloud/          cloud security                                – Vedant Mishra
│   secure_api.py  validation.py  field_crypto.py  audit.py  demo.py  templates/dashboard.html
├── tests/                  unit tests (unittest)
├── docs/                   architecture (+ .png), security_requirements, case_study (.md/.docx/.pdf),
│                           report.md (report source), viva_prep.md, requirements_checklist.md, ai_use_log.md
├── results/                generated CSVs, graphs, screenshots, sample outputs
└── deliverables/           secureTeam_SecureIoT-Sim_Report.docx/.pdf, secureTeam_SecureIoT-Sim_Presentation.pptx/.pdf
                            (uploaded separately; not inside the code ZIP)
```

`data/` is created at run time. It holds the SQLite databases, the encrypted keystore and
the master key. It is recreated on every run and is not part of the submission.

## 6. How the system works (short)

* **Network:** devices talk to the broker over TCP on `127.0.0.1:18830` using
  newline-delimited JSON frames, MQTT-style (topics like
  `building/floor1/temperature/temp-01`). The cloud bridge subscribes to `building/#`
  and stores readings in SQLite. The REST API and dashboard run on `127.0.0.1:5000`.
* **Insecure mode:** plain JSON, no authentication, any topic allowed, plaintext
  passwords, a forgeable token, no limits.
* **Secure mode:**
  * Devices prove their identity with challenge-response.
  * Every message is an envelope: AES-256-GCM ciphertext, HMAC-SHA256, sequence
    number, timestamp and key version.
  * The broker checks registry status, then the rate limit, then the topic ACL, then
    the crypto checks.
  * Door commands are ECDSA-signed.
  * Keys live in an encrypted keystore with rotation and revocation.
  * Users have bcrypt hashes, account lockout and roles (RBAC).
  * The API uses JWTs, input validation and rate limits.
  * Sensitive database fields are encrypted.
  * Every rejection is audit-logged and can raise an alert on the dashboard.
* See `docs/architecture.md` and `docs/security_requirements.md` for details.

## 7. Test accounts

The seed accounts in `config.py` are **made-up test values** for this simulation only.
`operator1` deliberately has a weak password from the attacker's wordlist. The *same*
password is used in secure mode, so if brute force fails there, it is because of the
real defences, not a changed password. New accounts in secure mode must pass the
password policy.

## 8. Submission ZIP

```powershell
python make_submission_zip.py
```
This writes `secureTeam_SecureIoT-Sim.zip` next to the project folder. It contains the code,
README, requirements, docs and results. It leaves out `venv/`, `__pycache__/`, `data/`
and `deliverables/`; the report and slides are uploaded as separate files.

## 9. Troubleshooting

* **"Address already in use" / port error:** another program (or a previous run still
  open with `--live` / `--serve`) is using port 18830, 18840, 5000 or 5050. Close it, or
  change `BROKER_PORT`, `MITM_PORT`, `CLOUD_PORT` and `PANEL_PORT` in `config.py`.
* **operator1 cannot sign in after the brute-force attack:** that is the lockout working.
  It clears after 5 minutes or when you restart the program.
* **Windows firewall pop-up:** the program only listens on `127.0.0.1`, so allowing
  or cancelling makes no difference.
* **`Activate.ps1` is blocked:** run
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that PowerShell
  window, or call `.\venv\Scripts\python.exe main.py ...` directly.

## 10. Known limitations (honest notes)

* The privacy graph uses small generated datasets: a 24-hour energy curve, room
  counts, and a door-access log of made-up employees. The short simulation doesn't
  produce enough data for it. `analytics_export.csv` uses the real readings.
* Flooding runs on localhost, so the honest sensor's traffic still arrives even in the
  insecure run. "Success" for flooding means the system accepted the flood without
  any limit.
* The JWT secret and the dashboard session are regenerated whenever the cloud starts
  (fine for a simulation; a real system would keep the secret in the key vault).
* Seed accounts are treated as legacy accounts and skip the password policy (see §7).

## 11. AI-use declaration

This project was generated with an AI assistant (Claude Code), phase by phase, and then
run, checked and studied by the group. The case study, report and slides were also
drafted with it. `docs/ai_use_log.md` lists every file and how it was produced, and the
signed declaration is Appendix B of the report.
