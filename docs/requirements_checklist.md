# Brief → Project Checklist

Every requirement from `IoT_Security_Project.pdf`, where it is implemented, and how to
show it during the demo. ✅ = done in the code, ⬜ = still to be done by the group.

How to see things live:

* **Console**: `python main.py --mode insecure`, `--mode secure`, or `--compare`
* **Live in the browser**: `python main.py --mode secure --live` (or `--mode insecure --live`),
  then open the control panel http://127.0.0.1:5050 and the dashboard http://127.0.0.1:5000/dashboard
* **Files**: everything listed under `results/` is created by those runs

## 1. Objective and scenario

| ✓ | Requirement | Where / how to show it |
|---|---|---|
| ✅ | Software-simulated IoT system: virtual sensors, gateway/broker, cloud server | `core/devices.py`, `core/broker.py`, `core/cloud_bridge.py` + Flask API |
| ✅ | Smart Building, ≥ 4 device types, ≥ 8 devices | 4 types × 2 = 8 devices (`config.py` → `DEVICES`); dashboard "Devices" table |
| ✅ | Attack it while unsecured | `--mode insecure`: every attack prints `SUCCEEDED` |
| ✅ | Secure it (crypto, access control, privacy, cloud security) | `--mode secure`: Module 2, 3 and 4 demo sections in the console |
| ✅ | Before/after comparison showing attacks are blocked | `--compare` → `results/comparison.csv`, `comparison.md`, `before_after.png` |
| ✅ | Entirely Python, no hardware | Python 3.9+; runs on one laptop on `127.0.0.1` |

## 2. Module 1: Threats and Attacks (6 marks)

| ✓ | Requirement | Where / how to show it |
|---|---|---|
| ✅ | Baseline (insecure) system | `--mode insecure`: plain JSON, no auth, plaintext passwords (console "baseline weaknesses") |
| ✅ | Security requirements table | `docs/security_requirements.md` (SR-01 … SR-13) |
| ✅ | One attack tree | `results/attack_tree.png` (`module1_attacks/trees.py`) |
| ✅ | One fault tree | `results/fault_tree.png` |
| ✅ | ≥ 4 simulated attacks | **8 attacks**: sniffing, tampering, replay, spoofing, brute force, broker flooding, API flooding, unauthorised command (`module1_attacks/`) |
| ✅ | Record the "before" results | `results/before.csv` |

## 3. Module 2: Cryptography (7 marks)

| ✓ | Requirement | Where / how to show it |
|---|---|---|
| ✅ | AES encryption of messages | AES-256-GCM, `module2_crypto/aes_gcm.py`; console "on the wire: … ct" |
| ✅ | SHA-256 / HMAC for integrity | `module2_crypto/integrity.py`; tampering attack → "HMAC check failed" |
| ✅ | Digital signatures (RSA or ECDSA) | ECDSA P-256 signed door commands, `module2_crypto/signatures.py` |
| ✅ | Secure random key generation | `secrets` / `os.urandom` + HKDF, `module2_crypto/keygen.py` |
| ✅ | Key management: storage | Encrypted keystore `data/keystore.enc` (console: "key bytes visible in file: none") |
| ✅ | Key management: rotation | Console: "temp-01 key rotated v1 -> v2" |
| ✅ | Key management: revocation | Console: "motion-02 revoked … reconnect refused" |
| ✅ | Challenge-response device authentication | `module2_crypto/challenge_response.py`; spoofing attack → "challenge-response failed" |
| ✅ | Compare two ciphers (speed and size graph) | AES-256-GCM vs ChaCha20-Poly1305 → `results/cipher_benchmark.png` / `.csv` |

## 4. Module 3: Access Control and Privacy (7 marks)

| ✓ | Requirement | Where / how to show it |
|---|---|---|
| ✅ | Device registration and revocation | `module3_access/registry.py`; revoked device refused at the broker |
| ✅ | User registration and revocation | `registry.py` (register user with password policy, deactivate user) |
| ✅ | Salted password hashing | bcrypt cost 12, `module3_access/passwords.py`; console shows `$2b$12$…` hash |
| ✅ | Role-based access control | admin / operator / viewer, `module3_access/rbac.py`; viewer → HTTP 403 on commands |
| ✅ | Pub/sub broker with topic-level permissions | `module3_access/topic_acl.py` + `secure_broker.py`; device can only publish on its own topic |
| ✅ | ≥ 3 privacy techniques | **4**: pseudonymisation, aggregation, Laplace noise (differential privacy), k-anonymity (`module3_access/privacy.py`) |
| ✅ | Before/after privacy graph | `results/privacy_before_after.png` |

## 5. Module 4: Cloud Security and Case Study (6 marks)

| ✓ | Requirement | Where / how to show it |
|---|---|---|
| ✅ | REST API with Flask + SQLite | `module4_cloud/secure_api.py`, `core/database.py` |
| ✅ | API authentication | JWT (PyJWT, HS256, 15-min expiry); forged `alg: none` token rejected |
| ✅ | Input validation | `module4_cloud/validation.py`; console: SQL-injection id → HTTP 400 |
| ✅ | Rate limiting | Token bucket per user / login → HTTP 429 |
| ✅ | Encrypted storage | Emails and door/motion readings stored as `enc:v1:…` (AES-GCM) in SQLite |
| ✅ | Audit log and alerts | `module4_cloud/audit.py`; alerts printed in the console and shown on the dashboard |
| ✅ | Simple dashboard | http://127.0.0.1:5000/dashboard: live readings, door control (RBAC-checked), alerts for admin |
| ✅ | Study of one real IoT security incident compared with the project | Mirai botnet (2016): `docs/case_study.md` / `.docx` / `.pdf`, also Chapter 8 of the report. ⬜ Group to review the AI draft |

## 6. Integration (4 marks)

| ✓ | Requirement | Where / how to show it |
|---|---|---|
| ✅ | One entry point `python main.py --mode insecure / --mode secure` | `main.py` |
| ✅ | All attacks re-run on the secured system | Same attack code runs in both modes; `--compare` runs both back to back |
| ✅ | Before/after table or graph | `results/comparison.md` (table) + `results/before_after.png` (graph) |
| ✅ | Live demo | `--live`: devices keep sending; launch any attack from the control panel (port 5050) and watch it succeed (insecure) or get blocked (secure). The header switch flips between insecure and secure, and the before-vs-after table (or the one-click full comparison) shows both. Screenshots: `results/screenshots/` |
| ✅ | Clean commented code | Every function has a docstring; one package per module |
| ✅ | README and requirements.txt | `README.md`, `requirements.txt` (pinned versions) |

## 7. Submission requirements

| ✓ | Requirement | Status |
|---|---|---|
| ✅ | Files named GroupNo_ProjectName | `secureTeam_SecureIoT-Sim` (group name: secureTeam) |
| ✅ | ZIP of the code | `python make_submission_zip.py` → `secureTeam_SecureIoT-Sim.zip` |
| ✅ | Complete source, README with install/run steps, requirements.txt | Included |
| ✅ | Sample outputs or screenshots | `results/sample_output_*.txt`, `results/dashboard_secure_admin_*.jpg`, all graphs |
| ✅ | Runs on Python 3.9+ without errors | Tested clean install on 3.12 and 3.11; libraries support 3.9. ⬜ Optional: one run on real 3.9 |
| ✅ | No virtual-environment or cache folders in the ZIP | Script skips `venv/`, `__pycache__/`, `data/` |
| ✅ | **Report** (abstract, intro, background, design + diagram, one chapter per module, case study, testing, before/after, conclusion, references, appendix with contributions + AI declaration) | `deliverables/secureTeam_SecureIoT-Sim_Report.docx` / `.pdf` (36 pages, 13 figures). ⬜ Review, and sign Appendix B |
| ✅ | **PPT** (≤ 6 lines per slide, each member presents own module) | `deliverables/secureTeam_SecureIoT-Sim_Presentation.pptx` / `.pdf` (24 slides; a divider per member; speaker notes name the presenter) |

## 8. Rules

| ✓ | Rule | Status |
|---|---|---|
| ✅ | No hardware, runs on a normal laptop | Yes |
| ✅ | Attacks only on your own simulated system | All attacks call `assert_local()` and refuse any address except `127.0.0.1` |
| ✅ | AI use declared | `docs/ai_use_log.md` lists every file; declaration in Appendix B of the report (⬜ sign it) |
| ⬜ | Every line explainable in the viva | `docs/viva_prep.md`: questions and answers per member + demo script. Each member studies their own folder |
| ✅ | Suggested libraries only | cryptography, PyJWT, bcrypt, Flask, sqlite3, matplotlib, networkx + stdlib |

## Summary

* **Everything the brief asks for now exists:** code, case study, report and PPT, with the
  team's names (class IIOT-B2) throughout.
* **Left for the group:**
  * read and review the AI-drafted documents;
  * sign Appendix B;
  * practise the viva (`docs/viva_prep.md`);
  * one member submits the ZIP, report and PPT on GC before the deadline.
