# AI Use Log

This file records which parts of the project were generated with an AI
assistant (Claude Code, model Claude Opus 5.5), so the group can write an
honest originality / AI-use declaration. Every listed file must still be read,
understood and explainable by the group member who owns it.

Status key: **AI-generated** = written by the AI, reviewed by us;
**Edited** = AI draft changed by us; **Ours** = written by us.

| Phase | File / part | Status | Owner | Notes |
|---|---|---|---|---|
| 0 | Folder structure and architecture plan (`docs/architecture.md`) | AI-generated | All | Plan proposed by AI, approved by group |
| 1 | `config.py` | AI-generated | All | Ports, paths, device list, seed test users |
| 1 | `.gitignore`, `requirements.txt` | AI-generated | All | Versions checked for Python 3.9 wheels |
| 1 | `core/messages.py` | AI-generated | Vansh Dabas | Frame format + topic wildcard matching |
| 1 | `core/channel.py` | AI-generated | Vansh Dabas | Plain (insecure) channel |
| 1 | `core/broker.py` | AI-generated | Vansh Dabas | Insecure pub/sub broker |
| 1 | `core/devices.py` | AI-generated | Vansh Dabas | 4 device types |
| 1 | `core/database.py` | AI-generated | Vansh Dabas | SQLite schema + helpers |
| 1 | `core/cloud_bridge.py` | AI-generated | Vansh Dabas | Broker → database bridge |
| 1 | `core/cloud_insecure.py` | AI-generated | Vansh Dabas | Insecure Flask API |
| 1 | `core/webserver.py` | AI-generated | Vansh Dabas | Runs Flask in a background thread |
| 1 | `core/simulation.py` | AI-generated | Vansh Dabas | Builds and runs the whole building |
| 1 | `main.py` | AI-generated | All | Entry point |
| 2 | `core/client.py`, `core/simulation.py`, `core/database.py` (edits) | AI-generated | Vansh Dabas | Reconnect / reroute support, `readings_after()` |
| 2 | `module1_attacks/safety.py` | AI-generated | Vansh Dabas | Localhost-only guard |
| 2 | `module1_attacks/common.py` | AI-generated | Vansh Dabas | Result format, helpers |
| 2 | `module1_attacks/mitm_proxy.py` | AI-generated | Vansh Dabas | Record / tamper / inject relay |
| 2 | `module1_attacks/sniffing.py`, `tampering.py`, `replay.py`, `spoofing.py` | AI-generated | Vansh Dabas | Network attacks |
| 2 | `module1_attacks/brute_force.py`, `flooding.py`, `unauthorised_command.py` | AI-generated | Vansh Dabas | API / DoS / privilege attacks |
| 2 | `module1_attacks/wordlist.txt` | AI-generated | Vansh Dabas | 99 common passwords |
| 2 | `module1_attacks/attack_runner.py` | AI-generated | Vansh Dabas | Runs all attacks, writes CSV |
| 2 | `module1_attacks/trees.py` | AI-generated | Vansh Dabas | Attack tree + fault tree PNGs (tree content proposed by AI) |
| 2 | `docs/security_requirements.md` | AI-generated | Vansh Dabas | Requirements table SR-01..SR-13 |
| 3 | `core/chart_style.py` | AI-generated | All | Shared colour-blind-safe chart style |
| 3 | `module2_crypto/keygen.py` | AI-generated | Sadia Mohd. Khan | `secrets`/`os.urandom` keys, HKDF sub-keys, ECDSA key |
| 3 | `module2_crypto/aes_gcm.py` | AI-generated | Sadia Mohd. Khan | AES-256-GCM encrypt/decrypt |
| 3 | `module2_crypto/integrity.py` | AI-generated | Sadia Mohd. Khan | SHA-256, HMAC-SHA256, constant-time compare |
| 3 | `module2_crypto/signatures.py` | AI-generated | Sadia Mohd. Khan | ECDSA P-256 signed door commands |
| 3 | `module2_crypto/key_manager.py` | AI-generated | Sadia Mohd. Khan | Encrypted keystore, rotation, revocation |
| 3 | `module2_crypto/challenge_response.py` | AI-generated | Sadia Mohd. Khan | HMAC challenge-response |
| 3 | `module2_crypto/secure_channel.py` | AI-generated | Sadia Mohd. Khan | Envelope format (AES-GCM + HMAC + seq + ts) |
| 3 | `module2_crypto/crypto_broker.py` | AI-generated | Sadia Mohd. Khan | Broker enforcing auth / integrity / freshness |
| 3 | `module2_crypto/benchmark.py` | AI-generated | Sadia Mohd. Khan | AES-GCM vs ChaCha20-Poly1305 graph |
| 3 | `module2_crypto/demo.py` | AI-generated | Sadia Mohd. Khan | Rotation / revocation demo |
| 3 | `core/simulation.py`, `core/devices.py`, `main.py` (edits) | AI-generated | All | Secure-mode wiring |
| 4 | `module3_access/passwords.py` | AI-generated | Abubakar Siddiqui | bcrypt, password policy, lockout (LoginGuard) |
| 4 | `module3_access/rbac.py` | AI-generated | Abubakar Siddiqui | Roles and permission matrix |
| 4 | `module3_access/registry.py` | AI-generated | Abubakar Siddiqui | User / device registration and revocation |
| 4 | `module3_access/rate_limit.py` | AI-generated | Abubakar Siddiqui | Token bucket (also used by Module 4) |
| 4 | `module3_access/topic_acl.py` | AI-generated | Abubakar Siddiqui | Topic-level publish/subscribe permissions |
| 4 | `module3_access/secure_broker.py` | AI-generated | Abubakar Siddiqui | Registry + rate limit + ACL on top of CryptoBroker |
| 4 | `module3_access/privacy.py` | AI-generated | Abubakar Siddiqui | Pseudonymisation, aggregation, Laplace DP, k-anonymity + graph |
| 4 | `module3_access/demo.py` | AI-generated | Abubakar Siddiqui | Access-control and privacy demo |
| 4 | `core/database.py`, `core/cloud_insecure.py`, `core/simulation.py`, `module2_crypto/crypto_broker.py`, `main.py` (edits) | AI-generated | All | Login-state columns, pluggable password check, Module 3 wiring |
| 5 | `module4_cloud/secure_api.py` | AI-generated | Vedant Mishra | JWT, RBAC enforcement, validation, rate limits, headers |
| 5 | `module4_cloud/validation.py` | AI-generated | Vedant Mishra | Allow-list input checks |
| 5 | `module4_cloud/field_crypto.py` | AI-generated | Vedant Mishra | AES-GCM encrypted DB fields |
| 5 | `module4_cloud/audit.py` | AI-generated | Vedant Mishra | Audit log + alert rules |
| 5 | `module4_cloud/templates/dashboard.html` | AI-generated | Vedant Mishra | Dashboard (both modes) |
| 5 | `module4_cloud/demo.py` | AI-generated | Vedant Mishra | Cloud-security demo + alert summary |
| 5 | `core/database.py`, `core/cloud_insecure.py`, `core/simulation.py`, `main.py` (edits) | AI-generated | All | Transparent field encryption, insecure dashboard, Module 4 wiring |
| 5 | `docs/case_study.md` (headings only) | AI-generated | Vedant Mishra | Empty template |
| 5 | `results/dashboard_secure_admin_*.jpg` | AI-captured | Vedant Mishra | Screenshots taken by the AI in a local browser |
| 6 | `compare.py` | AI-generated | All | Runs both modes, comparison CSV/Markdown, before/after chart |
| 6 | `main.py` (`--compare`) | AI-generated | All | Comparison entry point |
| 7 | `README.md` | AI-generated | All | Install / run / results / troubleshooting |
| 7 | `tests/test_crypto.py`, `tests/test_access_and_cloud.py` | AI-generated | All | 21 unittest cases |
| 7 | `make_submission_zip.py` | AI-generated | All | ZIP without venv / caches / data |
| 7 | `docs/architecture.md` (update), docstring fixes in `module4_cloud/secure_api.py` | AI-generated | All | Final cleanup |
| 7 | `results/*` (CSVs, PNGs, `sample_output_*.txt`) | Generated by running the code | All | Produced by a fresh-venv test run (Python 3.12), not written by hand |
| 7 | `docs/requirements_checklist.md` | AI-generated | All | Brief requirement → file / demo mapping |
| 8 | `core/live.py`, `core/control_panel.py`, `core/templates/control_panel.html` | AI-generated | Vansh Dabas | Live simulation (`--live`): continuous traffic, attack launcher, key actions |
| 8 | `core/broker.py`, `core/devices.py`, `core/webserver.py`, `config.py`, `main.py`, `module1_attacks/attack_runner.py` (edits) | AI-generated | All | Live traffic feed, `--live` flag, attack descriptions |
| 8 | `module4_cloud/templates/dashboard.html` (edit) | AI-generated | Vedant Mishra | Live indicator, reading age, door-control card, layout fix |
| 8 | Insecure ⇄ secure switch, before/after table + one-click comparison (`core/live.py`, `control_panel.html`), `/api/mode` on both clouds, light/dark toggle on both pages | AI-generated | All | Mode switch restarts a fresh building on the same ports |
| 8 | `results/screenshots/*.jpg` | AI-captured | All | Taken by the AI in a local browser from a real run (insecure, then secure) |
| 8 | Dashboard ↔ control panel buttons; `module1_attacks/common.py` ERROR outcome; attack guard in `core/live.py` | AI-generated | All | A crashed attack is reported as ERROR, never as BLOCKED |
| 9 | `docs/case_study.md` / `.docx` / `.pdf` (Mirai botnet) | AI-generated (draft), to be reviewed by the group | Vedant Mishra | Written at the group's request from public sources (listed in its references) and our measured results |
| 9 | `docs/report.md` → `deliverables/secureTeam_SecureIoT-Sim_Report.docx` / `.pdf` | AI-generated (draft), to be reviewed by the group | All | Full project report; contains the AI-use declaration (Appendix B) to be signed |
| 9 | `deliverables/secureTeam_SecureIoT-Sim_Presentation.pptx` / `.pdf` | AI-generated (draft), to be reviewed by the group | All | 24 slides, one section per member, speaker notes name the presenter |
| 9 | `docs/architecture.png`, `docs/viva_prep.md` | AI-generated | All | Architecture diagram (matplotlib) and viva question sheet |
| 9 | Team names and enrollment numbers in README, `docs/architecture.md`, this log | AI-edited | All | Provided by the group |

## How the code was verified

* Every phase was run after it was written, and its output was checked before moving on.
* Final check: the submission ZIP was unpacked into an empty folder, a new virtual
  environment was created, `pip install -r requirements.txt` was run, then the unit
  tests, `--mode insecure`, `--mode secure` and `--compare`. Everything passed with exit
  code 0 on Python 3.12.10 and again on Python 3.11.9.
* Python 3.9 itself was not available for testing. The pinned libraries publish
  Python 3.9 wheels (cryptography needs 3.9.2+), and the code was syntax-checked
  against the Python 3.9 grammar.

## Things we must be able to explain in the viva

Each owner should be able to walk through their files line by line. In particular:
the envelope format (`secure_channel.py`), the order of checks in `secure_broker.py`,
why attack results are measured (not hard-coded) in `module1_attacks/common.py`, and
how the JWT check rejects `alg: none` tokens in `secure_api.py`.
