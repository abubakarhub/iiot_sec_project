# Before / after comparison

Same attack code against the insecure baseline and the secured system.

| Attack | Insecure: success | Secure: success | Outcome after | Defence observed in secure mode |
|---|---|---|---|---|
| sniffing | 20/20 (100.0%) | 0/20 (0.0%) | BLOCKED | payload unreadable on the wire (encrypted) |
| tampering | 10/10 (100.0%) | 0/10 (0.0%) | BLOCKED | HMAC check failed (message modified) |
| replay | 5/5 (100.0%) | 0/5 (0.0%) | BLOCKED | replayed message (old sequence number) |
| spoofing | 10/10 (100.0%) | 0/10 (0.0%) | BLOCKED | challenge-response failed (wrong key); not authenticated |
| brute_force | 1/59 (100.0%) | 0/99 (0.0%) | BLOCKED | login refused: HTTP 401 x5, HTTP 423 x5, HTTP 429 x89 |
| flooding_broker | 1000/1000 (100.0%) | 20/1000 (2.0%) | PARTIAL | rate limit exceeded |
| flooding_api | 300/300 (100.0%) | 36/300 (12.0%) | PARTIAL | refused: HTTP 429 x264 |
| unauthorised_command | 4/4 (100.0%) | 0/4 (0.0%) | BLOCKED | viewer token -> HTTP 403; no token -> HTTP 401; forged admin JWT -> HTTP 401; direct broker publish -> hello refused; broker: unknown or revoked device 'viewer1-laptop'; not authenticated |

Notes:
* brute_force: attempts = passwords tried; success = account taken over (1 = yes), so its rate is 100% or 0%.
* flooding_*: success = flood messages / requests the system accepted. A rate limiter lets a small burst through by design, so these are PARTIAL, not 0%.
* Every number comes from attacks that really ran against the live system (database rows, lock state, broker and HTTP replies).
