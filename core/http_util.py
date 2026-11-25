"""
core/http_util.py - Tiny HTTP helper (standard library only) for calling the cloud API.

Used by main.py for the demo and by the Module 1 attacks (brute force, flooding).
It refuses any URL that is not on 127.0.0.1 so it can never touch a real site.
"""

import json
import urllib.error
import urllib.parse
import urllib.request

from config import HOST


def http_json(method, url, body=None, token=None, timeout=5.0):
    """
    Send an HTTP request with an optional JSON body and Bearer token.

    Returns (status_code, response_dict). Network errors give status 0.
    """
    host = urllib.parse.urlparse(url).hostname
    if host != HOST:
        raise ValueError(f"refusing to contact {host}: only {HOST} is allowed")

    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, _parse(response.read())
    except urllib.error.HTTPError as err:          # 4xx / 5xx still have a body
        return err.code, _parse(err.read())
    except (urllib.error.URLError, OSError) as err:
        return 0, {"error": str(err)}


def _parse(raw):
    """Decode a JSON response body, or wrap plain text in a dictionary."""
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"raw": raw.decode("utf-8", errors="replace")}
