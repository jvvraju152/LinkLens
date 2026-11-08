"""Threat-intelligence lookups (Google Safe Browsing + abuse.ch URLhaus).

Each checker returns a dict:
    {"name": str, "status": "hit" | "clear" | "skipped" | "error",
     "detail": str, "threats": [str], "severity": "high" | "medium" | None}

Rules:
* API keys are sent in headers, never in URLs, and exception text is never
  returned to callers (requests exceptions can echo URLs and credentials).
* Every call has a timeout. Failure is reported as ``error``, never as ``clear``.
* "clear" only means "not listed" - it is not proof that a URL is safe.
* Only definite answers (``hit`` / ``clear``) are cached. Failures are never
  cached, so a transient outage cannot linger as a stale answer.
* After a rate-limit response a provider is paused for a cooldown, so the
  server does not keep hammering an API that has told it to back off. After several
  timeouts / server errors in a row it is paused briefly too (a simple circuit breaker).
* Requests never follow redirects: API-key headers are not stripped on a cross-host
  redirect, so following one could hand the key to another server.
* Timeouts are clamped, and responses larger than 1 MB are refused.

Tuning (environment variables, read at call time):
    THREAT_INTEL_CACHE_TTL_SECONDS       default 300
    THREAT_INTEL_RATE_LIMIT_COOLDOWN     default 60
    THREAT_INTEL_FAILURE_THRESHOLD       default 3   (consecutive failures before a pause)
    THREAT_INTEL_FAILURE_PAUSE_SECONDS   default 30
"""
from __future__ import annotations

import json
import math
import os
import threading
import time

import requests

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"

SB_NAME = "Google Safe Browsing"
URLHAUS_NAME = "URLhaus"

SB_THREAT_LABELS = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing / social engineering",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "potentially harmful application",
}

DEFAULT_TIMEOUT = (3.0, 5.0)  # (connect, read) seconds
MIN_TIMEOUT, MAX_TIMEOUT = 0.5, 15.0
MAX_RESPONSE_BYTES = 1_000_000

def _result(name, status, detail, threats=None, severity=None):
    return {"name": name, "status": status, "detail": detail, "threats": threats or [], "severity": severity}


# ---------------------------------------------------------------- cache + cooldown
_lock = threading.Lock()
_cache: dict = {}    # (provider, url) -> (expires_at, result)
_blocked: dict = {}  # provider -> (monotonic time until which lookups are paused, reason message)
_failures: dict = {}  # provider -> consecutive timeouts / server errors


def _env_float(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, ""))
        return value if value > 0 else default
    except ValueError:
        return default


def reset_state() -> None:
    """Forget cached answers and cooldowns (used by tests)."""
    with _lock:
        _cache.clear()
        _blocked.clear()
        _failures.clear()


RATE_LIMITED_MSG = "The service is rate-limiting requests right now."
PAUSED_MSG = "The service is temporarily paused after repeated failures."


def _clamp_timeout(timeout):
    """Accept a float or a (connect, read) pair; never allow zero, negative, NaN or huge values."""
    pair = timeout if isinstance(timeout, (tuple, list)) and len(timeout) == 2 else (timeout, timeout)
    out = []
    for v, default in zip(pair, DEFAULT_TIMEOUT):
        try:
            v = float(v)
        except (TypeError, ValueError):
            v = default
        out.append(default if not math.isfinite(v) else max(MIN_TIMEOUT, min(MAX_TIMEOUT, v)))
    return (out[0], out[1])


def _lookup_cached(name, url):
    """Return a cached answer, a rate-limited error during cooldown, or None."""
    now = time.monotonic()
    with _lock:
        cached = _cache.get((name, url))
        if cached and cached[0] > now:
            return dict(cached[1])
        blocked = _blocked.get(name)
        if blocked and blocked[0] > now:
            return _result(name, "error", blocked[1])
    return None


def _remember(name, url, result):
    if result["status"] in ("hit", "clear"):
        ttl = _env_float("THREAT_INTEL_CACHE_TTL_SECONDS", 300.0)
        with _lock:
            if len(_cache) > 1000:
                _cache.clear()
            _cache[(name, url)] = (time.monotonic() + ttl, dict(result))
    return result


def _block(name, seconds, reason):
    with _lock:
        _blocked[name] = (time.monotonic() + seconds, reason)


def _start_cooldown(name, resp):
    """Pause a provider after a rate-limit response (honours Retry-After, capped at 1 hour)."""
    retry = ""
    headers = getattr(resp, "headers", None)
    if headers:
        retry = headers.get("Retry-After", "") or ""
    default = _env_float("THREAT_INTEL_RATE_LIMIT_COOLDOWN", 60.0)
    try:
        wait = float(retry)
        if not math.isfinite(wait):  # "nan" would otherwise compare False and switch the cooldown off
            raise ValueError
        wait = min(wait, 3600.0)
    except ValueError:
        wait = default
    _block(name, max(wait, 1.0), RATE_LIMITED_MSG)
    return _result(name, "error", "The API quota was exceeded.")


def _note_failure(name):
    """Count a timeout / server error; after enough in a row, pause the provider briefly."""
    threshold = int(_env_float("THREAT_INTEL_FAILURE_THRESHOLD", 3.0))
    with _lock:
        _failures[name] = _failures.get(name, 0) + 1
        tripped = _failures[name] >= max(threshold, 1)
        if tripped:
            _failures[name] = 0
    if tripped:
        _block(name, _env_float("THREAT_INTEL_FAILURE_PAUSE_SECONDS", 30.0), PAUSED_MSG)


def _note_success(name):
    with _lock:
        _failures.pop(name, None)


def _request(name, http, url, timeout, **kw):
    """POST without following redirects. Returns (response, None) or (None, error result)."""
    try:
        resp = http.post(url, timeout=_clamp_timeout(timeout), allow_redirects=False, stream=True, **kw)
    except requests.Timeout:
        _note_failure(name)
        return None, _result(name, "error", "The lookup timed out.")
    except requests.RequestException:
        _note_failure(name)
        return None, _result(name, "error", "The service could not be reached.")
    if 300 <= resp.status_code < 400:
        _note_failure(name)
        return None, _result(name, "error", "The service sent an unexpected redirect, which was not followed.")
    if resp.status_code >= 500:
        _note_failure(name)
    return resp, None


def _json(resp):
    """Parse a JSON body, refusing anything over MAX_RESPONSE_BYTES. Raises ValueError on bad or oversized data."""
    headers = getattr(resp, "headers", None) or {}
    length = headers.get("Content-Length", "")
    if str(length).isdigit() and int(length) > MAX_RESPONSE_BYTES:
        raise ValueError("response too large")
    try:
        if hasattr(resp, "iter_content"):
            buf = b""
            for chunk in resp.iter_content(65536):
                buf += chunk
                if len(buf) > MAX_RESPONSE_BYTES:
                    raise ValueError("response too large")
            return json.loads(buf.decode("utf-8"))
        return resp.json()
    finally:
        close = getattr(resp, "close", None)
        if callable(close):
            close()


def _error_status(resp):
    try:
        return (_json(resp).get("error") or {}).get("status")
    except (ValueError, AttributeError, TypeError):
        return None


# ---------------------------------------------------------------- Google Safe Browsing
def check_safe_browsing(url: str, api_key: str | None, timeout=DEFAULT_TIMEOUT, session=None) -> dict:
    name = SB_NAME
    if not api_key:
        return _result(name, "skipped", "Not configured (set GOOGLE_SAFE_BROWSING_API_KEY).")
    cached = _lookup_cached(name, url)
    if cached:
        return cached

    http = session or requests
    body = {
        "client": {"clientId": "cyber-solutions", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": list(SB_THREAT_LABELS),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    resp, failed = _request(name, http, SAFE_BROWSING_ENDPOINT, timeout, json=body, headers={"X-Goog-Api-Key": api_key})
    if failed:
        return failed

    if resp.status_code == 429:
        return _start_cooldown(name, resp)
    if resp.status_code in (400, 401, 403):
        # Google reports an exhausted quota as 403 / RESOURCE_EXHAUSTED on some projects.
        if _error_status(resp) == "RESOURCE_EXHAUSTED":
            return _start_cooldown(name, resp)
        return _result(name, "error", "The API key was rejected or the Safe Browsing API is not enabled for it.")
    if resp.status_code != 200:
        return _result(name, "error", f"Unexpected response from the service (HTTP {resp.status_code}).")

    try:
        data = _json(resp)
        if not isinstance(data, dict):
            raise ValueError("unexpected JSON shape")
        matches = data.get("matches") or []
        if not isinstance(matches, list):
            raise ValueError("unexpected matches shape")
        types = sorted({SB_THREAT_LABELS.get(str(m.get("threatType")), "unsafe content") for m in matches})
    except (ValueError, AttributeError, TypeError):
        _note_failure(name)
        return _result(name, "error", "The service returned an unreadable response.")
    _note_success(name)

    if not matches:
        return _remember(name, url, _result(name, "clear", "Not listed."))
    return _remember(name, url, _result(name, "hit", f"Listed as {', '.join(types)}.", threats=types, severity="high"))


# ---------------------------------------------------------------- URLhaus
def check_urlhaus(url: str, hostname: str, auth_key: str | None, timeout=DEFAULT_TIMEOUT, session=None) -> dict:
    """Query abuse.ch URLhaus (malware distribution URLs). Requires a free Auth-Key."""
    name = URLHAUS_NAME
    if not auth_key:
        return _result(name, "skipped", "Not configured (set URLHAUS_AUTH_KEY).")
    cached = _lookup_cached(name, url)
    if cached:
        return cached

    http = session or requests
    headers = {"Auth-Key": auth_key}
    try:
        r, failed = _request(name, http, URLHAUS_URL_ENDPOINT, timeout, data={"url": url}, headers=headers)
        if failed:
            return failed
        if r.status_code == 429:
            return _start_cooldown(name, r)
        if r.status_code in (401, 403):
            return _result(name, "error", "The Auth-Key was rejected.")
        if r.status_code != 200:
            return _result(name, "error", f"Unexpected response from the service (HTTP {r.status_code}).")
        data = _json(r)
        status = data.get("query_status")
        if status == "ok":
            threat = data.get("threat") or "malware distribution"
            state = data.get("url_status") or "unknown"
            _note_success(name)
            return _remember(name, url, _result(
                name, "hit", f"Listed as {threat} (status: {state}).", threats=[threat], severity="high"))
        if status not in ("no_results", "invalid_url"):
            _note_failure(name)
            return _result(name, "error", "The service returned an unexpected result.")

        # Not listed as an exact URL - see whether the host serves known malware.
        r2, failed = _request(name, http, URLHAUS_HOST_ENDPOINT, timeout, data={"host": hostname}, headers=headers)
        if failed:
            return failed
        if r2.status_code == 429:
            return _start_cooldown(name, r2)
        if r2.status_code != 200:
            # The exact-URL answer is not enough to call the host clear when the host lookup failed.
            return _result(name, "error", f"Unexpected response from the service (HTTP {r2.status_code}).")
        d2 = _json(r2)
        _note_success(name)
        if d2.get("query_status") == "ok" and int(d2.get("urls_online") or 0) > 0:
            n = int(d2["urls_online"])
            return _remember(name, url, _result(
                name, "hit",
                f"The host currently serves {n} URL(s) listed as malware (this exact URL is not listed).",
                threats=["host serves malware"], severity="medium"))
        return _remember(name, url, _result(name, "clear", "Not listed."))
    except (ValueError, AttributeError, TypeError):
        _note_failure(name)
        return _result(name, "error", "The service returned an unreadable response.")
