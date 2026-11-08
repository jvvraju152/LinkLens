"""All environment-driven settings in one place, parsed defensively.

A bad or hostile value (negative, NaN, huge, not a number) falls back to the default or is clamped, and never
crashes the server or silently turns a protection off.
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field

_ORIGIN_RE = re.compile(r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?$")
DEFAULT_ORIGINS = ("http://127.0.0.1:5000", "http://localhost:5000")

# Browser extensions call the API with "Origin: chrome-extension://<32 letters a-p>". They get their own exact-match list,
# separate from CORS_ORIGINS, and (see urldetection.py) may use only /scan and /health. The default is the ID the bundled
# extension gets when loaded unpacked (its manifest pins a key). Set EXTENSION_ORIGINS to your own published ID(s), or to
# an empty value to switch extension access off.
_EXTENSION_ORIGIN_RE = re.compile(r"^chrome-extension://[a-p]{32}$")
BUNDLED_EXTENSION_ORIGIN = "chrome-extension://pooegmoiedafmkppnjmddffjbkdepeke"
DEFAULT_EXTENSION_ORIGINS = (BUNDLED_EXTENSION_ORIGIN,)


def env_secret(env, name: str) -> str:
    """A secret from ``NAME`` or, if that is empty, from the file named by ``NAME_FILE`` (Docker/Kubernetes secrets).

    Returns "" when neither is set or the file cannot be read; the caller treats that as "not configured". The file's
    contents are never logged, and a trailing newline is stripped.
    """
    direct = str(env.get(name, "") or "").strip().strip("\"'")
    if direct:
        return direct
    path = str(env.get(name + "_FILE", "") or "").strip()
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read(4096).strip().strip("\"'")
    except OSError:
        return ""


def env_bool(env, name: str, default: bool = False) -> bool:
    raw = env.get(name)
    if raw is None or not str(raw).strip():
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def env_int(env, name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(str(env.get(name, "")).strip())
    except ValueError:
        return default
    return max(lo, min(hi, value))


def env_float(env, name: str, default: float, lo: float, hi: float) -> float:
    try:
        value = float(str(env.get(name, "")).strip())
    except ValueError:
        return default
    if not math.isfinite(value):
        return default
    return max(lo, min(hi, value))


def parse_origins(raw: str | None, allow_null: bool = False) -> tuple[tuple[str, ...], list[str]]:
    """Return (valid origins, warnings). Wildcards and malformed entries are dropped, never honoured."""
    if raw is None:
        return DEFAULT_ORIGINS, []
    origins, warnings = [], []
    for item in (o.strip() for o in raw.split(",")):
        if not item:
            continue
        if item == "*":
            warnings.append("CORS_ORIGINS contains '*'; wildcards are ignored. List exact origins instead.")
        elif item == "null":
            if allow_null:
                origins.append("null")
            else:
                warnings.append("CORS_ORIGINS contains 'null'; ignored unless ALLOW_NULL_ORIGIN=1 (development only).")
        elif _ORIGIN_RE.match(item):
            origins.append(item.rstrip("/").lower() if item.count("/") > 2 else item.lower())
        else:
            warnings.append(f"CORS_ORIGINS entry {item[:60]!r} is not a plain origin (scheme://host[:port]); ignored.")
    return tuple(dict.fromkeys(origins)), warnings


def parse_extension_origins(raw: str | None) -> tuple[tuple[str, ...], list[str]]:
    """Return (valid extension origins, warnings). Only exact ``chrome-extension://<id>`` entries are honoured."""
    if raw is None:
        return DEFAULT_EXTENSION_ORIGINS, []
    origins, warnings = [], []
    for item in (o.strip() for o in raw.split(",")):
        if not item:
            continue
        candidate = item.rstrip("/").lower()
        if _EXTENSION_ORIGIN_RE.match(candidate):
            origins.append(candidate)
        elif "*" in item:
            warnings.append("EXTENSION_ORIGINS contains a wildcard; wildcards are ignored. List exact extension origins instead.")
        else:
            warnings.append(f"EXTENSION_ORIGINS entry {item[:60]!r} is not a chrome-extension://<id> origin; ignored.")
    return tuple(dict.fromkeys(origins)), warnings


@dataclass(frozen=True)
class Settings:
    cors_origins: tuple[str, ...] = DEFAULT_ORIGINS
    cors_warnings: tuple[str, ...] = ()
    extension_origins: tuple[str, ...] = DEFAULT_EXTENSION_ORIGINS
    extension_warnings: tuple[str, ...] = ()
    scan_limit_per_minute: int = 30
    global_scan_limit_per_minute: int = 600
    api_limit_per_minute: int = 120
    contact_limit_per_minute: int = 5
    trusted_proxies: int = 0
    max_body_bytes: int = 16 * 1024
    history_enabled: bool = True
    history_retention_days: int = 30
    history_max_per_client: int = 200
    contact_enabled: bool = True
    contact_retention_days: int = 90
    contact_max_bytes: int = 2_000_000
    cookie_secure: bool | None = None   # None = decide per request (secure when the request is https)
    hsts: bool = False
    send_query_to_providers: bool = True
    lookup_deadline_seconds: float = 10.0
    health_detail: bool = False
    debug: bool = field(default=False)
    app_env: str = "development"        # "production" turns on the startup checks in production_warnings()
    log_format: str = "text"            # "json" = one JSON object per line (for log shippers)
    log_level: str = "INFO"
    metrics_token: str = ""             # empty = /metrics is switched off (404)
    log_requests: bool = True


def load_settings(env=None) -> Settings:
    env = os.environ if env is None else env
    origins, warnings = parse_origins(env.get("CORS_ORIGINS"), env_bool(env, "ALLOW_NULL_ORIGIN"))
    ext_origins, ext_warnings = parse_extension_origins(env.get("EXTENSION_ORIGINS"))
    secure_raw = env.get("COOKIE_SECURE")
    return Settings(
        cors_origins=origins,
        cors_warnings=tuple(warnings),
        extension_origins=ext_origins,
        extension_warnings=tuple(ext_warnings),
        scan_limit_per_minute=env_int(env, "RATE_LIMIT_PER_MINUTE", 30, 1, 10_000),
        global_scan_limit_per_minute=env_int(env, "GLOBAL_RATE_LIMIT_PER_MINUTE", 600, 1, 1_000_000),
        api_limit_per_minute=env_int(env, "API_RATE_LIMIT_PER_MINUTE", 120, 1, 10_000),
        contact_limit_per_minute=env_int(env, "CONTACT_RATE_LIMIT_PER_MINUTE", 5, 1, 1_000),
        trusted_proxies=env_int(env, "TRUSTED_PROXY_COUNT", 0, 0, 5),
        history_enabled=env_bool(env, "HISTORY_ENABLED", True),
        history_retention_days=env_int(env, "HISTORY_RETENTION_DAYS", 30, 1, 3650),
        history_max_per_client=env_int(env, "HISTORY_MAX_PER_CLIENT", 200, 10, 10_000),
        contact_enabled=env_bool(env, "CONTACT_ENABLED", True),
        contact_retention_days=env_int(env, "CONTACT_RETENTION_DAYS", 90, 1, 3650),
        contact_max_bytes=env_int(env, "CONTACT_MAX_BYTES", 2_000_000, 10_000, 100_000_000),
        cookie_secure=None if secure_raw is None or not secure_raw.strip() else env_bool(env, "COOKIE_SECURE"),
        hsts=env_bool(env, "HSTS"),
        send_query_to_providers=env_bool(env, "THREAT_INTEL_SEND_QUERY", True),
        lookup_deadline_seconds=env_float(env, "LOOKUP_DEADLINE_SECONDS", 10.0, 1.0, 60.0),
        health_detail=env_bool(env, "HEALTH_DETAIL", False),
        debug=env_bool(env, "FLASK_DEBUG", False),
        app_env="production" if str(env.get("APP_ENV", "")).strip().lower() in ("production", "prod") else "development",
        log_format="json" if str(env.get("LOG_FORMAT", "")).strip().lower() == "json" else "text",
        log_level=(str(env.get("LOG_LEVEL", "INFO")).strip().upper()
                   if str(env.get("LOG_LEVEL", "INFO")).strip().upper() in ("DEBUG", "INFO", "WARNING", "ERROR") else "INFO"),
        metrics_token=env_secret(env, "METRICS_TOKEN"),
        log_requests=env_bool(env, "LOG_REQUESTS", True),
    )


def production_warnings(settings: Settings, has_threat_key: bool) -> list[str]:
    """Problems worth fixing before real users arrive. Empty unless ``APP_ENV=production``.

    These are warnings, not errors, except debug mode, which the caller refuses to start with.
    """
    if settings.app_env != "production":
        return []
    problems: list[str] = []
    if settings.debug:
        problems.append("FLASK_DEBUG=1 in production exposes an interactive debugger. Set FLASK_DEBUG=0.")
    if not settings.trusted_proxies:
        problems.append("TRUSTED_PROXY_COUNT=0: behind an HTTPS proxy every visitor shares the proxy's address, so rate limits "
                        "hit everyone at once. Set it to the number of proxies in front (usually 1).")
    if not settings.hsts:
        problems.append("HSTS=0: browsers are not told to insist on HTTPS. Set HSTS=1 once HTTPS works.")
    if settings.cookie_secure is False:
        problems.append("COOKIE_SECURE=0: the history cookie may travel over plain HTTP. Remove it or set 1.")
    if not has_threat_key:
        problems.append("No threat-database key is set, so every scan is 'Unable to verify' or 'Suspicious'. "
                        "Set GOOGLE_SAFE_BROWSING_API_KEY (or the _FILE variant).")
    if settings.health_detail:
        problems.append("HEALTH_DETAIL=1 makes /health public with provider details. Turn it off unless the endpoint is private.")
    return problems
