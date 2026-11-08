"""Request-level security helpers: rate limiting, anonymous client ids, secret redaction."""
from __future__ import annotations

import hashlib
import logging
import re
import secrets
import threading
import time
from collections import deque

_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")


class RateLimiter:
    """Sliding-window limiter keyed by client address, with bounded memory.

    In-memory and per process: with several worker processes each has its own counters, so set the limit with that in
    mind or rate-limit at the reverse proxy as well.
    """

    OVERFLOW_KEY = "*overflow*"

    def __init__(self, limit: int, window: float = 60.0, max_keys: int = 10_000, clock=time.monotonic):
        self.limit, self.window, self.max_keys, self._clock = limit, window, max_keys, clock
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()
        self._calls = 0

    def _prune(self, now: float) -> None:
        for key in [k for k, q in self._hits.items() if not q or now - q[-1] > self.window]:
            del self._hits[key]

    def check(self, key: str) -> float:
        """Return 0 if allowed, otherwise the number of seconds to wait."""
        now = self._clock()
        with self._lock:
            self._calls += 1
            if len(self._hits) >= self.max_keys or self._calls % 1000 == 0:
                self._prune(now)
            if key not in self._hits and len(self._hits) >= self.max_keys:
                key = self.OVERFLOW_KEY  # many distinct clients at once: they share one bucket, memory stays bounded
            q = self._hits.setdefault(key, deque())
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return max(self.window - (now - q[0]), 0.001)
            q.append(now)
            return 0.0

    def __len__(self) -> int:
        return len(self._hits)


def new_client_id() -> str:
    return secrets.token_urlsafe(24)


def valid_client_id(value: str | None) -> bool:
    return bool(value) and bool(_CLIENT_ID_RE.match(value))


def hash_client_id(value: str) -> str:
    """Only this hash is stored, so a copy of the database cannot be used to impersonate a browser."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class SecretFilter(logging.Filter):
    """Replace configured secrets (API keys) with ``***`` in every log line passing through the logger."""

    def __init__(self, secrets_: list[str]):
        super().__init__()
        self._secrets = [s for s in secrets_ if s and len(s) >= 4]

    def scrub(self, text: str) -> str:
        for s in self._secrets:
            text = text.replace(s, "***")
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        if self._secrets:
            record.msg = self.scrub(record.getMessage())
            record.args = ()
        return True


def install_secret_filter(secrets_: list[str]) -> SecretFilter:
    f = SecretFilter(secrets_)
    for name in ("werkzeug", "urllib3", "requests", "flask.app"):
        logging.getLogger(name).addFilter(f)
    return f
