"""Production logging and metrics.

* ``configure_logging`` gives the app logger one handler: plain text for a terminal, or one JSON object per line for a
  log shipper. Every line passes through the secret filter, so an API key cannot reach the log.
* ``Metrics`` keeps a few in-memory counters and renders them in the Prometheus text format for ``GET /metrics``.
  Counters are per process. Run one worker with several threads (the default in ``gunicorn.conf.py``) and they are exact.

Neither records the address a person scanned, a query string, a cookie or a client IP.
"""
from __future__ import annotations

import json
import logging
import sys
import threading
from datetime import datetime, timezone

_HANDLER_MARK = "_cyber_solutions_handler"
# Fields a request log line may carry. Anything else attached to a record is ignored, so nothing sensitive slips in.
_EXTRA_FIELDS = ("event", "request_id", "method", "path", "status", "duration_ms")


class JsonFormatter(logging.Formatter):
    """One JSON object per line. ``scrub`` (optional) is applied to the finished line as a last line of defence."""

    def __init__(self, scrub=None):
        super().__init__()
        self._scrub = scrub

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in _EXTRA_FIELDS:
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        return self._scrub(line) if self._scrub else line


class _TextFormatter(logging.Formatter):
    def __init__(self, scrub=None):
        super().__init__("[%(asctime)s] %(levelname)s %(name)s: %(message)s")
        self._scrub = scrub

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        return self._scrub(line) if self._scrub else line


def configure_logging(logger: logging.Logger, level: str = "INFO", fmt: str = "text", scrub=None) -> logging.Handler:
    """Install (or replace) this app's handler on ``logger``. Safe to call many times: handlers never pile up."""
    for old in [h for h in logger.handlers if getattr(h, _HANDLER_MARK, False)]:
        logger.removeHandler(old)
    try:   # Flask attaches its own plain-text handler the first time app.logger is used; keeping it would print every line twice
        from flask.logging import default_handler
        logger.removeHandler(default_handler)
    except ImportError:
        pass
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(scrub) if fmt == "json" else _TextFormatter(scrub))
    setattr(handler, _HANDLER_MARK, True)
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level, logging.INFO))
    return handler


class Metrics:
    """Thread-safe counters with a tiny Prometheus renderer. No labels with user-controlled values, ever."""

    def __init__(self):
        self._lock = threading.Lock()
        self._requests: dict[tuple[str, str], int] = {}     # (route group, status class) -> count
        self._verdicts: dict[str, int] = {}                  # verdict_code -> count
        self._rate_limited = 0
        self._lookup_failures = 0
        self._duration_sum = 0.0
        self._duration_count = 0
        self._started = datetime.now(timezone.utc)

    def request(self, group: str, status: int, seconds: float) -> None:
        with self._lock:
            key = (group, f"{status // 100}xx")
            self._requests[key] = self._requests.get(key, 0) + 1
            self._duration_sum += seconds
            self._duration_count += 1
            if status == 429:
                self._rate_limited += 1

    def verdict(self, code: str, any_source_failed: bool) -> None:
        with self._lock:
            self._verdicts[code] = self._verdicts.get(code, 0) + 1
            if any_source_failed:
                self._lookup_failures += 1

    def render(self) -> str:
        with self._lock:
            lines = ["# HELP cs_requests_total HTTP requests by route group and status class.", "# TYPE cs_requests_total counter"]
            for (group, cls), n in sorted(self._requests.items()):
                lines.append(f'cs_requests_total{{route="{group}",status="{cls}"}} {n}')
            lines += ["# HELP cs_scan_verdicts_total Completed scans by verdict.", "# TYPE cs_scan_verdicts_total counter"]
            for code, n in sorted(self._verdicts.items()):
                lines.append(f'cs_scan_verdicts_total{{verdict="{code}"}} {n}')
            lines += [
                "# HELP cs_rate_limited_total Requests answered 429.", "# TYPE cs_rate_limited_total counter",
                f"cs_rate_limited_total {self._rate_limited}",
                "# HELP cs_lookup_failures_total Scans where at least one threat database could not be checked.",
                "# TYPE cs_lookup_failures_total counter", f"cs_lookup_failures_total {self._lookup_failures}",
                "# HELP cs_request_duration_seconds_sum Total time spent answering requests.",
                "# TYPE cs_request_duration_seconds_sum counter", f"cs_request_duration_seconds_sum {self._duration_sum:.6f}",
                "# HELP cs_request_duration_seconds_count Requests timed.", "# TYPE cs_request_duration_seconds_count counter",
                f"cs_request_duration_seconds_count {self._duration_count}",
                "# HELP cs_process_start_time_seconds Start time of this process (unix).", "# TYPE cs_process_start_time_seconds gauge",
                f"cs_process_start_time_seconds {self._started.timestamp():.0f}",
            ]
        return "\n".join(lines) + "\n"
