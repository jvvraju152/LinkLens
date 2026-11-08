"""Contact-form messages: validation, minimal storage, retention.

Privacy design
* Stores only what the person typed (name, email, message) plus a UTC timestamp. No IP address, no user agent.
* The file is created readable by its owner only (0600) and lives under data/, which is never served over HTTP.
* Messages older than the retention period are deleted automatically; the file has a size cap so it cannot fill the disk.
* Storage requires an explicit consent flag. ``tools/contact_admin.py`` can list, export or delete by email address.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

NAME_MAX, EMAIL_MAX = 100, 200
MESSAGE_MIN, MESSAGE_MAX = 10, 2000
_EMAIL_RE = re.compile(r"^[^\s@<>\"']+@[^\s@<>\"']+\.[^\s@<>\"']+$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u2028\u2029]")


class ContactUnavailable(Exception):
    """Storage is disabled, full, or failed. The message is safe to show to the user."""


def _clean_line(text: str) -> str:
    return re.sub(r"\s+", " ", _CONTROL.sub("", text)).strip()


def validate(payload) -> tuple[dict, dict]:
    """Return (clean fields, {field: message}). Messages are written for the person filling in the form."""
    data = payload if isinstance(payload, dict) else {}
    errors: dict[str, str] = {}

    name = _clean_line(str(data.get("name", "")))
    if not name:
        errors["name"] = "Enter your name."
    elif len(name) > NAME_MAX:
        errors["name"] = f"Keep your name under {NAME_MAX} characters."

    email = str(data.get("email", "")).strip()
    if not email:
        errors["email"] = "Enter your email address so we can reply."
    elif len(email) > EMAIL_MAX or not _EMAIL_RE.match(email):
        errors["email"] = "Enter a valid email address, like name@example.com."

    message = _CONTROL.sub("", str(data.get("message", "")).replace("\r\n", "\n").replace("\r", "\n")).strip()
    if len(message) < MESSAGE_MIN:
        errors["message"] = f"Write at least {MESSAGE_MIN} characters so we can help."
    elif len(message) > MESSAGE_MAX:
        errors["message"] = f"Keep your message under {MESSAGE_MAX} characters ({len(message)} now)."

    if data.get("consent") is not True:
        errors["consent"] = "Please tick the box to agree to how your message is stored."
    return {"name": name, "email": email, "message": message}, errors


def is_honeypot(payload) -> bool:
    """Bots fill every field. A human never sees ``website``, so any value means automation."""
    return isinstance(payload, dict) and bool(str(payload.get("website", "")).strip())


class ContactStore:
    def __init__(self, path, enabled: bool = True, retention_days: int = 90, max_bytes: int = 2_000_000, clock=None):
        self.path = Path(path)
        self.enabled, self.retention_days, self.max_bytes = enabled, retention_days, max_bytes
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()

    # ---- helpers
    def _read(self) -> list[dict]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        out = []
        for line in lines:
            try:
                rec = json.loads(line)
                if isinstance(rec, dict) and "at" in rec:
                    out.append(rec)
            except ValueError:
                continue
        return out

    def _write_all(self, records: list[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".contact-", suffix=".tmp")  # mkstemp is 0600
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                for r in records:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            os.replace(tmp, self.path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _expired(self, rec: dict) -> bool:
        try:
            at = datetime.fromisoformat(rec["at"])
        except (ValueError, TypeError):
            return True
        return at < self._clock() - timedelta(days=self.retention_days)

    # ---- public
    def purge_expired(self) -> int:
        with self._lock:
            recs = self._read()
            keep = [r for r in recs if not self._expired(r)]
            if len(keep) != len(recs):
                self._write_all(keep)
            return len(recs) - len(keep)

    def save(self, clean: dict) -> None:
        if not self.enabled:
            raise ContactUnavailable("The contact form is switched off on this server.")
        record = {"at": self._clock().isoformat(timespec="seconds"), **clean}
        line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            self.purge_expired()
            with self._lock:
                size = self.path.stat().st_size if self.path.exists() else 0
                if size + len(line) > self.max_bytes:
                    raise ContactUnavailable("The inbox is full right now. Please try again later.")
                self.path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, "ab") as f:
                    f.write(line)
        except OSError:
            raise ContactUnavailable("Your message couldn't be saved. Please try again later.") from None

    def delete_by_email(self, email: str) -> int:
        email = email.strip().lower()
        with self._lock:
            recs = self._read()
            keep = [r for r in recs if str(r.get("email", "")).lower() != email]
            if len(keep) != len(recs):
                self._write_all(keep)
            return len(recs) - len(keep)

    def records(self) -> list[dict]:
        with self._lock:
            return self._read()
