"""Small SQLite-backed scan history, private to each browser.

Privacy
* Only scheme + host + path are stored (query strings and fragments often carry tokens), truncated to 200 characters.
* The evidence saved with a scan (why it got its verdict, which threat database listed it) is the short, fixed wording the
  scanner produces. Anything that looks like a query string or fragment is removed and every field has a length cap.
* Each browser gets a random anonymous id in an HttpOnly cookie. Only a SHA-256 hash of it is stored, and EVERY read,
  search, export and delete is scoped to it (``WHERE client = ?``), so one visitor can never see or erase another's
  history, not even by guessing a scan id.
* Rows are deleted after the retention period, and each browser keeps at most ``max_per_client`` rows.
* The database file is created readable by its owner only.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

VERDICT_CODES = ("malicious", "suspicious", "no_known_threat", "unable_to_verify")
# Rows written before verdict codes were stored only have the display label.
CODE_BY_LABEL = {"Malicious": "malicious", "Suspicious": "suspicious",
                 "No known threat detected": "no_known_threat", "Unable to verify": "unable_to_verify"}
SORTS = ("newest", "oldest", "risk")
MAX_QUERY_CHARS = 100
MAX_PAGE = 100
EVIDENCE_LIMIT, SOURCES_LIMIT = 12, 6

_NEW_COLUMNS = {  # added after the first version; older databases are upgraded in place
    "verdict_code": "TEXT", "confirmed": "INTEGER", "risk_score": "INTEGER", "basis": "TEXT",
    "hit_sources": "TEXT", "evidence": "TEXT", "sources": "TEXT",
}
_QUERY_TAIL = re.compile(r"[?#]\S*")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _text(value, limit: int) -> str:
    return _CONTROL.sub(" ", str(value if value is not None else ""))[:limit]


def _clean_evidence(items) -> list[dict]:
    out = []
    for e in (items if isinstance(items, list) else [])[:EVIDENCE_LIMIT]:
        if not isinstance(e, dict):
            continue
        item = {"source": _text(e.get("source"), 60), "severity": _text(e.get("severity"), 12),
                "detail": _QUERY_TAIL.sub("", _text(e.get("detail"), 300)).strip()}
        if e.get("code"):
            item["code"] = _text(e["code"], 40)
        if isinstance(e.get("points"), int) and not isinstance(e.get("points"), bool):
            item["points"] = e["points"]
        out.append(item)
    return out


def _clean_sources(items) -> list[dict]:
    return [{"name": _text(s.get("name"), 60), "status": _text(s.get("status"), 12), "detail": _text(s.get("detail"), 160)}
            for s in (items if isinstance(items, list) else [])[:SOURCES_LIMIT] if isinstance(s, dict)]


def _like(text: str) -> str:
    """A LIKE pattern that matches ``text`` literally, so a search for ``50%_off`` does not act as a wildcard."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def parse_filters(args) -> dict:
    """Turn query-string arguments into safe, clamped filters. Unknown or malformed values are ignored, never an error."""
    q = _CONTROL.sub(" ", (args.get("q") or "")).strip()[:MAX_QUERY_CHARS]
    verdicts = tuple(dict.fromkeys(v for v in (args.get("verdict") or "").split(",") if v in VERDICT_CODES))
    try:
        days = max(1, min(int(args.get("days")), 3650))
    except (TypeError, ValueError):
        days = None
    sort = args.get("sort") if args.get("sort") in SORTS else "newest"
    try:
        limit = max(1, min(int(args.get("limit", 25)), MAX_PAGE))
    except (TypeError, ValueError):
        limit = 25
    try:
        offset = max(0, min(int(args.get("offset", 0)), 1_000_000))
    except (TypeError, ValueError):
        offset = 0
    return {"q": q, "verdicts": verdicts, "source": _text(args.get("source"), 60).strip(),
            "days": days, "confirmed_only": str(args.get("confirmed", "")).lower() in ("1", "true", "yes"),
            "sort": sort, "limit": limit, "offset": offset}


class ScanHistory:
    def __init__(self, path: str, retention_days: int = 30, max_per_client: int = 200):
        self.path = path
        self.retention_days, self.max_per_client = retention_days, max_per_client
        self._lock = threading.Lock()
        Path(path).parent.mkdir(parents=True, exist_ok=True)  # e.g. data/ may not exist yet
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT NOT NULL, "
                "url TEXT NOT NULL, verdict TEXT NOT NULL, severity TEXT NOT NULL, client TEXT)"
            )
            cols = {r[1] for r in db.execute("PRAGMA table_info(scans)")}
            if "client" not in cols:  # databases from before history was per-browser
                db.execute("ALTER TABLE scans ADD COLUMN client TEXT")
            for name, kind in _NEW_COLUMNS.items():  # databases from before evidence was kept
                if name not in cols:
                    db.execute(f"ALTER TABLE scans ADD COLUMN {name} {kind}")
            db.execute("CREATE INDEX IF NOT EXISTS scans_client ON scans (client, id)")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        self.purge()

    def _connect(self):
        return sqlite3.connect(self.path, timeout=5)

    @staticmethod
    def _redact(url: str) -> str:
        p = urlsplit(url)
        return f"{p.scheme}://{p.netloc.split('@')[-1]}{p.path}"[:200]

    def purge(self) -> None:
        """Delete expired rows, and rows from before history was per-browser (they belong to nobody)."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat(timespec="seconds")
        with self._lock, self._connect() as db:
            db.execute("DELETE FROM scans WHERE scanned_at < ? OR client IS NULL", (cutoff,))

    # ------------------------------------------------------------------ write
    def add(self, client: str, url: str, verdict: str, severity: str, details: dict | None = None) -> int:
        """Save one scan. ``details`` is the scanner's result (verdict_code, confirmed, risk_score, basis, evidence,
        sources); only the fields kept here are read from it, and each is cleaned and length-limited first."""
        d = details or {}
        sources = _clean_sources(d.get("sources"))
        evidence = _clean_evidence(d.get("evidence"))
        hits = [s["name"] for s in sources if s["status"] == "hit" and s["name"]]
        code = d.get("verdict_code") if d.get("verdict_code") in VERDICT_CODES else CODE_BY_LABEL.get(verdict)
        score = d.get("risk_score")
        with self._lock, self._connect() as db:
            cur = db.execute(
                "INSERT INTO scans (scanned_at, url, verdict, severity, client, verdict_code, confirmed, risk_score, basis, "
                "hit_sources, evidence, sources) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(timespec="seconds"), self._redact(url), verdict, severity, client,
                 code, 1 if d.get("confirmed") else 0, score if isinstance(score, int) and not isinstance(score, bool) else None,
                 _text(d.get("basis"), 30) or None, ("|" + "|".join(hits) + "|") if hits else "",
                 json.dumps(evidence), json.dumps(sources)),
            )
            new_id = cur.lastrowid
            db.execute(
                "DELETE FROM scans WHERE client = ? AND id NOT IN "
                "(SELECT id FROM scans WHERE client = ? ORDER BY id DESC LIMIT ?)",
                (client, client, self.max_per_client),
            )
        return new_id

    def delete(self, client: str, scan_id: int) -> bool:
        """Delete one scan, but only if it belongs to ``client``. Someone else's id behaves exactly like a missing one."""
        with self._lock, self._connect() as db:
            return db.execute("DELETE FROM scans WHERE id = ? AND client = ?", (scan_id, client)).rowcount > 0

    def clear(self, client: str) -> int:
        with self._lock, self._connect() as db:
            return db.execute("DELETE FROM scans WHERE client = ?", (client,)).rowcount

    # ------------------------------------------------------------------ read
    _COLS = ("id, scanned_at, url, verdict, verdict_code, severity, confirmed, risk_score, basis, hit_sources, evidence, sources")

    @staticmethod
    def _row(r) -> dict:
        def loads(raw):
            try:
                value = json.loads(raw) if raw else []
            except ValueError:
                value = []
            return value if isinstance(value, list) else []
        return {"id": r[0], "scanned_at": r[1], "url": r[2], "verdict": r[3],
                "verdict_code": r[4] or CODE_BY_LABEL.get(r[3], "unable_to_verify"), "severity": r[5],
                "confirmed": bool(r[6]), "risk_score": r[7], "basis": r[8],
                "threat_sources": [s for s in (r[9] or "").split("|") if s],
                "evidence": loads(r[10]), "sources": loads(r[11])}

    def search(self, client: str, q: str = "", verdicts=(), source: str = "", days: int | None = None,
               confirmed_only: bool = False, sort: str = "newest", limit: int | None = 25, offset: int = 0) -> dict:
        """This client's scans that match every filter given, plus the total number of matches (for paging).
        ``limit=None`` returns everything that matches (used for export)."""
        if not client:  # a browser with no cookie has no history
            return {"total": 0, "scans": []}
        where, params = ["client = ?"], [client]
        if q:
            pattern = _like(q.lower())
            where.append("(LOWER(url) LIKE ? ESCAPE '\\' OR LOWER(verdict) LIKE ? ESCAPE '\\' "
                         "OR LOWER(hit_sources) LIKE ? ESCAPE '\\')")
            params += [pattern] * 3
        codes = [v for v in verdicts if v in VERDICT_CODES]
        if codes:
            labels = [label for label, code in CODE_BY_LABEL.items() if code in codes]  # rows saved before codes existed
            where.append(f"(verdict_code IN ({','.join('?' * len(codes))}) OR "
                         f"(verdict_code IS NULL AND verdict IN ({','.join('?' * len(labels))})))")
            params += codes + labels
        if source:
            where.append("hit_sources LIKE ? ESCAPE '\\'")
            params.append(_like("|" + source + "|"))
        if days:
            where.append("scanned_at >= ?")
            params.append((datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds"))
        if confirmed_only:
            where.append("confirmed = 1")
        order = {"newest": "id DESC", "oldest": "id ASC",
                 "risk": "COALESCE(risk_score, -1) DESC, id DESC"}.get(sort, "id DESC")
        clause = " AND ".join(where)
        sql = f"SELECT {self._COLS} FROM scans WHERE {clause} ORDER BY {order}"
        page_params = []
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            page_params = [max(1, int(limit)), max(0, int(offset))]
        with self._lock, self._connect() as db:
            total = db.execute(f"SELECT COUNT(*) FROM scans WHERE {clause}", params).fetchone()[0]
            rows = db.execute(sql, params + page_params).fetchall()
        return {"total": total, "scans": [self._row(r) for r in rows]}

    def recent(self, client: str, limit: int = 10) -> list[dict]:
        return self.search(client, limit=max(1, min(int(limit), 50)))["scans"]

    def stats(self, client: str, tz_offset_minutes: int = 0, days: int = 14) -> dict:
        """Totals for the dashboard, over all of this client's saved scans (not just one page or filter)."""
        offset = timedelta(minutes=max(-840, min(int(tz_offset_minutes), 840)))
        rows = []
        if client:
            with self._lock, self._connect() as db:
                rows = db.execute("SELECT scanned_at, verdict, verdict_code, confirmed, hit_sources FROM scans WHERE client = ?",
                                  (client,)).fetchall()
        by_verdict = dict.fromkeys(VERDICT_CODES, 0)
        sources: dict[str, int] = {}
        per_day: dict[str, list[int]] = {}
        confirmed, newest = 0, ""
        for scanned_at, verdict, code, is_confirmed, hit_sources in rows:
            code = code or CODE_BY_LABEL.get(verdict, "unable_to_verify")
            by_verdict[code] = by_verdict.get(code, 0) + 1
            confirmed += 1 if is_confirmed else 0
            newest = max(newest, scanned_at)
            for name in (hit_sources or "").split("|"):
                if name:
                    sources[name] = sources.get(name, 0) + 1
            try:
                day = (datetime.fromisoformat(scanned_at) + offset).date().isoformat()
            except ValueError:
                continue
            bucket = per_day.setdefault(day, [0, 0])
            bucket[0] += 1
            bucket[1] += 1 if code in ("malicious", "suspicious") else 0
        today = (datetime.now(timezone.utc) + offset).date()
        series = []
        for i in range(days - 1, -1, -1):
            day = (today - timedelta(days=i)).isoformat()
            total, flagged = per_day.get(day, [0, 0])
            series.append({"date": day, "scans": total, "flagged": flagged})
        return {"total": len(rows), "by_verdict": by_verdict, "flagged": by_verdict["malicious"] + by_verdict["suspicious"],
                "confirmed": confirmed, "last_scan": newest or None, "by_day": series,
                "threat_sources": [{"name": n, "count": c} for n, c in sorted(sources.items(), key=lambda kv: (-kv[1], kv[0]))[:5]]}


# ---------------------------------------------------------------------- export
EXPORT_FIELDS = ("scanned_at", "url", "verdict", "confirmed", "risk_score", "severity", "basis", "threat_sources", "evidence")


def _csv_cell(value) -> str:
    """Stop a spreadsheet from running a saved value as a formula (CSV injection): prefix risky first characters."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def to_csv(scans: list[dict]) -> str:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(EXPORT_FIELDS)
    for s in scans:
        writer.writerow([_csv_cell(v) for v in (
            s["scanned_at"], s["url"], s["verdict"], "yes" if s["confirmed"] else "no", s["risk_score"], s["severity"],
            s["basis"], "; ".join(s["threat_sources"]),
            " | ".join((e["detail"] + (f" [{e['source']}]" if e.get("source") and e["source"] != "URL analysis" else ""))
                       for e in s["evidence"] if e.get("detail")))])
    return buf.getvalue()


def to_json(scans: list[dict]) -> str:
    keep = ("scanned_at", "url", "verdict", "verdict_code", "confirmed", "risk_score", "severity", "basis",
            "threat_sources", "evidence", "sources")
    return json.dumps({"exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "count": len(scans),
                       "scans": [{k: s[k] for k in keep} for s in scans]}, indent=2, ensure_ascii=False)
