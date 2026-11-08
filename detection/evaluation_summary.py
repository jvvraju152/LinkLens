"""Read the evaluation results written by ``evaluate.py --report`` for display in the web app.

Nothing here computes accuracy. It only reports what ``evaluate.py`` measured, and says so when those
figures no longer match the rules that are running.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

_PKG = Path(__file__).resolve().parent
RULE_FILES = (_PKG / "url_features.py", _PKG / "classifier.py")
_METRIC_KEYS = ("n", "positives", "negatives", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "fpr",
                "precision_ci", "recall_ci", "fpr_ci")


def rules_sha256() -> str:
    """Fingerprint of the files that decide a verdict. Changes whenever a rule changes."""
    h = hashlib.sha256()
    for p in RULE_FILES:
        h.update(p.read_bytes().replace(b"\r\n", b"\n"))  # same hash on Windows and Linux checkouts
    return h.hexdigest()


def _weak_spots(results: list[dict]) -> dict:
    """Categories (per split) where phishing was missed or legitimate links were flagged."""
    out: dict[str, dict] = {}
    for r in results:
        if r.get("outcome") not in ("TP", "FP", "TN", "FN"):
            continue
        split = out.setdefault(r["split"], {"missed": {}, "false_alarms": {}})
        bucket = split["missed" if r["actual"] else "false_alarms"].setdefault(r["category"], [0, 0])
        bucket[1] += 1                                   # total in this category
        if (r["actual"] and r["outcome"] == "FN") or (not r["actual"] and r["outcome"] == "FP"):
            bucket[0] += 1                               # wrong in this category
    result = {}
    for split, d in out.items():
        result[split] = {
            kind: sorted(({"category": c, "wrong": w, "total": t} for c, (w, t) in cats.items() if w),
                         key=lambda x: (-x["wrong"], x["category"]))
            for kind, cats in d.items()
        }
    return result


def summarise(path) -> dict:
    """Compact, display-ready view of ``evaluation_results.json``; ``{"available": False}`` if absent or unreadable."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        env = data["environment"]
        splits = {name: {k: m.get(k) for k in _METRIC_KEYS} for name, m in data["by_split"].items()}
        overall = {k: data["overall"].get(k) for k in _METRIC_KEYS}
        weak = _weak_spots(data.get("results", []))
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {"available": False}
    return {
        "available": True,
        "stale": env.get("rules_sha256") != rules_sha256(),
        "scope": "URL-structure rules only. Threat-database lookups are not part of these figures.",
        "dataset": {"file": env.get("dataset_file"), "sha256": (env.get("dataset_sha256") or "")[:12], "rows": overall["n"]},
        "environment": {"python": env.get("python"), "tldextract": env.get("tldextract")},
        "splits": splits,
        "overall": overall,
        "weak_spots": weak,
    }
