"""Combine threat-intelligence results and URL analysis into an evidence-based verdict."""
from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .threat_intel import check_safe_browsing, check_urlhaus
from .url_features import (ML_FEATURE_VERSION, ML_NGRAM_BUCKETS, ML_NGRAM_N, ML_NUMERIC_FEATURES, InvalidURLError,
                           ParsedURL, analyze_structure, host_only_url, ml_ngram_buckets, ml_numeric, ml_tld,
                           parse_url)

log = logging.getLogger(__name__)

MALICIOUS = "Malicious"
SUSPICIOUS = "Suspicious"
NO_THREAT = "No known threat detected"
UNABLE = "Unable to verify"

# Stable machine-readable codes used by the frontend (labels above are for display).
VERDICT_CODES = {
    MALICIOUS: "malicious",
    SUSPICIOUS: "suspicious",
    NO_THREAT: "no_known_threat",
    UNABLE: "unable_to_verify",
}

SUSPICIOUS_THRESHOLD = 3  # structural risk score at which a URL is called Suspicious
RISK_SCALE_NOTE = "Structural risk score (not a probability): 0-2 low, 3+ suspicious."

DISCLAIMER = (
    "Results come from threat databases and URL-structure checks. A URL that is not listed "
    "is not guaranteed to be safe, and new phishing sites may not be listed yet."
)


@dataclass
class Config:
    # repr=False: a Config printed in a log line or traceback must never reveal the API keys.
    safe_browsing_key: str | None = field(default=None, repr=False)
    urlhaus_key: str | None = field(default=None, repr=False)
    connect_timeout: float = 3.0
    read_timeout: float = 5.0
    send_query: bool = True              # False: strip ?query and #fragment before a URL leaves the server
    lookup_deadline: float = 10.0        # overall seconds a scan may wait for all threat lookups
    model: object | None = field(default=None, repr=False)   # optional LinearURLModel; None = rules + threat intel only

    @property
    def timeout(self) -> tuple[float, float]:
        """(connect, read) timeout passed to ``requests``."""
        return (self.connect_timeout, self.read_timeout)


def lookup_url(parsed: ParsedURL, send_query: bool = True) -> str:
    """The address that is sent to third-party threat databases."""
    if send_query:
        return parsed.normalized
    p = urlsplit(parsed.normalized)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


# ----------------------------------------------------------------------------- optional ML component
# A small linear (logistic-regression) model over host-only features. It is OFF unless an artifact exists, says
# ``adopted: true`` (written by ``python evaluate.py --ml --report`` only when every evidence gate passed) and the
# operator opts in with ENABLE_ML_MODEL=1. Scoring is plain Python: no scikit-learn, numpy or network at runtime.
# It can only ADD a Suspicious verdict. It never produces Malicious, never overrides or lowers a threat-database
# result, and never changes ``risk_score``.
MODEL_PATH = Path(__file__).resolve().parent / "ml_model.json"
MODEL_FORMAT = 1
ML_EVIDENCE = (
    "A statistical model trained on public phishing-feed examples rates the shape of this address as similar to "
    "reported phishing sites. This is a pattern score, not a probability and not a threat-database finding."
)


def ml_schema_sha256() -> str:
    """Fingerprint of the feature definition. A model trained on different features is refused, not guessed at."""
    spec = json.dumps({"v": ML_FEATURE_VERSION, "n": ML_NGRAM_N, "buckets": ML_NGRAM_BUCKETS,
                       "numeric": list(ML_NUMERIC_FEATURES)}, sort_keys=True)
    return hashlib.sha256(spec.encode()).hexdigest()


def _finite(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


class LinearURLModel:
    """Logistic regression with standardised numeric features, one-hot TLD and hashed 3-character host pieces."""

    def __init__(self, spec: dict):
        self.spec = spec
        self.numeric = spec["numeric"]
        self.tlds = spec["tlds"]
        self.ngrams = {int(k): v for k, v in spec["ngram_weights"].items()}
        self.bias = float(spec["bias"])
        self.threshold = float(spec["threshold"])
        self.adopted = bool(spec["adopted"])

    @staticmethod
    def validate(spec) -> str | None:
        """Return a reason the artifact must not be used, or None if it is well formed."""
        try:
            if not isinstance(spec, dict) or spec.get("format") != MODEL_FORMAT:
                return "unknown format"
            if spec.get("feature_version") != ML_FEATURE_VERSION or spec.get("feature_schema_sha256") != ml_schema_sha256():
                return "feature definition has changed since training"
            if not isinstance(spec.get("adopted"), bool):
                return "missing adoption flag"
            if not (_finite(spec.get("bias")) and _finite(spec.get("threshold")) and 0 < spec["threshold"] < 1):
                return "bad bias or threshold"
            num = spec.get("numeric")
            if not isinstance(num, dict) or set(num) != set(ML_NUMERIC_FEATURES):
                return "numeric features do not match"
            for v in num.values():
                if not (isinstance(v, dict) and all(_finite(v.get(k)) for k in ("mean", "std", "w")) and v["std"] > 0):
                    return "bad numeric feature entry"
            tlds = spec.get("tlds")
            if not isinstance(tlds, dict) or len(tlds) > 2000 or not all(isinstance(k, str) and _finite(v) for k, v in tlds.items()):
                return "bad TLD weights"
            ng = spec.get("ngram_weights")
            if not isinstance(ng, dict) or len(ng) > ML_NGRAM_BUCKETS:
                return "bad n-gram weights"
            for k, v in ng.items():
                if not (isinstance(k, str) and k.isdigit() and int(k) < ML_NGRAM_BUCKETS and _finite(v)):
                    return "bad n-gram weight entry"
        except Exception:  # a malformed file must never crash the scanner
            return "unreadable"
        return None

    def score(self, parsed: ParsedURL) -> float | None:
        """Pattern score in (0, 1), or None if the address cannot be reduced to a host."""
        try:
            view = parse_url(host_only_url(parsed.normalized))
        except InvalidURLError:
            return None
        feats = ml_numeric(view)
        z = self.bias
        for name, c in self.numeric.items():
            z += (feats[name] - c["mean"]) / c["std"] * c["w"]
        z += self.tlds.get(ml_tld(view), 0.0)
        z += sum(self.ngrams.get(b, 0.0) for b in ml_ngram_buckets(view))
        return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, z))))

    def assess(self, parsed: ParsedURL) -> dict | None:
        s = self.score(parsed)
        if s is None:
            return None
        return {"score": round(s, 4), "threshold": self.threshold, "flagged": s >= self.threshold}


def load_model(path=MODEL_PATH, require_adopted: bool = True) -> "LinearURLModel | None":
    """Load the artifact, or None if it is missing, invalid, or (by default) was not adopted by the evidence gates."""
    try:
        spec = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    reason = LinearURLModel.validate(spec)
    if reason:
        log.warning("ML model artifact ignored: %s", reason)
        return None
    model = LinearURLModel(spec)
    if require_adopted and not model.adopted:
        return None
    return model


def model_from_env(env=None, path=MODEL_PATH) -> "LinearURLModel | None":
    """The model only when the operator asked for it (ENABLE_ML_MODEL=1) and the artifact passed its gates."""
    import os
    env = os.environ if env is None else env
    if str(env.get("ENABLE_ML_MODEL", "")).strip().lower() not in ("1", "true", "yes", "on"):
        return None
    model = load_model(path)
    if model is None:
        log.warning("ENABLE_ML_MODEL is set but no adopted model artifact is available; running without it.")
    return model


def default_checkers(config: Config):
    """Return a list of callables ``f(parsed) -> result dict``; replaceable in tests."""
    return [
        lambda p: check_safe_browsing(lookup_url(p, config.send_query), config.safe_browsing_key, config.timeout),
        lambda p: check_urlhaus(lookup_url(p, config.send_query), p.hostname, config.urlhaus_key, config.timeout),
    ]


# One small shared pool: a burst of scans cannot start an unbounded number of threads, and threads stuck on a slow
# provider are limited to this many. The per-request deadline below is what keeps a scan from waiting on them.
_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="lookup")
DEFAULT_DEADLINE = 10.0


def _failed(detail: str) -> dict:
    return {"name": "Threat lookup", "status": "error", "detail": detail, "threats": [], "severity": None}


def _run_checkers(parsed: ParsedURL, checkers, deadline: float = DEFAULT_DEADLINE) -> list[dict]:
    if not checkers:
        return []
    futures = [_POOL.submit(c, parsed) for c in checkers]
    end = time.monotonic() + deadline
    results = []
    for f in futures:
        try:
            results.append(f.result(timeout=max(0.0, end - time.monotonic())))
        except FutureTimeout:
            f.cancel()
            results.append(_failed("The lookup took too long."))
        except Exception:  # a broken checker must not take the scan down, and its message is never shown
            results.append(_failed("The lookup failed unexpectedly."))
    return results


def classify_parsed(parsed: ParsedURL, intel: list[dict], model: "LinearURLModel | None" = None) -> dict:
    struct_ev, risk = analyze_structure(parsed)
    ml = model.assess(parsed) if model is not None else None
    ml_flag = bool(ml and ml["flagged"])
    hits = [r for r in intel if r["status"] == "hit"]
    clear = [r for r in intel if r["status"] == "clear"]
    usable = hits or clear

    evidence = []
    for r in hits:
        evidence.append({"source": r["name"], "severity": r["severity"] or "high", "detail": r["detail"]})
    for e in struct_ev:
        evidence.append({"source": "URL analysis", "severity": e["severity"], "detail": e["detail"],
                         "code": e["code"], "points": e["points"], "weak": e["weak"]})
    if ml_flag:  # source "URL analysis" so the page lists it with the address warning signs, not under threat databases
        evidence.append({"source": "URL analysis", "severity": "medium", "detail": ML_EVIDENCE,
                         "code": "ml_model", "points": 0, "weak": False})
    if parsed.scheme_assumed:
        evidence.append({"source": "URL analysis", "severity": "info",
                         "detail": "No scheme was given, so https:// was assumed."})

    strong_hit = any(r["severity"] == "high" for r in hits)
    if strong_hit:
        verdict, severity = MALICIOUS, "high"
        names = " and ".join(r["name"] for r in hits)
        summary = f"{names} lists this URL as unsafe. Do not open it or enter any information."
    elif hits or risk >= SUSPICIOUS_THRESHOLD or ml_flag:
        verdict, severity = SUSPICIOUS, "medium"
        if hits:
            summary = "A threat database reports risk associated with this host. Treat the link with caution."
        elif risk < SUSPICIOUS_THRESHOLD:  # only the statistical model fired
            summary = ("No threat database lists this URL and no rule fired, but a statistical model rates the shape of "
                       "the address as similar to reported phishing sites. "
                       + ("" if usable else "No threat database could be consulted to confirm. ")
                       + "Do not enter credentials unless you are sure of the site.")
        elif usable:
            summary = ("No threat database lists this URL, but its structure has warning signs "
                       "commonly seen in phishing links. Do not enter credentials unless you are sure of the site.")
        else:
            summary = ("Its structure has warning signs commonly seen in phishing links, and no threat "
                       "database could be consulted to confirm. Do not enter credentials unless you are sure of the site.")
    elif usable:
        verdict, severity = NO_THREAT, "low"
        summary = ("No threat database we checked lists this URL, and no strong warning signs were found. "
                   "That is not a guarantee of safety.")
        failed = [r["name"] for r in intel if r["status"] == "error"]
        if failed:
            summary += f" {' and '.join(failed)} could not be checked, so this result is less complete."
    else:
        verdict, severity = UNABLE, "unknown"
        summary = ("No threat database could be consulted, and the URL's structure alone shows no strong "
                   "warning signs. We can't say whether it is safe.")

    if usable and not hits:
        for r in clear:
            evidence.append({"source": r["name"], "severity": "info", "detail": "Checked: URL is not listed."})

    return {
        "url": parsed.original,
        "normalized_url": parsed.normalized,
        "hostname": parsed.hostname,
        "registered_domain": parsed.registered_domain,
        "verdict": verdict,
        "verdict_code": VERDICT_CODES[verdict],
        "confirmed": strong_hit,  # True only when a threat database lists the URL itself
        "severity": severity,
        "summary": summary,
        "evidence": evidence,
        "sources": [{"name": r["name"], "status": r["status"], "detail": r["detail"]} for r in intel],
        "risk_score": risk,
        "risk_note": RISK_SCALE_NOTE,
        "confidence": None,  # no calibrated probability is available; never fabricated
        "basis": "threat_database" if hits else ("url_structure" if (risk >= SUSPICIOUS_THRESHOLD or ml_flag) else "no_match"),
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "disclaimer": DISCLAIMER,
        **({"ml": {**ml, "note": "Pattern score from an optional model; not a probability."}} if ml else {}),
    }


def classify_url(raw_url, checkers, deadline: float = DEFAULT_DEADLINE, model: "LinearURLModel | None" = None) -> dict:
    """Full pipeline. Raises InvalidURLError for bad input. ``model`` is the optional ML component (default: none)."""
    parsed = parse_url(raw_url)
    intel = _run_checkers(parsed, checkers, deadline)
    return classify_parsed(parsed, intel, model)
