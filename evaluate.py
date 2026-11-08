"""Measure how well the URL-structure classifier separates phishing from legitimate links.

    python evaluate.py                         # data/labelled_urls.csv (dev) + data/independent_holdout.csv (holdout)
    python evaluate.py --report                # also write reports/evaluation_report.md and .json
    python evaluate.py --split holdout         # score only one split (dev | holdout)
    python evaluate.py my_labels.csv           # your own CSV(s), e.g. the output of tools/build_feed_dataset.py
    python evaluate.py --ml                    # does the optional ML model beat the rules? (needs requirements-ml.txt)
    python evaluate.py --ml --report           # also write reports/ml_evaluation.md, ml_results.json and the model file

CSV columns: ``url`` and ``label`` are required. ``category``, ``split`` and ``source`` are optional.
Label ``phishing`` (or ``malicious``) is the positive class, ``benign`` is the negative class. Any other
label is an error, so a typo can never be silently scored as benign.

What is measured: the local heuristics only. Threat-intelligence lookups (Google Safe Browsing, URLhaus)
are NOT used, so the run needs no network and gives the same answer every time. A URL counts as
"predicted positive" when the pipeline's verdict is Suspicious or Malicious.

The numbers are only as good as the dataset. See reports/evaluation_report.md for what this one is and is not.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import sys
from collections import Counter, OrderedDict, defaultdict
from pathlib import Path

from datetime import date

from detection.classifier import (MALICIOUS, MODEL_FORMAT, MODEL_PATH, SUSPICIOUS, SUSPICIOUS_THRESHOLD,
                                  LinearURLModel, classify_url, load_model, ml_schema_sha256)
from detection.evaluation_summary import rules_sha256
from detection.url_features import (ML_FEATURE_VERSION, ML_NGRAM_BUCKETS, ML_NUMERIC_FEATURES, InvalidURLError,
                                    analyze_structure, host_only_url, ml_ngram_buckets, ml_numeric, ml_tld, parse_url)

ROOT = Path(__file__).resolve().parent
DEFAULT_DATA = ROOT / "data" / "labelled_urls.csv"
DEFAULT_HOLDOUT = ROOT / "data" / "independent_holdout.csv"
DEFAULT_DATASETS = (DEFAULT_DATA, DEFAULT_HOLDOUT)
REPORT_DIR = ROOT / "reports"

POSITIVE = {"phishing", "malicious"}
NEGATIVE = {"benign"}

# Categories whose label cannot be known from the address alone. A shortened link's real destination is
# never fetched, so "phishing" vs "benign" is unknowable here. They are reported, but not scored.
UNSCORED_CATEGORIES = {"shortener"}

SWEEP_THRESHOLDS = (1, 2, 3, 4, 5, 6)
PREVALENCES = (0.5, 0.1, 0.01, 0.001)


# ----------------------------------------------------------------------------- loading
def load_dataset(path) -> list[dict]:
    """Read and validate a labelled CSV. Raises ValueError naming the line for any bad row."""
    rows, seen = [], set()
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = {"url", "label"} - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"{path}: missing required column(s): {', '.join(sorted(missing))}")
        for line_no, row in enumerate(reader, start=2):
            url = (row.get("url") or "").strip()
            label = (row.get("label") or "").strip().lower()
            if not url:
                raise ValueError(f"{path}:{line_no}: empty url")
            if label not in POSITIVE | NEGATIVE:
                raise ValueError(f"{path}:{line_no}: unknown label {label!r} (use 'phishing' or 'benign')")
            if url in seen:
                raise ValueError(f"{path}:{line_no}: duplicate url {url}")
            seen.add(url)
            rows.append({
                "url": url,
                "actual": label in POSITIVE,
                "category": (row.get("category") or "uncategorised").strip(),
                "split": (row.get("split") or "all").strip(),
                "source": (row.get("source") or "unknown").strip(),
            })
    return rows


def _as_paths(paths) -> list[Path]:
    return [Path(p) for p in ([paths] if isinstance(paths, (str, Path)) else paths)]


def load_datasets(paths) -> list[dict]:
    """Load one or more CSVs. A URL appearing in two files is an error: it would leak tuning data into the holdout."""
    rows, owner = [], {}
    for path in _as_paths(paths):
        for r in load_dataset(path):
            if r["url"] in owner:
                raise ValueError(f"{path.name}: {r['url']} is also in {owner[r['url']]} (datasets must not overlap)")
            owner[r["url"]] = path.name
            rows.append(r)
    return rows


# ----------------------------------------------------------------------------- scoring
def score_rows(rows: list[dict]) -> list[dict]:
    """Run every URL through the real pipeline (no threat-intel) and attach the outcome."""
    out = []
    for r in rows:
        r = dict(r)
        try:
            result = classify_url(r["url"], [])
            risk = result["risk_score"]
        except InvalidURLError as exc:
            r.update(verdict="Rejected", predicted=None, risk=None, codes=[], outcome="skipped", note=str(exc))
            out.append(r)
            continue
        codes = [e["code"] for e in result["evidence"] if e.get("source") == "URL analysis" and e.get("code")]
        predicted = result["verdict"] in (SUSPICIOUS, MALICIOUS)
        if r["category"] in UNSCORED_CATEGORIES:
            outcome = "unscored"
        elif predicted and r["actual"]:
            outcome = "TP"
        elif predicted:
            outcome = "FP"
        elif r["actual"]:
            outcome = "FN"
        else:
            outcome = "TN"
        r.update(verdict=result["verdict"], predicted=predicted, risk=risk, codes=codes, outcome=outcome, note="")
        out.append(r)
    return out


# ----------------------------------------------------------------------------- metrics
def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion. Honest about small samples (unlike +/- sqrt(p(1-p)/n))."""
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _div(a, b):
    return a / b if b else math.nan


def metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    precision, recall = _div(tp, tp + fp), _div(tp, tp + fn)
    f1 = _div(2 * precision * recall, precision + recall) if not (math.isnan(precision) or math.isnan(recall)) else math.nan
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "n": tp + fp + tn + fn,
        "positives": tp + fn, "negatives": tn + fp,
        "precision": precision, "recall": recall, "f1": f1,
        "fpr": _div(fp, fp + tn), "accuracy": _div(tp + tn, tp + fp + tn + fn),
        "precision_ci": wilson(tp, tp + fp), "recall_ci": wilson(tp, tp + fn), "fpr_ci": wilson(fp, fp + tn),
    }


def metrics_for(scored: list[dict]) -> dict:
    c = Counter(r["outcome"] for r in scored)
    return metrics(c["TP"], c["FP"], c["TN"], c["FN"])


def precision_at_prevalence(recall: float, fpr: float, prevalence: float) -> float:
    """Expected precision if phishing made up ``prevalence`` of the scanned links (Bayes)."""
    tp, fp = recall * prevalence, fpr * (1 - prevalence)
    return _div(tp, tp + fp)


def sweep(scored: list[dict]) -> list[dict]:
    """Metrics if the Suspicious cut-off were t instead of the shipped value (uses the raw risk score)."""
    scorable = [r for r in scored if r["outcome"] in ("TP", "FP", "TN", "FN")]
    rows = []
    for t in SWEEP_THRESHOLDS:
        tp = sum(1 for r in scorable if r["actual"] and r["risk"] >= t)
        fn = sum(1 for r in scorable if r["actual"] and r["risk"] < t)
        fp = sum(1 for r in scorable if not r["actual"] and r["risk"] >= t)
        tn = sum(1 for r in scorable if not r["actual"] and r["risk"] < t)
        rows.append({"threshold": t, **metrics(tp, fp, tn, fn)})
    return rows


def by_category(scored: list[dict]) -> "OrderedDict[str, dict]":
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in scored:
        groups[r["category"]].append(r)
    out = OrderedDict()
    for cat in sorted(groups):
        g = groups[cat]
        pos = [r for r in g if r["actual"]]
        neg = [r for r in g if not r["actual"]]
        out[cat] = {
            "label": "phishing" if pos and not neg else "benign" if neg and not pos else "mixed",
            "n": len(g),
            "flagged": sum(1 for r in g if r["predicted"]),
            "unscored": cat in UNSCORED_CATEGORIES,
        }
    return out


def evaluate(paths, split: str | None = None) -> dict:
    rows = load_datasets(paths)
    if split:
        rows = [r for r in rows if r["split"] == split]
        if not rows:
            raise ValueError(f"No rows with split {split!r}")
    scored = score_rows(rows)
    scorable = [r for r in scored if r["outcome"] in ("TP", "FP", "TN", "FN")]
    splits = sorted({r["split"] for r in scorable}, key=lambda s: (s != "dev", s))
    return {
        "scored": scored,
        "overall": metrics_for(scorable),
        "by_split": OrderedDict((s, metrics_for([r for r in scorable if r["split"] == s])) for s in splits),
        "sweep_by_split": OrderedDict((s, sweep([r for r in scorable if r["split"] == s])) for s in splits),
        "by_category": {s: by_category([r for r in scored if r["split"] == s]) for s in splits},
        "false_positives": [r for r in scored if r["outcome"] == "FP"],
        "false_negatives": [r for r in scored if r["outcome"] == "FN"],
        "unscored": [r for r in scored if r["outcome"] == "unscored"],
        "skipped": [r for r in scored if r["outcome"] == "skipped"],
    }


# ----------------------------------------------------------------------------- reproducibility info
def _sha256(*paths) -> str:
    h = hashlib.sha256()
    for p in paths:
        h.update(Path(p).read_bytes().replace(b"\r\n", b"\n"))  # same hash on Windows and Linux checkouts
    return h.hexdigest()


def environment(paths) -> dict:
    try:
        import tldextract
        tld_version = getattr(tldextract, "__version__", "unknown")
    except Exception:  # pragma: no cover
        tld_version = "unavailable"
    files = _as_paths(paths)
    hashes = [_sha256(p) for p in files]
    return {
        "dataset_file": " + ".join(p.name for p in files),
        "dataset_sha256": hashes[0] if len(hashes) == 1 else hashlib.sha256("".join(hashes).encode()).hexdigest(),
        "datasets": [{"file": p.name, "sha256": h} for p, h in zip(files, hashes)],
        "rules_sha256": rules_sha256(),
        "suspicious_threshold": SUSPICIOUS_THRESHOLD,
        "python": platform.python_version(),
        "tldextract": tld_version,
    }


# ----------------------------------------------------------------------------- formatting
def pct(x, digits: int = 1) -> str:
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x * 100:.{digits}f}%"


def pct_ci(x, ci, ci_digits: int = 0) -> str:
    return "n/a" if math.isnan(x) else f"{pct(x)} ({pct(ci[0], ci_digits)}–{pct(ci[1], ci_digits)})"


def _row_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def _md_escape(url: str) -> str:
    return "`" + url.replace("`", "%60").replace("|", "%7C") + "`"


def console_summary(res: dict, path) -> str:
    o = res["overall"]
    out = [f"Dataset: {environment(path)['dataset_file']}   scored {o['n']} (positives {o['positives']}, negatives {o['negatives']})"]
    if res["unscored"]:
        out.append(f"Not scored (label depends on an unseen destination): {len(res['unscored'])}")
    if res["skipped"]:
        out.append(f"Skipped {len(res['skipped'])} unparseable URL(s): " + ", ".join(r["url"] for r in res["skipped"][:5]))
    for name, m in res["by_split"].items():  # no pooled row: it would blend tuned and untuned data
        out.append(f"\n[{name}]  n={m['n']}  TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}")
        out.append(f"  Precision:           {pct_ci(m['precision'], m['precision_ci'])}")
        out.append(f"  Recall:              {pct_ci(m['recall'], m['recall_ci'])}")
        out.append(f"  F1-score:            {pct(m['f1'])}")
        out.append(f"  False-positive rate: {pct_ci(m['fpr'], m['fpr_ci'])}")
    for title, items in (("False positives (legitimate, flagged)", res["false_positives"]),
                         ("Missed threats (phishing, not flagged)", res["false_negatives"])):
        if items:
            out.append(f"\n{title}: {len(items)}")
            out += [f"  [{r['split']}] {r['url']}  (risk {r['risk']}; {', '.join(r['codes']) or 'no signals'})" for r in items]
    return "\n".join(out)


def render_report(res: dict, path) -> str:
    env = environment(path)
    o = res["overall"]
    splits = list(res["by_split"])
    L: list[str] = []
    w = L.append

    w("# Detection evaluation report\n")
    w("This report is generated by `python evaluate.py --report`. It measures how well the **URL-structure "
      "heuristics** separate phishing links from legitimate ones, on the labelled dataset in this repository. "
      "It does not measure the threat-database lookups (Google Safe Browsing, URLhaus), which need network "
      "access and API keys and are the only source of *confirmed* verdicts.\n")

    w("## Read this first\n")
    sources = Counter((r["source"], r["actual"]) for r in res["scored"] if r["outcome"] != "skipped")
    share = o["positives"] / o["n"] if o["n"] else math.nan
    w("- **What was measured:** the URL-structure heuristics only, never the threat-database lookups.")
    if any(src == "synthetic-phish" for src, _ in sources):
        w("- **The phishing URLs are synthetic.** They follow well-documented phishing patterns on invented domains. "
          "They are not a sample of real attacks, so recall here says how well the rules catch the patterns they "
          "were designed for, not how many real phishing links they would catch.")
    if any(src == "curated-legit" for src, _ in sources):
        w("- **The legitimate URLs are real domains** written by hand. Paths were not checked to be live.")
    if {"dev", "holdout"} <= set(splits):
        w("- **Dev vs holdout.** Rules were tuned by looking at every `dev` error. The `holdout` split was written after the "
          "rules were frozen and has not been used to change any rule, so it is the fairer estimate. Dev numbers are "
          "optimistic by construction. The holdout is independent of the tuning but **not of its author**: whoever wrote "
          "the rules also wrote it. A feed-based set (`tools/build_feed_dataset.py`) is the check that removes that limit.")
    w("- **Small samples.** Intervals in brackets are 95% Wilson intervals. They are wide; differences of a few "
      "points between runs or splits are not meaningful.")
    w(f"- **Prevalence.** {pct(share, 0)} of the scored URLs here are phishing. Real traffic is nowhere near that, and "
      "precision depends on it. Use the false-positive rate, and the prevalence table below, to judge real-world behaviour.")
    if res["skipped"]:
        w(f"- **{len(res['skipped'])} row(s) were rejected by the scanner's own URL validation and not scored:** "
          + ", ".join(_md_escape(r["url"]) for r in res["skipped"][:10]) + ".")
    w("")
    w(_row_table(["Source", "Label", "URLs"],
                 [[f"`{src}`", "phishing" if pos else "benign", n] for (src, pos), n in sorted(sources.items(), key=lambda kv: (kv[0][0], not kv[0][1]))]))
    w("")

    w("## Headline results\n")
    head_rows = []
    for name in splits:
        m = res["by_split"][name]
        head_rows.append([name + (" (tuned on)" if name == "dev" else " (not tuned on)" if name == "holdout" else ""),
                          m["n"], f"{m['positives']} / {m['negatives']}", pct_ci(m["precision"], m["precision_ci"]),
                          pct_ci(m["recall"], m["recall_ci"]), pct(m["f1"]), pct_ci(m["fpr"], m["fpr_ci"])])
    w(_row_table(["Split", "Scored", "Phishing / legit", "Precision", "Recall", "F1", "False-positive rate"], head_rows))
    w("\nPositive class = phishing. Predicted positive = verdict *Suspicious* (risk score ≥ "
      f"{SUSPICIOUS_THRESHOLD}). Heuristics alone never produce *Malicious*.\n")

    w("### Confusion matrices\n")
    w(_row_table(["Split", "TP", "FP", "TN", "FN"],
                 [[n, m["tp"], m["fp"], m["tn"], m["fn"]] for n, m in res["by_split"].items()]))
    w("")

    ref = res["by_split"].get("holdout") or o
    ref_name = "holdout" if "holdout" in res["by_split"] else "all rows"
    w("### What precision would look like on real traffic\n")
    w(f"Using recall and false-positive rate from the **{ref_name}** split. A measured FPR of 0 does not mean the true "
      "rate is 0, so the last column uses the upper end of its 95% interval.\n")
    prev_rows = []
    for p in PREVALENCES:
        prev_rows.append([pct(p, 1 if p < 0.01 else 0),
                          pct(precision_at_prevalence(ref["recall"], ref["fpr"], p)),
                          pct(precision_at_prevalence(ref["recall"], ref["fpr_ci"][1], p))])
    w(_row_table(["Share of scanned links that are phishing", "Precision (measured FPR)", "Precision (FPR at upper bound)"], prev_rows))
    w("")

    w("## Method\n")
    w("1. Each URL goes through the same `classify_url()` pipeline the web app uses, with no threat-database results.")
    w("2. A URL is *predicted positive* if the verdict is Suspicious or Malicious.")
    w("3. Counts come from comparing that to the label. Precision = TP/(TP+FP), recall = TP/(TP+FN), "
      "F1 = harmonic mean of the two, false-positive rate = FP/(FP+TN).")
    w("4. Categories whose label depends on a destination the scanner never visits are listed but **not scored**: "
      + ", ".join(f"`{c}`" for c in sorted(UNSCORED_CATEGORIES)) + ".")
    w("5. Labels are validated on load. Unknown labels, empty URLs and duplicates stop the run.\n")

    for name in splits:
        w(f"## Threshold sweep: {name}\n")
        w(f"What would change if the Suspicious cut-off were different from the shipped value ({SUSPICIOUS_THRESHOLD}).\n")
        w(_row_table(["Cut-off", "Precision", "Recall", "F1", "False-positive rate", "FP", "FN"],
                     [[("**" if s["threshold"] == SUSPICIOUS_THRESHOLD else "") + str(s["threshold"]) + ("**" if s["threshold"] == SUSPICIOUS_THRESHOLD else ""),
                       pct(s["precision"]), pct(s["recall"]), pct(s["f1"]), pct(s["fpr"]), s["fp"], s["fn"]]
                      for s in res["sweep_by_split"][name]]))
        w("")

    for name in splits:
        w(f"## Results by category: {name}\n")
        cats = res["by_category"][name]
        w(_row_table(["Category", "Label", "URLs", "Flagged", "Result"],
                     [[f"`{c}`", v["label"], v["n"], v["flagged"],
                       "not scored" if v["unscored"] else
                       (f"caught {v['flagged']}/{v['n']}" if v["label"] == "phishing" else
                        f"{v['flagged']} false positive(s)" if v["flagged"] else "none flagged")]
                      for c, v in cats.items()]))
        w("")

    w("## False positives: legitimate links that were flagged\n")
    if res["false_positives"]:
        w(_row_table(["Split", "URL", "Risk", "Signals that fired"],
                     [[r["split"], _md_escape(r["url"]), r["risk"], ", ".join(r["codes"]) or "-"] for r in res["false_positives"]]))
    else:
        w("None.")
    w("")
    w("## Missed threats: phishing links that were not flagged\n")
    if res["false_negatives"]:
        w(_row_table(["Split", "Category", "URL", "Risk", "Signals that fired"],
                     [[r["split"], f"`{r['category']}`", _md_escape(r["url"]), r["risk"], ", ".join(r["codes"]) or "none"]
                      for r in res["false_negatives"]]))
    else:
        w("None.")
    w("")

    if res["unscored"]:
        w("## Not scored\n")
        w("These links cannot be judged from the address alone.\n")
        w(_row_table(["Split", "URL", "Label in dataset", "Verdict"],
                     [[r["split"], _md_escape(r["url"]), "phishing" if r["actual"] else "benign", r["verdict"]] for r in res["unscored"]]))
        w("")

    w("## Limitations\n")
    w("- A link on a legitimate site that has been compromised, an open redirect on a trusted domain, and a "
      "malicious page on a trusted platform all look normal from the address alone. Only a threat database, "
      "or fetching the page, can catch them.")
    w("- Brand and official-domain lists are hand-maintained. A brand missing from the list is not protected, "
      "and a legitimate first-party domain missing from it can be flagged.")
    w("- The dataset is small and was written by the same people who wrote the rules, so it shares their blind spots.")
    w("- For a real benchmark, run this script on a PhishTank/OpenPhish export plus a Tranco top-sites sample "
      "(see Reproduce below) and report that instead of, or beside, these figures.\n")

    w("## Reproduce\n")
    w("```")
    w("python -m pip install -r requirements.txt")
    w("python evaluate.py --report")
    w("```\n")
    w("Same dataset hash and same rules hash give the same numbers. Different `tldextract` versions can differ "
      "slightly because the public-suffix list changes. To evaluate real feeds, export them to a CSV with "
      "`url,label` columns (and optionally `category`, `split`, `source`) and run `python evaluate.py yourfile.csv`.\n")
    w(_row_table(["Item", "Value"], [
        *[[f"Dataset file", f"`{d['file']}` (SHA-256 `{d['sha256']}`)"] for d in env["datasets"]],
        ["Rules SHA-256 (`url_features.py` + `classifier.py`)", f"`{env['rules_sha256']}`"],
        ["Suspicious cut-off", env["suspicious_threshold"]], ["Python", env["python"]], ["tldextract", env["tldextract"]],
    ]))
    w("")
    return "\n".join(L)


def results_json(res: dict, path) -> dict:
    def clean(x):
        if isinstance(x, float) and math.isnan(x):
            return None
        if isinstance(x, tuple):
            return [clean(i) for i in x]
        if isinstance(x, dict):
            return {k: clean(v) for k, v in x.items()}
        if isinstance(x, list):
            return [clean(i) for i in x]
        return x
    return clean({
        "environment": environment(path),
        "overall": res["overall"],
        "by_split": res["by_split"],
        "sweep_by_split": res["sweep_by_split"],
        "results": [{k: r[k] for k in ("url", "actual", "category", "split", "source", "verdict", "risk", "codes", "outcome")}
                    for r in res["scored"]],
    })



# ============================================================================= optional ML component
# Question this section answers: does a trained model beat the existing rules, on data it never saw, by enough to be
# worth shipping? The protocol below is fixed BEFORE the final numbers are read and every rule in it is enforced by
# code, so the answer cannot be bent by choosing a favourable threshold or split afterwards.
#
#   1. Train on data/feed_train.csv only. Test on data/feed_test.csv only, once. They come from different phishing
#      collectors and share no group (registered domain, or full host on shared-hosting platforms).
#   2. Both classes are reduced to the same host-only form, so path length, scheme, port or "www." cannot separate them.
#   3. Model settings are chosen by GROUP-aware cross-validation on the training data. The test set plays no part.
#   4. The operating threshold is the lowest score whose out-of-fold false-positive rate is <= ML_TARGET_FPR.
#   5. The shipped component is the rules plus the model ("hybrid"). It is compared with the rules alone, on the
#      same rows, with paired bootstrap intervals. The model is adopted only if EVERY gate in ML_GATES passes.
ML_TRAIN = ROOT / "data" / "feed_train.csv"
ML_TEST = ROOT / "data" / "feed_test.csv"
ML_SEED = 7
ML_GRID = tuple((c, ng) for ng in (False, True) for c in (0.03, 0.1, 0.3, 1.0))   # (C, use hashed 3-grams)
ML_CV_FOLDS = 5
ML_TARGET_FPR = 0.01
ML_TLD_MIN_COUNT = 20
ML_BOOTSTRAPS = 2000
ML_SHARED_HOST_MIN_HOSTS = 25
ML_GATES = OrderedDict([
    ("enough_test_data", "at least 100 phishing and 500 benign test rows"),
    ("recall_gain", "hybrid recall exceeds rules-only recall by >= 5 points, paired-bootstrap 95% interval above 0"),
    ("fpr_ceiling", "hybrid false-positive rate on the test set: 95% Wilson upper bound <= 3.0%"),
    ("holdout_guard", "on the author's independent holdout, the hybrid adds at most 1 false positive over the rules"),
    ("no_leakage_signs", "grouped-CV AUC within 0.03 of random-CV AUC, and AUC with shuffled labels within 0.45-0.55"),
])


def _ml_libs():
    try:
        import numpy as np
        from scipy import sparse
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import roc_auc_score
        from sklearn.model_selection import GroupKFold, StratifiedKFold
        import sklearn
    except ImportError as exc:
        raise RuntimeError("The ML evaluation needs scikit-learn. Install it with: python -m pip install -r requirements-ml.txt") from exc
    return {"np": np, "sparse": sparse, "LR": LogisticRegression, "auc": roc_auc_score, "GroupKFold": GroupKFold,
            "StratifiedKFold": StratifiedKFold, "sklearn": sklearn.__version__, "numpy": np.__version__}


def load_host_rows(path) -> tuple[list[dict], int]:
    """Load a labelled CSV and reduce every URL to its host-only form. Returns (rows, number skipped as unparseable)."""
    rows, skipped = [], 0
    for r in load_dataset(path):
        try:
            host_url = host_only_url(r["url"])
        except InvalidURLError:
            skipped += 1
            continue
        rows.append({**r, "host_url": host_url, "parsed": parse_url(host_url)})
    return rows, skipped


def shared_platforms(*row_sets: list[dict]) -> set[str]:
    """Registered domains that host many unrelated tenants (>= ML_SHARED_HOST_MIN_HOSTS distinct hosts across all files)."""
    hosts = defaultdict(set)
    for rows in row_sets:
        for r in rows:
            hosts[r["parsed"].registered_domain].add(r["parsed"].hostname)
    return {d for d, h in hosts.items() if len(h) >= ML_SHARED_HOST_MIN_HOSTS}


def manifest_platforms(*csv_paths) -> set[str]:
    """Shared-hosting platforms recorded by tools/build_ml_dataset.py next to the data (empty if there is no manifest)."""
    out: set[str] = set()
    for path in csv_paths:
        m = Path(path).with_name("feed_manifest.json")
        try:
            out |= set(json.loads(m.read_text(encoding="utf-8")).get("shared_hosting_platforms", []))
        except (OSError, ValueError, AttributeError):
            pass
    return out


def assign_groups(rows: list[dict], platforms: set[str]) -> list[str]:
    """Leakage groups: the registered domain, or the full host where the registered domain is a shared-hosting platform
    (thousands of unrelated tenants under one name). Rows in the same group never sit on both sides of a split.
    ``platforms`` must be computed over every file being compared, or the same domain gets different keys in each."""
    return [r["parsed"].hostname if r["parsed"].registered_domain in platforms else r["parsed"].registered_domain for r in rows]


def featurize(rows: list[dict], L) -> dict:
    np = L["np"]
    return {"numeric": np.array([[ml_numeric(r["parsed"])[k] for k in ML_NUMERIC_FEATURES] for r in rows]),
            "tld": [ml_tld(r["parsed"]) for r in rows], "grams": [ml_ngram_buckets(r["parsed"]) for r in rows]}


def _design(feat: dict, idx, vocab: list[str], use_ngrams: bool, mean, std, L):
    np, sparse = L["np"], L["sparse"]
    idx = list(idx)
    dense = (feat["numeric"][idx] - mean) / std
    tld_index = {t: i for i, t in enumerate(vocab)}
    rr, cc = [], []
    for i, j in enumerate(idx):
        if feat["tld"][j] in tld_index:
            rr.append(i); cc.append(tld_index[feat["tld"][j]])
    tld_m = sparse.csr_matrix((np.ones(len(rr)), (rr, cc)), shape=(len(idx), len(vocab)))
    parts = [sparse.csr_matrix(dense), tld_m]
    if use_ngrams:
        rr, cc = [], []
        for i, j in enumerate(idx):
            for b in feat["grams"][j]:
                rr.append(i); cc.append(b)
        parts.append(sparse.csr_matrix((np.ones(len(rr)), (rr, cc)), shape=(len(idx), ML_NGRAM_BUCKETS)))
    return sparse.hstack(parts).tocsr()


def _fit(feat, idx, y, C: float, use_ngrams: bool, L) -> dict:
    """Fit on the rows ``idx`` only. TLD vocabulary and scaling are learned from those rows alone (no peeking)."""
    np = L["np"]
    idx = list(idx)
    counts = Counter(feat["tld"][j] for j in idx)
    vocab = sorted(t for t, c in counts.items() if c >= ML_TLD_MIN_COUNT and t)
    mean = feat["numeric"][idx].mean(axis=0)
    std = feat["numeric"][idx].std(axis=0)
    std[std == 0] = 1.0
    clf = L["LR"](C=C, max_iter=3000).fit(_design(feat, idx, vocab, use_ngrams, mean, std, L), y[idx])
    return {"vocab": vocab, "mean": mean, "std": std, "clf": clf, "use_ngrams": use_ngrams, "C": C}


def _predict(fit: dict, feat, idx, L):
    return fit["clf"].predict_proba(_design(feat, idx, fit["vocab"], fit["use_ngrams"], fit["mean"], fit["std"], L))[:, 1]


def _oof(feat, y, groups, C, use_ngrams, L, grouped: bool = True):
    np = L["np"]
    n = len(y)
    out = np.zeros(n)
    splitter = (L["GroupKFold"](ML_CV_FOLDS).split(np.zeros(n), y, groups) if grouped
                else L["StratifiedKFold"](ML_CV_FOLDS, shuffle=True, random_state=ML_SEED).split(np.zeros(n), y))
    for tr, te in splitter:
        out[te] = _predict(_fit(feat, tr, y, C, use_ngrams, L), feat, te, L)
    return out


def choose_threshold(oof, y, target_fpr: float, L) -> float:
    """Lowest threshold whose out-of-fold false-positive rate is <= target. Uses training data only."""
    np = L["np"]
    neg = np.sort(oof[~y])[::-1]
    k = int(target_fpr * len(neg))
    if k == 0:
        return float(min(0.999999, neg[0] + 1e-6))
    return float((neg[k - 1] + neg[k]) / 2)


def export_model(fit: dict, threshold: float, meta: dict, L) -> dict:
    """Turn the fitted scikit-learn model into plain JSON the scanner can score without scikit-learn."""
    w = fit["clf"].coef_[0]
    n_num, n_tld = len(ML_NUMERIC_FEATURES), len(fit["vocab"])
    return {
        "format": MODEL_FORMAT, "kind": "logistic_regression", "feature_version": ML_FEATURE_VERSION,
        "feature_schema_sha256": ml_schema_sha256(), "created": date.today().isoformat(),
        "adopted": False, "threshold": threshold, "bias": float(fit["clf"].intercept_[0]),
        "numeric": {name: {"mean": float(fit["mean"][i]), "std": float(fit["std"][i]), "w": float(w[i])}
                    for i, name in enumerate(ML_NUMERIC_FEATURES)},
        "tlds": {t: float(w[n_num + i]) for i, t in enumerate(fit["vocab"])},
        "ngram_weights": ({str(b): float(w[n_num + n_tld + b]) for b in range(ML_NGRAM_BUCKETS) if w[n_num + n_tld + b] != 0.0}
                          if fit["use_ngrams"] else {}),
        "settings": {"C": fit["C"], "hashed_3grams": fit["use_ngrams"], "tld_min_count": ML_TLD_MIN_COUNT,
                     "target_fpr": ML_TARGET_FPR, "seed": ML_SEED},
        **meta,
    }


def paired_bootstrap(a, b, y, L, n: int = ML_BOOTSTRAPS, seed: int = ML_SEED) -> dict:
    """Paired bootstrap of (b - a) for recall (over positives) and false-positive rate (over negatives)."""
    np = L["np"]
    rng = np.random.default_rng(seed)
    a, b, y = np.asarray(a, bool), np.asarray(b, bool), np.asarray(y, bool)
    pa, pb, na, nb = a[y], b[y], a[~y], b[~y]
    ip = rng.integers(0, len(pa), (n, len(pa)))
    ine = rng.integers(0, len(na), (n, len(na)))
    d_rec = pb[ip].mean(1) - pa[ip].mean(1)
    d_fpr = nb[ine].mean(1) - na[ine].mean(1)
    q = lambda x: [float(np.quantile(x, 0.025)), float(np.quantile(x, 0.975))]  # noqa: E731
    return {"delta_recall": float(pb.mean() - pa.mean()), "delta_recall_ci": q(d_rec),
            "delta_fpr": float(nb.mean() - na.mean()), "delta_fpr_ci": q(d_fpr)}


def _confusion(pred, y) -> dict:
    tp = sum(1 for p, a in zip(pred, y) if p and a)
    fp = sum(1 for p, a in zip(pred, y) if p and not a)
    fn = sum(1 for p, a in zip(pred, y) if not p and a)
    tn = sum(1 for p, a in zip(pred, y) if not p and not a)
    return metrics(tp, fp, tn, fn)


def _systems(rows: list[dict], model: LinearURLModel, url_key: str) -> dict:
    """Predictions of the three systems on the same rows, through the real scanner code path."""
    rules, hybrid, model_only = [], [], []
    for r in rows:
        u = r[url_key]
        rules.append(classify_url(u, [])["verdict"] in (SUSPICIOUS, MALICIOUS))
        hybrid.append(classify_url(u, [], model=model)["verdict"] in (SUSPICIOUS, MALICIOUS))
        a = model.assess(parse_url(u))
        model_only.append(bool(a and a["flagged"]))
    return {"rules": rules, "hybrid": hybrid, "model": model_only}


def ml_evaluate(train_path=ML_TRAIN, test_path=ML_TEST) -> dict:
    L = _ml_libs()
    np = L["np"]
    train, skipped_train = load_host_rows(train_path)
    test, skipped_test = load_host_rows(test_path)
    platforms = shared_platforms(train, test) | manifest_platforms(train_path, test_path)
    groups_train = assign_groups(train, platforms)
    groups_test = assign_groups(test, platforms)
    shared = set(groups_train) & set(groups_test)
    if shared:   # the datasets must be disjoint by group, or the test set is not independent
        raise ValueError(f"{len(shared)} group(s) occur in both train and test, e.g. {sorted(shared)[:3]}")
    y = np.array([r["actual"] for r in train])
    yt = np.array([r["actual"] for r in test])
    feat = featurize(train, L)

    # -- 3. model selection by grouped CV on the training data only
    grid = []
    for C, ng in ML_GRID:
        oof = _oof(feat, y, groups_train, C, ng, L, grouped=True)
        grid.append({"C": C, "hashed_3grams": ng, "grouped_cv_auc": float(L["auc"](y, oof)), "oof": oof})
    best = max(grid, key=lambda g: (round(g["grouped_cv_auc"], 4), -g["C"], g["hashed_3grams"]))  # ties: simpler/stronger regularisation
    C, ng, oof = best["C"], best["hashed_3grams"], best["oof"]

    # -- leakage diagnostics (training data only)
    rng = np.random.default_rng(ML_SEED)
    random_auc = float(L["auc"](y, _oof(feat, y, groups_train, C, ng, L, grouped=False)))
    shuffled = rng.permutation(y)
    shuffled_auc = float(L["auc"](shuffled, _oof(feat, shuffled, groups_train, C, ng, L, grouped=True)))
    yardsticks = {k: float(max(L["auc"](y, feat["numeric"][:, i]), 1 - L["auc"](y, feat["numeric"][:, i])))
                  for i, k in enumerate(ML_NUMERIC_FEATURES) if k in ("host_len", "domain_len", "hyphens", "domain_entropy")}

    def sub_share(rows):
        """Share of hosts that have a subdomain (after dropping www), per class: a structural difference between the
        classes that has nothing to do with phishing and that a model will happily learn."""
        out = {}
        for label, name in ((True, "phishing"), (False, "benign")):
            rs = [r for r in rows if r["actual"] == label]
            out[name] = sum(1 for r in rs if r["parsed"].subdomain) / len(rs) if rs else math.nan
        return out
    confound = {"train": sub_share(train), "test": sub_share(test)}

    # -- 4. threshold from out-of-fold scores, then refit on all training rows and freeze
    tau = choose_threshold(oof, y, ML_TARGET_FPR, L)
    fit = _fit(feat, range(len(train)), y, C, ng, L)
    meta = {"training": {"file": Path(train_path).name, "sha256": _sha256(train_path), "rows": len(train),
                         "phishing": int(y.sum()), "benign": int((~y).sum()), "groups": len(set(groups_train))}}
    spec = export_model(fit, tau, meta, L)
    spec["adopted"] = True    # only so the evaluation can exercise the real code path; reset below unless every gate passes
    model = LinearURLModel(spec)
    if LinearURLModel.validate(spec):
        raise ValueError("exported model failed its own validation: " + LinearURLModel.validate(spec))

    # the shipped scorer must agree with scikit-learn, or the evaluation says nothing about what ships
    sk = _predict(fit, featurize(test, L), range(len(test)), L)
    py = np.array([model.score(r["parsed"]) for r in test])
    max_diff = float(np.abs(sk - py).max())

    # -- 5. one pass over the independent test set
    sysm = _systems(test, model, "host_url")
    conf = {k: _confusion(v, yt) for k, v in sysm.items()}
    boot = paired_bootstrap(sysm["rules"], sysm["hybrid"], yt, L)
    bands = OrderedDict()
    for cat in sorted({r["category"] for r in test if not r["actual"]}):
        ix = [i for i, r in enumerate(test) if r["category"] == cat]
        bands[cat] = {k: sum(sysm[k][i] for i in ix) / len(ix) for k in sysm} | {"n": len(ix)}
    auc_test = float(L["auc"](yt, py))
    # context only: the same phishing URLs with their real paths (benign rows are bare home pages, so no FPR here)
    full = [r for r in test if r["actual"]]
    full_rules = sum(classify_url(r["url"], [])["verdict"] in (SUSPICIOUS, MALICIOUS) for r in full)
    full_hybrid = sum(classify_url(r["url"], [], model=model)["verdict"] in (SUSPICIOUS, MALICIOUS) for r in full)

    # -- secondary guard: the author's independent holdout (written by hand, full URLs)
    hold = [r for r in load_datasets(DEFAULT_DATASETS) if r["split"] == "holdout" and r["category"] not in UNSCORED_CATEGORIES]
    hs = _systems(hold, model, "url")
    yh = np.array([r["actual"] for r in hold])
    hold_conf = {k: _confusion(v, yh) for k, v in hs.items()}
    extra_fp = [r["url"] for r, a, b in zip(hold, hs["rules"], hs["hybrid"]) if b and not a and not r["actual"]]

    # -- gates
    f = conf["hybrid"]
    gates = OrderedDict()
    gates["enough_test_data"] = f["positives"] >= 100 and f["negatives"] >= 500
    gates["recall_gain"] = boot["delta_recall"] >= 0.05 and boot["delta_recall_ci"][0] > 0
    gates["fpr_ceiling"] = f["fpr_ci"][1] <= 0.03
    gates["holdout_guard"] = len(extra_fp) <= 1
    gates["no_leakage_signs"] = abs(best["grouped_cv_auc"] - random_auc) <= 0.03 and 0.45 <= shuffled_auc <= 0.55
    adopted = all(gates.values())
    spec["adopted"] = adopted
    spec["evaluation"] = {
        "test_file": Path(test_path).name, "test_sha256": _sha256(test_path), "test_rows": len(test),
        "rules_recall": conf["rules"]["recall"], "rules_fpr": conf["rules"]["fpr"],
        "hybrid_recall": f["recall"], "hybrid_fpr": f["fpr"], "model_auc": auc_test,
        "gates": dict(gates), "verdict": "adopted" if adopted else "not adopted",
        "rules_sha256": rules_sha256(),
    }
    return {
        "L": {k: L[k] for k in ("sklearn", "numpy")}, "spec": spec, "adopted": adopted, "gates": gates,
        "train": {"rows": len(train), "phishing": int(y.sum()), "benign": int((~y).sum()), "skipped": skipped_train,
                  "groups": len(set(groups_train)), "file": Path(train_path).name, "sha256": _sha256(train_path)},
        "test": {"rows": len(test), "phishing": int(yt.sum()), "benign": int((~yt).sum()), "skipped": skipped_test,
                 "groups": len(set(groups_test)), "file": Path(test_path).name, "sha256": _sha256(test_path)},
        "grid": [{k: g[k] for k in ("C", "hashed_3grams", "grouped_cv_auc")} for g in grid],
        "selected": {"C": C, "hashed_3grams": ng, "grouped_cv_auc": best["grouped_cv_auc"], "threshold": tau,
                     "oof_fpr": float((oof[~y] >= tau).mean()), "oof_recall": float((oof[y] >= tau).mean())},
        "confound": confound,
        "leakage": {"random_cv_auc": random_auc, "grouped_cv_auc": best["grouped_cv_auc"], "shuffled_label_auc": shuffled_auc,
                    "univariate_auc": yardsticks},
        "scorer_max_abs_diff_vs_sklearn": max_diff,
        "test_conf": conf, "bootstrap": boot, "bands": bands, "test_auc": auc_test,
        "full_url_phish": {"n": len(full), "rules": full_rules, "hybrid": full_hybrid},
        "holdout": {"n": len(hold), "conf": hold_conf, "extra_false_positives": extra_fp},
    }


def ml_console_summary(res: dict) -> str:
    c, b = res["test_conf"], res["bootstrap"]
    out = [f"ML evaluation: train {res['train']['rows']} rows ({res['train']['file']}), "
           f"independent test {res['test']['rows']} rows ({res['test']['file']}: {res['test']['phishing']} phishing / "
           f"{res['test']['benign']} benign)",
           f"Selected: C={res['selected']['C']}, hashed 3-grams={res['selected']['hashed_3grams']}, "
           f"grouped-CV AUC {res['selected']['grouped_cv_auc']:.3f}, threshold {res['selected']['threshold']:.4f}"]
    for name in ("rules", "model", "hybrid"):
        m = c[name]
        out.append(f"  {name:7s} recall {pct_ci(m['recall'], m['recall_ci'])}   FPR {pct_ci(m['fpr'], m['fpr_ci'], 1)}")
    out.append(f"  hybrid - rules: recall {b['delta_recall'] * 100:+.1f} pts (95% {b['delta_recall_ci'][0] * 100:+.1f} to "
               f"{b['delta_recall_ci'][1] * 100:+.1f}), FPR {b['delta_fpr'] * 100:+.2f} pts")
    out.append("Gates:")
    out += [f"  [{'PASS' if ok else 'FAIL'}] {k}: {ML_GATES[k]}" for k, ok in res["gates"].items()]
    out.append("VERDICT: " + ("ADOPT the model as an optional component (still off unless ENABLE_ML_MODEL=1)."
                              if res["adopted"] else "DO NOT ADOPT. The model stays disabled."))
    return "\n".join(out)


ML_DISCLOSURE = (
    "**Order of events, for the record.** (1) The test file was scored once, for AUC only, on three exploratory model "
    "variants, before the benign sample was widened to three popularity bands and before the selection procedure, "
    "threshold rule and gates were fixed in code; no feature, threshold or gate was set from test results. (2) The first "
    "full run failed the holdout guard. Diagnosis: all of the extra false positives were ordinary subdomain hosts of "
    "major sites. (3) A builder bug was found (benign tenants of a shared-hosting platform were collapsed into one row by "
    "keying on the registered domain) and fixed; it made almost no difference, because the top-sites list simply has "
    "almost no subdomain hosts. Features, grid, threshold rule and gates were left unchanged. The holdout guard was "
    "therefore consulted twice, and the test set is not perfectly untouched. Rebuild the data from a fresh snapshot "
    "(`python tools/build_ml_dataset.py`) and re-run `python evaluate.py --ml` before relying on these figures."
)


def render_ml_report(res: dict) -> str:
    c, b, sel, lk = res["test_conf"], res["bootstrap"], res["selected"], res["leakage"]
    spec, tr, te = res["spec"], res["train"], res["test"]
    L: list[str] = []
    w = L.append
    w("# Optional ML component: evidence report\n")
    w("Generated by `python evaluate.py --ml --report`. It answers one question: **does a trained model improve on the "
      "existing rules and threat-database lookups enough to ship, measured on data it never saw?**\n")
    w("## Verdict\n")
    if res["adopted"]:
        w(f"**Adopted as an optional component.** Every gate passed. On the independent test set the rules flagged "
          f"{pct(c['rules']['recall'])} of phishing links; rules plus model flagged {pct(c['hybrid']['recall'])} "
          f"({b['delta_recall'] * 100:+.1f} points, 95% interval {b['delta_recall_ci'][0] * 100:+.1f} to "
          f"{b['delta_recall_ci'][1] * 100:+.1f}), while the false-positive rate went from {pct(c['rules']['fpr'], 2)} to "
          f"{pct(c['hybrid']['fpr'], 2)}. The model stays **off by default** (`ENABLE_ML_MODEL=1` turns it on) and can only "
          "add a *Suspicious* verdict: it never produces *Malicious* and never overrides a threat-database result.\n")
    else:
        failed = [k for k, ok in res["gates"].items() if not ok]
        w("**Not adopted.** The model failed these gates: " + ", ".join(f"`{k}`" for k in failed) + ". "
          "The artifact is written with `adopted: false` and the scanner ignores it, so detection is unchanged.\n")
        if "holdout_guard" in failed:
            hc = res["holdout"]["conf"]
            w(f"**Why.** On the author's holdout the hybrid flagged {hc['hybrid']['fp']} of {hc['hybrid']['negatives']} legitimate "
              f"URLs, against {hc['rules']['fp']} for the rules alone, almost all of them ordinary subdomain hosts of major sites "
              f"(it also found more phishing there: recall {pct(hc['rules']['recall'], 0)} to {pct(hc['hybrid']['recall'], 0)}, "
              "but a false-alarm rate that high would teach users to ignore the scanner). The large recall gain on the feed test set "
              f"({b['delta_recall'] * 100:+.1f} points) is **not trusted**: the two classes in the feed data differ structurally "
              "(see the section below), and the model learned that difference as much as it learned anything about phishing.\n")
            w("**What would change the answer:** a benign sample with realistic subdomains and deep links (a vetted allow-list, "
              "or links your own users click, collected with consent), not a list of registered domains. Rebuild the data, "
              "re-run `python evaluate.py --ml --report`, and the same gates decide again. Until then the rules and "
              "threat-database lookups are the detection, and the model is not part of it.\n")
    w("This is a measured statement about one dataset, not a claim that the scanner 'uses AI to detect phishing'. "
      "Read the limitations before quoting any number.\n")

    w("## What was compared\n")
    w("| System | Definition |\n|---|---|\n"
      "| Rules | the existing URL-structure heuristics (`analyze_structure`), no threat databases |\n"
      "| Model | logistic regression on host-only features, scored in plain Python |\n"
      "| Hybrid | the shipped design: Suspicious if the rules *or* the model flags it |\n")
    w("Threat-database lookups (Safe Browsing, URLhaus) need network and API keys and are not part of any figure here. "
      "They remain the only source of *confirmed* verdicts, and the model cannot override them. Comparing the model "
      "with them directly is not possible offline; the model is judged on what it adds beyond the rules.\n")

    w("## Results on the independent test set\n")
    w(f"`{te['file']}`: {te['phishing']} phishing rows (OpenPhish public feed) and {te['benign']} benign rows "
      f"(top-sites list, three popularity bands). {te['groups']} groups, none shared with training. Both classes are "
      "reduced to the same host-only form first.\n")
    w(_row_table(["System", "Recall (phishing flagged)", "False-positive rate", "Precision", "F1"],
                 [[n, pct_ci(m["recall"], m["recall_ci"]), pct_ci(m["fpr"], m["fpr_ci"], 1), pct_ci(m["precision"], m["precision_ci"]), pct(m["f1"])]
                  for n, m in (("Rules", c["rules"]), ("Model alone", c["model"]), ("**Hybrid**", c["hybrid"]))]))
    w(f"\nPaired bootstrap, {ML_BOOTSTRAPS} resamples, hybrid minus rules: recall **{b['delta_recall'] * 100:+.1f} points** "
      f"(95% interval {b['delta_recall_ci'][0] * 100:+.1f} to {b['delta_recall_ci'][1] * 100:+.1f}); false-positive rate "
      f"**{b['delta_fpr'] * 100:+.2f} points** (95% interval {b['delta_fpr_ci'][0] * 100:+.2f} to {b['delta_fpr_ci'][1] * 100:+.2f}). "
      f"Model AUC on this set: {res['test_auc']:.3f}. Precision here reflects {te['phishing'] / te['rows']:.0%} phishing; see the "
      "prevalence table for real traffic.\n")

    w("### False-positive rate by how popular the benign site is\n")
    w("Benign rows are drawn equally from rank bands a (1-50k), b (50k-300k) and c (300k-1M). Popular sites look tidy; a "
      "model that only learnt 'popular = benign' would look fine on band a and fail on band c. The long tail also "
      "contains junk that is not truly benign, so band c *overstates* the false-positive rate.\n")
    w(_row_table(["Band", "Benign rows", "Rules flagged", "Model flagged", "Hybrid flagged"],
                 [[k.replace("top-sites-", ""), v["n"], pct(v["rules"], 2), pct(v["model"], 2), pct(v["hybrid"], 2)] for k, v in res["bands"].items()]))
    w("")
    w("### What precision would look like on real traffic\n")
    w("Using the hybrid's recall and false-positive rate from this test set. The last column uses the upper end of the "
      "false-positive interval.\n")
    h = c["hybrid"]
    w(_row_table(["Share of scanned links that are phishing", "Precision (measured FPR)", "Precision (FPR at upper bound)"],
                 [[pct(p_, 1 if p_ < 0.01 else 0), pct(precision_at_prevalence(h["recall"], h["fpr"], p_)),
                   pct(precision_at_prevalence(h["recall"], h["fpr_ci"][1], p_))] for p_ in PREVALENCES]))
    w("\nAt realistic prevalence most *Suspicious* flags from any address-shape model will be false alarms. That is why "
      "the model can only raise a caution, never a confirmed verdict.\n")

    w("## Gates (fixed in code before the final run)\n")
    w(_row_table(["Gate", "Requirement", "Result"], [[f"`{k}`", ML_GATES[k], "PASS" if ok else "**FAIL**"] for k, ok in res["gates"].items()]))
    w("")

    cf = res["confound"]
    gap = abs(cf["train"]["phishing"] - cf["train"]["benign"])
    w("## A structural difference between the two classes\n")
    w(_row_table(["Hosts with a subdomain (www ignored)", "Phishing", "Benign"],
                 [["Training file", pct(cf["train"]["phishing"], 0), pct(cf["train"]["benign"], 0)],
                  ["Test file", pct(cf["test"]["phishing"], 0), pct(cf["test"]["benign"], 0)]]))
    w("")
    if gap > 0.2:
        w("**This gap is a property of how the data was collected, not of phishing.** Feed phishing is full of throw-away "
          "tenant hosts (`name.platform.tld`), while a top-sites list names registered domains. A model can score well on "
          "this test set simply by learning \"has a subdomain\", and would then flag ordinary sites such as "
          "`docs.google.com` or `login.microsoftonline.com`. The test-set figures above therefore **overstate** what "
          "the model would do on real traffic, and the holdout guard below exists to catch exactly this.\n")
    else:
        w("The two classes have a similar share of subdomain hosts, so this particular shortcut is not available.\n")

    w("## Leakage and sanity checks\n")
    w(_row_table(["Check", "Value", "What it tells you"], [
        ["Grouped-CV AUC (selected model)", f"{lk['grouped_cv_auc']:.3f}", "training data only; no group on both sides of a fold"],
        ["Random-CV AUC (same model)", f"{lk['random_cv_auc']:.3f}", "if this were far above grouped-CV, the model would be memorising groups"],
        ["AUC with shuffled labels", f"{lk['shuffled_label_auc']:.3f}", "should be about 0.5; anything else means the pipeline leaks"],
        ["Best single-feature AUC (host length, domain length, hyphens, entropy)", f"{max(lk['univariate_auc'].values()):.3f}",
         "how far a trivial feature already gets; the model's extra value is the gap to this"],
        ["Shipped scorer vs scikit-learn, max difference", f"{res['scorer_max_abs_diff_vs_sklearn']:.1e}", "the plain-Python scorer is what runs, and it matches"],
    ]))
    w("\nModel settings were chosen by grouped CV on the training data (grid below). The threshold is the lowest score "
      f"whose out-of-fold false-positive rate was at most {ML_TARGET_FPR:.0%}; it came out at {sel['threshold']:.4f} "
      f"(out-of-fold recall {pct(sel['oof_recall'])}, false-positive rate {pct(sel['oof_fpr'], 2)}).\n")
    w(_row_table(["C", "Hashed 3-grams", "Grouped-CV AUC"],
                 [[g["C"], "yes" if g["hashed_3grams"] else "no", f"{g['grouped_cv_auc']:.4f}" + (" **(selected)**" if (g["C"], g["hashed_3grams"]) == (sel["C"], sel["hashed_3grams"]) else "")] for g in res["grid"]]))
    w("")

    hc, ho = res["holdout"]["conf"], res["holdout"]
    w("## Guard: the author's independent holdout\n")
    w(f"`independent_holdout.csv` ({ho['n']} scored rows, full URLs written by hand, a different distribution from the "
      "feeds). It is used only as a guard against the model adding false alarms on carefully curated legitimate sites.\n")
    w(_row_table(["System", "Recall", "False positives", "Missed"], [[n, pct_ci(hc[k]["recall"], hc[k]["recall_ci"]), f"{hc[k]['fp']} of {hc[k]['negatives']}", hc[k]["fn"]]
                                                                      for n, k in (("Rules", "rules"), ("Model alone", "model"), ("Hybrid", "hybrid"))]))
    if ho["extra_false_positives"]:
        w("\nLegitimate URLs the hybrid flagged that the rules did not: " + ", ".join(_md_escape(u) for u in ho["extra_false_positives"]) + ".")
    w("")
    fu = res["full_url_phish"]
    w(f"Context only: on the {fu['n']} test phishing URLs *with their real paths*, the rules flag {fu['rules']} and the hybrid "
      f"{fu['hybrid']}. No false-positive rate is given for that variant because the benign rows have no deep links.\n")

    w("## Data, provenance and protocol\n")
    w(_row_table(["Item", "Value"], [
        ["Training file", f"`{tr['file']}`: {tr['phishing']} phishing (Phishing.Database ACTIVE list) / {tr['benign']} benign (top-sites list); SHA-256 `{tr['sha256']}`"],
        ["Test file", f"`{te['file']}`: {te['phishing']} phishing (OpenPhish public feed) / {te['benign']} benign; SHA-256 `{te['sha256']}`"],
        ["Leakage control", "no registered domain (or full host, on shared-hosting platforms) appears in both files; at most 3 URLs per group; benign domains unique across splits"],
        ["Features", f"15 numeric host-shape features, one-hot TLD, hashed 3-character host pieces; no brand list, no rule output, no path"],
        ["Model", "L2 logistic regression (scikit-learn " + res["L"]["sklearn"] + "), exported to JSON and scored in plain Python"],
        ["Seed / folds", f"{ML_SEED} / {ML_CV_FOLDS}"],
        ["Rules SHA-256", f"`{spec['evaluation']['rules_sha256']}`"],
    ]))
    w("\n" + ML_DISCLOSURE + "\n")

    w("## Limitations\n")
    for t in (
        "**The labels are what the feeds say.** Feed entries can be stale, wrongly listed, or already taken down. The benign "
        "list is a popularity ranking, not a verified-clean list.",
        "**Host-only.** To keep the comparison fair the model and the rules both see only the host here. In real use the rules "
        "also see the path and query, so the rules' recall on full URLs is higher than the host-only figure (context line above).",
        "**Benign rows are home pages.** Real users click deep links on ordinary sites. The false-positive rate here is for host "
        "shapes, not for every page of every site.",
        "**Look-alike shortcuts remain possible.** Feeds are dominated by throw-away hosts on free platforms and cheap TLDs; "
        "a model can learn those habits rather than anything fundamental. It will age as attackers change habits, so "
        "re-run this evaluation on a fresh feed snapshot before each release and on a schedule.",
        "**It cannot see what the address does not show.** A compromised legitimate site, a trusted-platform page or an open "
        "redirect looks normal from the host. Only a threat database, or fetching the page, can catch those.",
        "**The score is not a probability.** It is a ranking, and no calibration is claimed; the scanner's `confidence` stays null.",
    ):
        w("- " + t)
    w("")
    w("## Reproduce\n")
    w("```")
    w("python -m pip install -r requirements.txt -r requirements-ml.txt")
    w("python tools/build_ml_dataset.py        # optional: rebuild the feed files from fresh public lists (needs network)")
    w("python evaluate.py --ml --report         # re-runs everything and rewrites this report and detection/ml_model.json")
    w("```\n")
    w("Same files, same code and the same library versions give the same numbers.\n")
    return "\n".join(L)


def ml_results_json(res: dict) -> dict:
    keep = ("train", "test", "selected", "leakage", "confound", "grid", "gates", "adopted", "test_conf", "bootstrap", "bands", "test_auc",
            "full_url_phish", "scorer_max_abs_diff_vs_sklearn", "L")
    out = {k: res[k] for k in keep}
    out["holdout"] = {"n": res["holdout"]["n"], "conf": res["holdout"]["conf"],
                      "extra_false_positives": len(res["holdout"]["extra_false_positives"])}
    out["gate_definitions"] = dict(ML_GATES)
    out["rules_sha256"] = res["spec"]["evaluation"]["rules_sha256"]
    return json.loads(json.dumps(out, default=lambda o: o.item() if hasattr(o, "item") else str(o)).replace("NaN", "null"))

# ----------------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("csv", nargs="*", default=[str(p) for p in DEFAULT_DATASETS],
                    help="labelled CSV file(s) (default: data/labelled_urls.csv and data/independent_holdout.csv)")
    ap.add_argument("--split", help="score only rows whose split column equals this (dev or holdout)")
    ap.add_argument("--report", action="store_true", help="write reports/evaluation_report.md and evaluation_results.json")
    ap.add_argument("--out-dir", default=str(REPORT_DIR), help="where --report writes (default: reports/)")
    ap.add_argument("--ml", action="store_true", help="evaluate the optional ML model against the rules (needs requirements-ml.txt)")
    ap.add_argument("--ml-train", default=str(ML_TRAIN), help="training CSV for --ml (default: data/feed_train.csv)")
    ap.add_argument("--ml-test", default=str(ML_TEST), help="independent test CSV for --ml (default: data/feed_test.csv)")
    ap.add_argument("--model-out", default=str(MODEL_PATH), help="where --ml --report writes the model (default: detection/ml_model.json)")
    args = ap.parse_args(argv)

    if args.ml:
        try:
            res = ml_evaluate(args.ml_train, args.ml_test)
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(ml_console_summary(res))
        if args.report:
            out = Path(args.out_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / "ml_evaluation.md").write_text(render_ml_report(res), encoding="utf-8", newline="\n")
            (out / "ml_results.json").write_text(json.dumps(ml_results_json(res), indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
            Path(args.model_out).write_text(json.dumps(res["spec"], indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
            print(f"\nWrote {out / 'ml_evaluation.md'}, {out / 'ml_results.json'} and {args.model_out}")
        return 0

    try:
        res = evaluate(args.csv, args.split)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(console_summary(res, args.csv))
    if args.report:
        out = Path(args.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "evaluation_report.md").write_text(render_report(res, args.csv), encoding="utf-8", newline="\n")
        (out / "evaluation_results.json").write_text(
            json.dumps(results_json(res, args.csv), indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        print(f"\nWrote {out / 'evaluation_report.md'} and {out / 'evaluation_results.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
