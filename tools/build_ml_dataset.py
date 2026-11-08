"""Build the two real-feed CSVs used to judge the optional ML model (needs network; run it yourself).

    python tools/build_ml_dataset.py                 # downloads the three public lists, writes data/feed_train.csv,
                                                     # data/feed_test.csv and data/feed_manifest.json
    python tools/build_ml_dataset.py --phish-train-file pdb.txt --phish-test-file openphish.txt --benign-file top.txt

Why two files from different places (the point is to avoid leakage):

* ``feed_train.csv``  phishing from the Phishing.Database "ACTIVE" list, benign from a top-sites list.
* ``feed_test.csv``   phishing from the OpenPhish public feed, benign from *different* top-sites domains.

The test phishing comes from a different collector than the training phishing, and any test URL whose group (the
registered domain, or the full host on shared-hosting platforms) also occurs in the training data is dropped. Benign
domains are disjoint by construction. Nothing is tuned on the test file.

SAFETY: this script only downloads text lists. It never opens a listed URL. The phishing URLs are live or recently
live threats: do not click them and keep the CSVs out of anything that turns URLs into links.

Known limits, repeated in the generated manifest and in the ML report:

* Benign rows are bare home pages (``https://host/``) because a top-sites list has no deep links. Every comparison in
  ``evaluate.py --ml`` therefore reduces BOTH classes to the same host-only form, so path length cannot be a shortcut.
* The top-sites list is a popularity ranking, not a verified-clean list. Benign domains are drawn equally from three
  rank bands (a: 1-50k, b: 50k-300k, c: 300k-1M) so a model cannot get by on "popular sites look tidy". The long
  tail contains some junk, which makes the measured false-positive rate pessimistic, never optimistic.
* The feeds list what their crawlers saw. They are not a sample of all phishing.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import requests  # noqa: E402

from detection.url_features import InvalidURLError, parse_url  # noqa: E402

PHISH_TRAIN_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
PHISH_TEST_URL = "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt"
BENIGN_URL = "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-1000000-domains"
TIMEOUT = (5, 120)
MAX_BYTES = 120 * 1024 * 1024

SEED = 7
BENIGN_BANDS = (("a", 0, 50_000), ("b", 50_000, 300_000), ("c", 300_000, 1_000_000))  # rank ranges, 0-based slices
N_PHISH_TRAIN, N_BENIGN_TRAIN, N_BENIGN_TEST = 3000, 3000, 1500
PER_GROUP_CAP = 3            # at most this many URLs from one group (a campaign can list thousands on one host)
PER_PLATFORM_CAP = {"train": 150, "test": 150}   # at most this many from one shared-hosting platform
SHARED_HOST_MIN_HOSTS = 25   # a registered domain with this many distinct hosts in the feed is a multi-tenant platform


def download(url: str) -> bytes:
    with requests.get(url, timeout=TIMEOUT, stream=True, allow_redirects=False) as r:
        r.raise_for_status()
        data = b""
        for chunk in r.iter_content(1 << 16):
            data += chunk
            if len(data) > MAX_BYTES:
                raise ValueError(f"{url} is larger than expected; refusing to read it")
    return data


def _lines(raw: bytes) -> list[str]:
    return [ln.strip() for ln in raw.decode("utf-8", errors="ignore").splitlines() if ln.strip()]


def parse_phish(lines: list[str]) -> list:
    """http(s) lines that the scanner's own validation accepts. Returns ParsedURL objects."""
    out, seen = [], set()
    for line in lines:
        if not line.lower().startswith(("http://", "https://")) or line in seen:
            continue
        seen.add(line)
        try:
            out.append(parse_url(line))
        except InvalidURLError:
            continue
    return out


def parse_benign(lines: list[str], lo: int, hi: int) -> list:
    out = []
    for line in lines[lo:hi]:
        try:
            out.append(parse_url(f"https://{line.lower()}/"))
        except InvalidURLError:
            continue
    return out


def shared_platforms(parsed: list) -> set[str]:
    hosts = defaultdict(set)
    for p in parsed:
        hosts[p.registered_domain].add(p.hostname)
    return {d for d, h in hosts.items() if len(h) >= SHARED_HOST_MIN_HOSTS}


def group_key(p, platforms: set[str]) -> str:
    """Registered domain, or the full host when the registered domain is a shared-hosting platform."""
    return p.hostname if p.registered_domain in platforms else p.registered_domain


def capped_sample(parsed: list, platforms: set[str], n: int, split: str, rng: random.Random,
                  banned: set[str] = frozenset()) -> list:
    """Shuffle, apply the per-group and per-platform caps, drop banned groups, then take ``n``."""
    pool = parsed[:]
    rng.shuffle(pool)
    per_group, per_platform, kept = Counter(), Counter(), []
    for p in pool:
        g = group_key(p, platforms)
        if g in banned or per_group[g] >= PER_GROUP_CAP:
            continue
        if p.registered_domain in platforms and per_platform[p.registered_domain] >= PER_PLATFORM_CAP[split]:
            continue
        per_group[g] += 1
        per_platform[p.registered_domain] += 1
        kept.append(p)
        if len(kept) >= n:
            break
    return kept


def build(train_raw: bytes, test_raw: bytes, benign_raw: bytes) -> tuple[list[dict], list[dict], dict, set[str]]:
    rng = random.Random(SEED)
    train_all, test_all = parse_phish(_lines(train_raw)), parse_phish(_lines(test_raw))
    platforms = shared_platforms(train_all) | shared_platforms(test_all)

    train_phish = capped_sample(train_all, platforms, N_PHISH_TRAIN, "train", rng)
    train_groups = {group_key(p, platforms) for p in train_all}   # every group the training feed has ever listed
    test_pool = [p for p in test_all if group_key(p, platforms) not in train_groups]
    test_phish = capped_sample(test_pool, platforms, len(test_pool), "test", rng)
    phish_groups = train_groups | {group_key(p, platforms) for p in test_all}

    benign_lines = _lines(benign_raw)
    # One row per GROUP across all bands and both splits. A group is the registered domain, or the full host on a
    # shared-hosting platform, exactly as for phishing. (Keying on the registered domain alone would collapse every
    # benign tenant of a platform such as blogspot.com into one row and leave the benign side with no subdomain
    # structure, which a model then learns as "has a subdomain = phishing".)
    used, per_platform, benign_train, benign_test = set(), Counter(), [], []
    for band, lo, hi in BENIGN_BANDS:
        pool = [p for p in parse_benign(benign_lines, lo, hi) if group_key(p, platforms) not in phish_groups]
        rng.shuffle(pool)
        picked = []
        for p in pool:
            g = group_key(p, platforms)
            if g in used:
                continue
            if p.registered_domain in platforms and per_platform[p.registered_domain] >= PER_PLATFORM_CAP["train"]:
                continue
            used.add(g)
            per_platform[p.registered_domain] += 1
            picked.append((band, p))
            if len(picked) >= (N_BENIGN_TRAIN + N_BENIGN_TEST) // len(BENIGN_BANDS):
                break
        cut = N_BENIGN_TRAIN // len(BENIGN_BANDS)
        benign_train += picked[:cut]
        benign_test += picked[cut:]

    def rows(items, label, category, split, source):
        return [{"url": p.normalized if label == "phishing" else f"https://{p.hostname}/", "label": label,
                 "category": category, "split": split, "source": source} for p in items]

    def benign_rows(items, split):
        return [{"url": f"https://{p.hostname}/", "label": "benign", "category": f"top-sites-{band}", "split": split,
                 "source": "top-domains-list"} for band, p in items]

    train = rows(train_phish, "phishing", "feed-phish", "train", "phishing-database-active") + benign_rows(benign_train, "train")
    test = rows(test_phish, "phishing", "feed-phish", "test", "openphish-public-feed") + benign_rows(benign_test, "test")
    stats = {
        "phish_train_candidates": len(train_all), "phish_test_candidates": len(test_all),
        "phish_test_dropped_group_overlap": len(test_all) - len(test_pool),
        "shared_hosting_platforms_found": len(platforms),
        "phish_train": len(train_phish), "phish_test": len(test_phish),
        "benign_train": len(benign_train), "benign_test": len(benign_test),
    }
    return train, test, stats, platforms


def write_csv(path: Path, rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["url", "label", "category", "split", "source"], lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--phish-train-file", help="local copy of the training phishing list (default: download)")
    ap.add_argument("--phish-test-file", help="local copy of the test phishing list (default: download)")
    ap.add_argument("--benign-file", help="local copy of the top-sites list, one domain per line, best rank first")
    ap.add_argument("--out-dir", default=str(ROOT / "data"))
    args = ap.parse_args(argv)

    def get(path, url):
        return Path(path).read_bytes() if path else download(url)

    try:
        train_raw = get(args.phish_train_file, PHISH_TRAIN_URL)
        test_raw = get(args.phish_test_file, PHISH_TEST_URL)
        benign_raw = get(args.benign_file, BENIGN_URL)
    except (OSError, requests.RequestException, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    train, test, stats, platforms = build(train_raw, test_raw, benign_raw)
    out = Path(args.out_dir)
    write_csv(out / "feed_train.csv", train)
    write_csv(out / "feed_test.csv", test)
    manifest = {
        "built": date.today().isoformat(), "seed": SEED, "benign_bands": [list(b) for b in BENIGN_BANDS],
        "inputs": {name: {"url": url, "sha256": hashlib.sha256(raw).hexdigest()} for name, url, raw in (
            ("phish_train", PHISH_TRAIN_URL, train_raw), ("phish_test", PHISH_TEST_URL, test_raw),
            ("benign", BENIGN_URL, benign_raw))},
        "caps": {"per_group": PER_GROUP_CAP, "per_platform": PER_PLATFORM_CAP},
        "counts": stats,
        # evaluate.py reads this so it groups rows exactly as this script did (a small sample cannot re-derive it)
        "shared_hosting_platforms": sorted(platforms),
        "limits": ["benign rows are bare home pages, so evaluation reduces both classes to host-only form",
                   "the top-sites list is a popularity ranking, not a verified-clean list",
                   "feeds list what their crawlers saw; they are not a sample of all phishing"],
    }
    (out / "feed_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(stats, indent=2))
    print(f"Wrote {out / 'feed_train.csv'}, {out / 'feed_test.csv'} and {out / 'feed_manifest.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
