"""Build a genuinely independent evaluation CSV from public feeds (needs network; run it yourself).

    python tools/build_feed_dataset.py --out data/feed_holdout.csv --phish 300 --benign 300
    python evaluate.py data/labelled_urls.csv data/feed_holdout.csv

Positives: the OpenPhish community feed (a list of currently active phishing URLs).
Negatives: a random sample of the Tranco top-sites list, written as https://<domain>/ .

SAFETY: this script only downloads text lists. It never opens a listed URL. The phishing URLs are live threats:
do not click them, and keep the CSV out of anything that turns URLs into links.

Limits to state when quoting results: Tranco negatives are site home pages, which are easier than real
deep links, and the feed's own selection biases apply (OpenPhish lists what its crawlers saw). Sample once, freeze the
file (the output records the date), and do not tune rules on it.
"""
from __future__ import annotations

import argparse
import csv
import io
import random
import sys
import zipfile
from datetime import date

import requests

OPENPHISH_FEED = "https://openphish.com/feed.txt"
TRANCO_TOP_1M = "https://tranco-list.eu/top-1m.csv.zip"
TIMEOUT = (5, 60)
MAX_BYTES = 80 * 1024 * 1024


def _download(url: str) -> bytes:
    with requests.get(url, timeout=TIMEOUT, stream=True, allow_redirects=False) as r:
        r.raise_for_status()
        data = b""
        for chunk in r.iter_content(1 << 16):
            data += chunk
            if len(data) > MAX_BYTES:
                raise ValueError(f"{url} is larger than expected; refusing to read it")
    return data


def parse_openphish(text: str) -> list[str]:
    """One URL per line; keep only http(s) lines with no whitespace."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith(("http://", "https://")) and not any(c.isspace() for c in line):
            out.append(line)
    return list(dict.fromkeys(out))


def parse_tranco(raw_csv: str, top: int = 100_000) -> list[str]:
    """Rows are 'rank,domain'. Returns https://domain/ for the first ``top`` ranks."""
    out = []
    for row in csv.reader(io.StringIO(raw_csv)):
        if len(row) >= 2 and row[0].isdigit() and int(row[0]) <= top and row[1]:
            out.append(f"https://{row[1].strip().lower()}/")
    return out


def sample(items: list[str], n: int, seed: int) -> list[str]:
    return random.Random(seed).sample(items, min(n, len(items)))


def build_rows(phish: list[str], benign: list[str], stamp: str) -> list[list[str]]:
    rows = [[u, "phishing", "openphish-feed", "holdout", f"openphish-{stamp}"] for u in phish]
    rows += [[u, "benign", "tranco-home-page", "holdout", f"tranco-{stamp}"] for u in benign]
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--phish", type=int, default=300)
    ap.add_argument("--benign", type=int, default=300)
    ap.add_argument("--top", type=int, default=100_000, help="sample benign sites from the top N Tranco ranks")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args(argv)
    try:
        phish = parse_openphish(_download(OPENPHISH_FEED).decode("utf-8", "replace"))
        z = zipfile.ZipFile(io.BytesIO(_download(TRANCO_TOP_1M)))
        benign = parse_tranco(z.read(z.namelist()[0]).decode("utf-8", "replace"), args.top)
    except (requests.RequestException, ValueError, zipfile.BadZipFile, KeyError) as exc:
        print(f"error: could not download the feeds: {type(exc).__name__}", file=sys.stderr)
        return 2
    rows = build_rows(sample(phish, args.phish, args.seed), sample(benign, args.benign, args.seed), date.today().isoformat())
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["url", "label", "category", "split", "source"])
        w.writerows(rows)
    print(f"wrote {len(rows)} rows to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
