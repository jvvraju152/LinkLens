# Labelled URL dataset

`labelled_urls.csv` is what `python evaluate.py` scores.

| Column | Meaning |
|---|---|
| `url` | The address. Never fetched by anything in this project. |
| `label` | `phishing` (positive) or `benign` (negative). Anything else is an error. |
| `category` | The pattern or kind of site (`brand-in-domain`, `regional-domain`, `ip-host-legit`, …). Used for the per-category tables. |
| `split` | `dev` (rules were tuned on it) or `holdout` (not tuned on). |
| `source` | Where the row came from, see below. |

## Provenance: read before quoting any number

- `curated-legit`: real, well-known domains with hand-written paths. Paths were not checked to be live.
- `synthetic-phish`: **invented** domains that follow documented phishing patterns. These are not real
  attacks and not from any feed. An invented domain may coincidentally exist; do not visit any URL here.
- `seed-v1`: the 59 rows the project started with, written alongside the original rules.

Because the phishing rows are synthetic, recall measured here is the rules' coverage of the patterns the
authors thought of, not of real phishing. For a real benchmark, export a feed (PhishTank/OpenPhish) plus a
top-sites sample (Tranco) to a CSV with `url,label` and run `python evaluate.py yourfile.csv`.

## Keeping the split honest

- Tune rules by looking at `dev` errors only.
- When `holdout` errors are fixed, that data has become dev data. Move those rows to `dev` and write a new
  holdout before claiming a fresh estimate.
- Categories listed in `UNSCORED_CATEGORIES` in `evaluate.py` (currently `shortener`) are reported but not
  scored, because their label depends on a destination the scanner never visits.

## Feed files for the ML evaluation (`feed_train.csv`, `feed_test.csv`, `feed_manifest.json`)

Built by `python tools/build_ml_dataset.py`; the manifest records the date, seed, caps, counts and the SHA-256 of each raw
input list. Columns are the same as above (`split` is `train` or `test`).

- `feed-phish`: **real** phishing URLs. Training rows come from the Phishing.Database ACTIVE list, test rows from the OpenPhish
  public feed. A different collector for the test rows, and no test group (registered domain, or full host on shared-hosting
  platforms) also occurs in the training data. These are live or recently live threats: never open them, and keep this file out
  of anything that turns URLs into links.
- `top-sites-a/b/c`: benign home pages from a popularity list, equal numbers from ranks 1-50k, 50k-300k and 300k-1M. A
  popularity ranking is not a verified-clean list, and the long tail contains some junk, which makes measured false-positive
  rates pessimistic.
- **Known flaw:** a top-sites list has almost no subdomain hosts, but feed phishing is full of them. Any model can exploit that.
  `evaluate.py --ml` measures the gap and the independent holdout guards against it. Do not quote feed-only numbers on their own.
- Do not tune rules or features on `feed_test.csv`. If it has been used for that, rebuild it from a fresh snapshot.

