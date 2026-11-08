# Development reference

Everything a contributor or examiner needs beyond the [README](../README.md): every setting, the full API, the security and privacy details, the file layout and how accuracy is measured. Deployment is in [`DEPLOYMENT.md`](DEPLOYMENT.md); the optional model is in [`ML.md`](ML.md).

## Testing

```
python tools/smoke_test.py https://your.domain               # end-to-end check of a RUNNING server (local or deployed)
```

The smoke test is the one that proves a *deployment* is right: HTTPS and certificate, HSTS and other headers, cookie flags, that source and data files are not served, that `/metrics` is private, a real scan, per-browser history, and (with `--rate-limit-test`) HTTP 429.

## Configuration

Everything is in `.env` (template: `.env.example`, every value documented). Numbers are clamped and bad values fall
back to defaults, so a typo can't switch a protection off.

| Variable | Purpose |
| --- | --- |
| `GOOGLE_SAFE_BROWSING_API_KEY`, `URLHAUS_AUTH_KEY` | threat-database lookups |
| `THREAT_INTEL_*`, `LOOKUP_DEADLINE_SECONDS` | timeouts, cache, cooldown, circuit breaker, overall deadline |
| `THREAT_INTEL_SEND_QUERY` | `0` strips `?query`/`#fragment` before a link is sent to third parties |
| `CORS_ORIGINS`, `ALLOW_NULL_ORIGIN` | exact origins allowed to call the API from another site |
| `EXTENSION_ORIGINS` | exact `chrome-extension://<id>` origins allowed to use `/scan` and `/health` (default: the bundled extension; empty turns it off) |
| `RATE_LIMIT_PER_MINUTE`, `GLOBAL_RATE_LIMIT_PER_MINUTE`, `API_…`, `CONTACT_…` | rate limits |
| `TRUSTED_PROXY_COUNT`, `HSTS`, `COOKIE_SECURE` | running behind a proxy / HTTPS |
| `HISTORY_*`, `CONTACT_*` | switch on/off, retention days, size caps |
| `FLASK_DEBUG`, `HEALTH_DETAIL` | development switches (both off by default) |
| `APP_ENV` | `production` turns on startup warnings and refuses debug mode |
| `LOG_FORMAT`, `LOG_LEVEL`, `LOG_REQUESTS` | `json` log lines, level, and the per-request line on/off |
| `METRICS_TOKEN` | enables `GET /metrics` for a bearer token; empty = off (404) |
| `*_FILE` (e.g. `GOOGLE_SAFE_BROWSING_API_KEY_FILE`) | read a secret from a file (Docker/Kubernetes secrets) |
| `ENABLE_ML_MODEL` | `1` loads the optional ML model, but only if `detection/ml_model.json` says `adopted: true` (see [`ML.md`](ML.md)). Off by default. |

With no API keys the app still runs, but results are only "Unable to verify" or "Suspicious". It never says
"No known threat detected" without a successful lookup.

## API

* `POST /scan` `{"url": "..."}` returns `verdict`, `verdict_code` (`malicious` / `suspicious` / `no_known_threat` / `unable_to_verify`), `confirmed`, `severity`, `summary`, `evidence[]`, `sources[]` (`hit` / `clear` / `skipped` / `error` per provider), `risk_score`, `basis`, `lookup_sent_query`, `scanned_at`.
  A listed browser extension may call `/scan` and `/health` cross-origin. Its checks are **not** saved to history and issue no cookie.
* `GET /history`: this browser's scans, newest first, each with `id`, `scanned_at`, `url`, `verdict`, `verdict_code`, `confirmed`, `risk_score`, `threat_sources[]`, `evidence[]` and `sources[]`. Filters: `q` (site/address/verdict/source text), `verdict` (comma list of codes), `source`, `days`, `confirmed=1`, `sort` (`newest`|`oldest`|`risk`), `limit` (max 100), `offset`. The first page also returns dashboard `stats` over all saved scans (`tz` = minutes east of UTC, for daily totals).
* `GET /history/export?format=csv|json` (same filters): download this browser's scans. CSV cells that start with `= + - @` are prefixed with `'` so spreadsheets do not run them as formulas.
* `DELETE /history/<id>`: delete one scan; `DELETE /history`: delete all of this browser's scans. A scan id that belongs to another browser answers 404, exactly like one that does not exist.
* `POST /contact` `{"name", "email", "message", "consent": true}`: stores a message (see Privacy).
* `GET /privacy`: what this server stores and sends, as configured. The Privacy page renders from it.
* `GET /evaluation`: the latest measured accuracy (`stale: true` if the rules changed since the report).
* `GET /health`: `{"status": "ok"}` (provider details only with `HEALTH_DETAIL=1`). Liveness.
* `GET /ready`: `{"status": "ready"}`, or 503 naming `history_store` / `contact_store` when a data file cannot be written. Readiness.
* `GET /metrics`: Prometheus text counters. **404 unless `METRICS_TOKEN` is set**; needs `Authorization: Bearer <token>`.
* `GET /robots.txt`: asks crawlers to stay off the API paths.

Errors always look like `{"error": "...", "code": "...", "request_id": "..."}`. `error` is a short fixed message;
the request id matches a line in the server log.

## Security

What is in place:

| Area | Protection |
| --- | --- |
| CORS | Exact-match origins only; `*` and malformed entries are ignored; `null` only with an explicit dev flag; no credentials. State-changing requests (`POST`/`DELETE`) from an unlisted origin are refused with 403 before any work is done. |
| Request limits | 16 KB body cap (413); only `application/json` objects accepted (415/400); URLs over 2048 characters rejected. |
| Rate limiting | Per client address, plus a global budget that protects the threat-database quotas. Memory is bounded. `X-Forwarded-For` is ignored unless `TRUSTED_PROXY_COUNT` says a proxy is in front. |
| Errors | One JSON shape; no stack traces, paths or exception text reach the client; full details go to the server log with a request id. |
| Secrets | Keys only in `.env` (git-ignored; a startup warning if the file is world-readable), sent in headers never URLs, redacted from logs, absent from `repr(Config)` and from every response. Provider calls **do not follow redirects** (custom key headers are not stripped on a cross-host redirect). |
| Providers | Clamped connect/read timeouts, an overall per-scan deadline on a bounded worker pool, `Retry-After` handling (including `nan`/`inf`), a circuit breaker after repeated failures, 1 MB response cap. A failed lookup is never reported as "clear". |
| Browser extension | Its own exact-match allow-list (`EXTENSION_ORIGINS`, no wildcards); an allowed extension may use only `/scan` and `/health` (403 elsewhere); its checks are never stored and set no cookie; the extension requests two permissions, sends no cookies or referrer, never follows a redirect and never fetches the link (`tests/test_extension*.py`, `extension/tests`). |
| Browser | Strict CSP (no inline script or style), `frame-ancestors 'none'`, nosniff, no-referrer, COOP/CORP, Permissions-Policy, optional HSTS; API responses are `no-store`. Only an explicit list of files is served. |
| Production | `APP_ENV=production` warns on risky settings; request log lines carry no addresses, queries, cookies or IPs; `/metrics` is off without a token and answers 404 (not 401) to a wrong one; container runs as a non-root user with a read-only filesystem. |
| Development settings | No app is created at import time; debug mode refuses to start on a non-loopback address; the dev server warns when bound publicly. |

### What this does **not** do

* **No authentication.** Anyone who can reach the server can scan, which is why rate limits exist. History is
  private per browser by an anonymous cookie, not by an account.
* **Rate limits are per process.** With several workers each keeps its own counters; also limit at the proxy.
* **No TLS.** Terminate HTTPS at a proxy. Cookies are `Secure` only when the request is HTTPS.
* **Data at rest is not encrypted.** Contact messages and history are protected by file permissions (0600) and
  automatic deletion, not encryption. Use disk encryption if that matters for your deployment.
* **The cookie-scoped history needs same-origin use.** The bundled frontend is same-origin; a page on another
  origin using the API gets no persistent history (cookies are not sent cross-site by design).
* **Third parties see scanned addresses** (Google Safe Browsing, URLhaus) unless you set `THREAT_INTEL_SEND_QUERY=0`,
  which strips only the query/fragment. Google Fonts is loaded by the page.
* **A server log may contain IP addresses** (your web server's access log); the app itself stores none.
* This is a student project that has had tests and a self-review, **not an independent security audit.**

### Privacy

* **Scan history** (if enabled): scheme + host + path, verdict, the evidence shown with it (query-string-like text removed, length-capped) and time, linked to a random cookie id (only its SHA-256 is
  stored). Deleted after `HISTORY_RETENTION_DAYS` (default 30), capped per browser, and removable with "Clear history".
* **Contact form**: name, email, message and time, only with an explicit consent tick; no IP or browser details. Stored in
  `data/contact_messages.jsonl` (0600, never served), size-capped, deleted after `CONTACT_RETENTION_DAYS` (default 90).
  To honour a deletion request: `python tools/contact_admin.py delete someone@example.com`
  (also `list`, `show`, `purge`).
* **Browser extension**: each link you choose is sent to your server (without `#fragment`; optionally without `?query`), is not saved to
  scan history, and is not opened by the extension. It stores two settings; the current result stays in memory until the browser closes (at most an hour).
* **In the browser**: the last 50 scans (scheme + host + path only) and the theme choice, in local storage.

## Layout

* `urldetection.py`, `wsgi.py`, `gunicorn.conf.py`: the Flask app, its production entry point and server settings
* `detection/observability.py`: JSON/text logging and the metrics counters
* `Dockerfile`, `docker-compose.yml`, `deploy/` (Caddyfile, nginx example, production env template), `render.yaml`, `requirements-prod.txt`: deployment
* `docs/`: `DEPLOYMENT.md`, `DEVELOPMENT.md` (this file), `ML.md`, `architecture.svg`
* `detection/url_features.py`: URL parsing and structural analysis (no network)
* `detection/threat_intel.py`: Safe Browsing and URLhaus checkers
* `detection/classifier.py`: combines both into the verdict and evidence; also scores the optional ML model in plain Python
* `detection/ml_model.json`: the trained model artifact (currently `adopted: false`, so it is ignored)
* `detection/settings.py`, `security.py`: validated configuration, rate limiter, secret redaction
* `extension/`: the browser extension (manifest, service worker, result window, settings, `lib/common.js`)
* `detection/history.py`, `contact_store.py`: per-browser history; consent-based contact storage
* `evaluate.py`, `data/`: evaluation harness and datasets (`data/README.md`)
* `tools/`: `smoke_test.py`, `build_holdout_v2.py`, `build_feed_dataset.py` (real feeds), `build_ml_dataset.py` (ML train/test files), `contact_admin.py`
* `reports/`: generated by `evaluate.py`: `evaluation_report.md` and `evaluation_results.json` (the app and the Docker image read the JSON),
  `ml_evaluation.md` and `ml_results.json` (ML evidence), plus the hand-written `security_review.md`

## Evaluation

```
python evaluate.py --report                         # dev + independent holdout -> reports/
python evaluate.py --split holdout                  # one split
python tools/build_feed_dataset.py --out data/feed_holdout.csv    # real OpenPhish + Tranco sample (needs network)
python evaluate.py data/labelled_urls.csv data/feed_holdout.csv
```

It measures the URL-structure heuristics only, never the Safe Browsing / URLhaus lookups. The phishing rows in the
bundled datasets are synthetic, so treat the figures as coverage of known patterns, not real-world detection rates.
On the independent holdout the frozen rules reached 92.8% precision, 54.5% recall and a 4.4% false-positive rate; see
[`reports/evaluation_report.md`](../reports/evaluation_report.md). Re-run `--report` after any change to `detection/` or the
data; the web page flags the figures as out of date until you do.
