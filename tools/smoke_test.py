#!/usr/bin/env python3
"""End-to-end smoke test for a RUNNING Cyber Solutions server (local or deployed). Standard library only.

    python tools/smoke_test.py https://scanner.example.com              # full check of a deployment
    python tools/smoke_test.py http://127.0.0.1:5000 --allow-http       # a local server (skips the HTTPS-only checks)
    python tools/smoke_test.py https://scanner.example.com --expect-intel --rate-limit-test --json reports/smoke.json

What it does:
  * checks the things a deployment can get wrong: HTTPS and certificate, redirect from HTTP, security headers (HSTS,
    CSP...), cookie flags, that source/config/data files are NOT served, that /metrics is not public;
  * drives the real API the way the web page does: scan a link, read the history it created, delete it again;
  * with --expect-intel, fails unless at least one threat database actually answered (proves your API key works);
  * with --rate-limit-test, fires a burst of cheap requests and expects HTTP 429 with Retry-After. Run this LAST and
    only against your own server: it uses up your address's scan allowance for about a minute.

It scans only addresses that do not need to exist (example.com, an invented look-alike) and it removes the history it
created. Exit status: 0 = every check passed or was skipped, 1 = at least one failed, 2 = could not run at all.
"""
from __future__ import annotations

import argparse
import http.client
import json
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit

VERDICTS = {"malicious", "suspicious", "no_known_threat", "unable_to_verify"}
PRIVATE_PATHS = ["/.env", "/.env.example", "/urldetection.py", "/wsgi.py", "/gunicorn.conf.py", "/requirements.txt",
                 "/Dockerfile", "/docker-compose.yml", "/.git/config", "/data/scans.db", "/data/contact_messages.jsonl",
                 "/detection/settings.py", "/tests/test_api.py", "/reports/evaluation_results.json", "/../.env"]


class Response:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def header(self, name, default=""):
        return self.headers.get(name.lower(), default)

    def all_headers(self, name):
        return [v for k, v in self.raw if k.lower() == name.lower()]

    def json(self):
        return json.loads(self.body.decode("utf-8"))


class Client:
    """A tiny HTTP client: no redirects followed, its own cookie jar, custom headers allowed."""

    def __init__(self, base: str, insecure: bool, timeout: float = 30.0):
        parts = urlsplit(base)
        self.scheme, self.host = parts.scheme, parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.timeout, self.cookies = timeout, {}
        self.ctx = ssl.create_default_context()
        if insecure:
            self.ctx.check_hostname, self.ctx.verify_mode = False, ssl.CERT_NONE

    def _connect(self, scheme=None, port=None):
        scheme = scheme or self.scheme
        port = port or self.port
        if scheme == "https":
            return http.client.HTTPSConnection(self.host, port, timeout=self.timeout, context=self.ctx)
        return http.client.HTTPConnection(self.host, port, timeout=self.timeout)

    def request(self, method, path, *, headers=None, body=None, json_body=None, scheme=None, port=None, use_cookies=True):
        hdrs = {"User-Agent": "cyber-solutions-smoke-test/1.0", "Accept": "*/*"}
        hdrs.update(headers or {})
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        if use_cookies and self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        conn = self._connect(scheme, port)
        try:
            conn.request(method, path, body=body, headers=hdrs)
            raw = conn.getresponse()
            data = raw.read()
            resp = Response(raw.status, {k.lower(): v for k, v in raw.getheaders()}, data)
            resp.raw = raw.getheaders()
        finally:
            conn.close()
        for line in resp.all_headers("Set-Cookie"):
            name, _, rest = line.partition("=")
            value = rest.split(";", 1)[0]
            if "max-age=0" in line.lower() or not value:
                self.cookies.pop(name.strip(), None)
            else:
                self.cookies[name.strip()] = value
        return resp


class Report:
    def __init__(self):
        self.rows = []

    def add(self, status, name, detail=""):
        self.rows.append({"status": status, "name": name, "detail": detail})
        mark = {"PASS": "PASS", "FAIL": "FAIL", "SKIP": "skip", "INFO": "info"}[status]
        print(f"  [{mark}] {name}" + (f" - {detail}" if detail else ""), flush=True)

    @property
    def failed(self):
        return [r for r in self.rows if r["status"] == "FAIL"]


def check(report: Report, name: str):
    """Decorator: run one check, turning any exception into a FAIL (a crashed check is never a pass)."""
    def wrap(fn):
        try:
            result = fn()
            if isinstance(result, tuple):          # (status, detail), e.g. ("SKIP", "why")
                report.add(result[0], name, result[1])
            elif result is None:
                report.add("PASS", name)
            else:
                report.add("PASS", name, str(result))
        except AssertionError as exc:
            report.add("FAIL", name, str(exc) or "assertion failed")
        except (OSError, http.client.HTTPException, ValueError, KeyError, ssl.SSLError) as exc:
            report.add("FAIL", name, f"{type(exc).__name__}: {exc}")
        return fn
    return wrap


def run(args) -> Report:
    base = args.base_url.rstrip("/")
    scheme = urlsplit(base).scheme
    https = scheme == "https"
    c = Client(base, insecure=args.insecure)
    r = Report()
    print(f"Smoke test: {base}\n")

    # ------------------------------------------------------------------ transport
    @check(r, "served over HTTPS")
    def _():
        if https:
            return None
        if args.allow_http:
            return "SKIP", "plain HTTP allowed for this run (--allow-http)"
        raise AssertionError("the URL is http://. A deployment must use https:// (or pass --allow-http for a local run)")

    if https:
        @check(r, "TLS certificate is valid and not about to expire")
        def _():
            if args.insecure:
                return "SKIP", "certificate checks disabled (--insecure)"
            ctx = ssl.create_default_context()
            with socket.create_connection((c.host, c.port), timeout=15) as sock, ctx.wrap_socket(sock, server_hostname=c.host) as tls:
                cert = tls.getpeercert()
                days = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
                assert days > 7, f"certificate expires in {days:.0f} days"
                return f"{tls.version()}, expires in {days:.0f} days"

        @check(r, "plain HTTP redirects to HTTPS")
        def _():
            if c.port != 443:
                return "SKIP", f"non-standard HTTPS port {c.port}; the redirect lives on port 80"
            try:
                resp = c.request("GET", "/health", scheme="http", port=80, use_cookies=False)
            except OSError:
                return "SKIP", "port 80 not reachable from here"
            assert resp.status in (301, 302, 307, 308), f"got HTTP {resp.status}, expected a redirect"
            assert resp.header("location").startswith("https://"), f"redirects to {resp.header('location')!r}"
            return f"{resp.status} -> {resp.header('location')}"

    # ------------------------------------------------------------------ liveness, frontend, headers
    @check(r, "GET /health is ok")
    def _():
        resp = c.request("GET", "/health")
        assert resp.status == 200 and resp.json().get("status") == "ok", f"HTTP {resp.status}"

    @check(r, "GET /ready is ready (data files writable)")
    def _():
        resp = c.request("GET", "/ready")
        assert resp.status == 200 and resp.json().get("status") == "ready", f"HTTP {resp.status}: {resp.body[:120]!r}"

    @check(r, "frontend files are served with the right types")
    def _():
        expect = {"/": "text/html", "/style.css": "text/css", "/script.js": "javascript", "/theme.js": "javascript"}
        for path, kind in expect.items():
            resp = c.request("GET", path)
            assert resp.status == 200, f"{path} -> HTTP {resp.status}"
            assert kind in resp.header("content-type"), f"{path} has content-type {resp.header('content-type')!r}"
        assert b"LinkLens" in c.request("GET", "/").body

    @check(r, "security headers are present")
    def _():
        h = c.request("GET", "/").headers
        csp = h.get("content-security-policy", "")
        assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp, "Content-Security-Policy missing or weak"
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp, "CSP allows unsafe-inline/unsafe-eval"
        assert h.get("x-content-type-options") == "nosniff", "X-Content-Type-Options"
        assert h.get("x-frame-options", "").upper() == "DENY", "X-Frame-Options"
        assert h.get("referrer-policy") == "no-referrer", "Referrer-Policy"
        if https:
            assert "max-age=" in h.get("strict-transport-security", ""), "Strict-Transport-Security missing (set HSTS=1 and TRUSTED_PROXY_COUNT=1)"
        return "CSP, nosniff, frame, referrer" + (", HSTS" if https else "")

    @check(r, "robots.txt is served")
    def _():
        resp = c.request("GET", "/robots.txt")
        assert resp.status == 200 and b"Disallow: /metrics" in resp.body, f"HTTP {resp.status}"

    # ------------------------------------------------------------------ scanner API
    scan_seconds = {}

    @check(r, "POST /scan returns a well-formed verdict")
    def _():
        t0 = time.monotonic()
        resp = c.request("POST", "/scan", json_body={"url": "https://example.com/"})
        scan_seconds["example"] = time.monotonic() - t0
        assert resp.status == 200, f"HTTP {resp.status}: {resp.body[:160]!r}"
        d = resp.json()
        assert d.get("verdict_code") in VERDICTS, f"unknown verdict_code {d.get('verdict_code')!r}"
        for key in ("verdict", "summary", "evidence", "sources", "risk_score", "scanned_at"):
            assert key in d, f"missing field {key!r}"
        assert isinstance(d["evidence"], list) and isinstance(d["sources"], list)
        states = [s.get("status") for s in d["sources"]]
        assert not (d["verdict_code"] == "no_known_threat" and "clear" not in states), "claimed 'no known threat' without a successful lookup"
        scan_seconds["states"] = states
        return f"{d['verdict_code']} (sources: {', '.join(states) or 'none'}) in {scan_seconds['example']:.1f}s"

    @check(r, "threat-intelligence lookup works" if args.expect_intel else "threat-intelligence lookup status")
    def _():
        states = scan_seconds.get("states")
        if states is None:
            raise AssertionError("no scan result to inspect")
        answered = [s for s in states if s in ("clear", "hit")]
        if args.expect_intel:
            assert answered, f"no threat database answered (statuses: {states}). Check the API key and outbound network access."
            return f"{len(answered)} source(s) answered"
        return ("PASS", f"{len(answered)} source(s) answered") if answered else (
            "INFO", "no threat database answered, so results are 'Unable to verify' (add an API key; re-run with --expect-intel to enforce)")

    @check(r, "scan latency is reasonable")
    def _():
        took = scan_seconds.get("example")
        assert took is not None, "no timing"
        assert took <= args.max_scan_seconds, f"{took:.1f}s is over the {args.max_scan_seconds:.0f}s limit"
        return f"{took:.1f}s"

    @check(r, "a look-alike sign-in link is flagged (rules work without any API)")
    def _():
        d = c.request("POST", "/scan", json_body={"url": "https://paypal-secure-login.com/verify"}).json()
        assert d["verdict_code"] in ("suspicious", "malicious"), f"got {d['verdict_code']!r}"
        assert any(e.get("source") == "URL analysis" for e in d["evidence"]), "no URL-analysis evidence"
        return f"{d['verdict_code']}, risk score {d['risk_score']}"

    @check(r, "bad input is rejected cleanly")
    def _():
        bad = c.request("POST", "/scan", json_body={"url": "not a url at all"})
        assert bad.status == 400 and bad.json().get("code") == "invalid_url", f"bad url -> HTTP {bad.status}"
        private = c.request("POST", "/scan", json_body={"url": "http://192.168.1.1/admin"})
        assert private.status == 400, f"private address -> HTTP {private.status} (should be refused)"
        ctype = c.request("POST", "/scan", body=b'{"url":"https://example.com"}', headers={"Content-Type": "text/plain"})
        assert ctype.status == 415, f"wrong content type -> HTTP {ctype.status}"
        big = c.request("POST", "/scan", json_body={"url": "https://example.com/" + "a" * 20000})
        assert big.status in (400, 413), f"oversized body -> HTTP {big.status}"
        for resp in (bad, private, ctype, big):
            text = resp.body.decode("utf-8", "replace")
            assert "Traceback" not in text and ".py" not in text, "an error response leaks internals"
        return "400 / 400 / 415 / 413, no internals in any"

    @check(r, "a foreign website cannot use the API (CORS/origin)")
    def _():
        resp = c.request("POST", "/scan", json_body={"url": "https://example.com/"}, headers={"Origin": "https://evil.example"})
        assert resp.status == 403, f"HTTP {resp.status}, expected 403"
        assert "access-control-allow-origin" not in resp.headers, "evil origin was allowed"

    # ------------------------------------------------------------------ history / cookie flow
    @check(r, "scan history: cookie flags, per-browser privacy, deletion")
    def _():
        cookie_lines = []
        probe = Client(base, insecure=args.insecure)
        resp = probe.request("POST", "/scan", json_body={"url": "https://example.com/history-smoke-test?token=SHOULD-NOT-BE-STORED"})
        assert resp.status == 200
        cookie_lines = resp.all_headers("Set-Cookie")
        if not cookie_lines:
            return "SKIP", "history is switched off on this server (no cookie issued)"
        line = cookie_lines[0].lower()
        assert "httponly" in line and "samesite=strict" in line, f"cookie flags weak: {cookie_lines[0].split('=')[0]}"
        if https:
            assert "secure" in line, "cookie is missing the Secure flag (set COOKIE_SECURE=1 or TRUSTED_PROXY_COUNT=1)"
        mine = probe.request("GET", "/history").json()
        assert mine.get("enabled") and mine["total"] >= 1, "the scan did not appear in this browser's history"
        stored = json.dumps(mine)
        assert "SHOULD-NOT-BE-STORED" not in stored, "the query string was stored"
        other = Client(base, insecure=args.insecure).request("GET", "/history").json()
        assert other.get("total", 0) == 0, "another browser can see this history"
        assert probe.request("DELETE", "/history").json().get("cleared") is True
        assert probe.request("GET", "/history").json()["total"] == 0, "history was not cleared"
        return "HttpOnly, SameSite=Strict" + (", Secure" if https else "") + "; private; cleared"

    @check(r, "/evaluation and /privacy answer")
    def _():
        e, p = c.request("GET", "/evaluation"), c.request("GET", "/privacy")
        assert e.status == 200 and "available" in e.json(), f"/evaluation HTTP {e.status}"
        assert p.status == 200 and "history_enabled" in p.json(), f"/privacy HTTP {p.status}"
        return "evaluation figures " + ("present" if e.json().get("available") else "not available") + (", STALE" if e.json().get("stale") else "")

    # ------------------------------------------------------------------ what must NOT be reachable
    @check(r, "source, config and data files are not served")
    def _():
        leaked = []
        for path in PRIVATE_PATHS:
            resp = c.request("GET", path)
            if resp.status != 404:
                leaked.append(f"{path} -> {resp.status}")
        assert not leaked, "reachable: " + ", ".join(leaked)
        return f"{len(PRIVATE_PATHS)} paths all 404"

    @check(r, "/metrics is not public")
    def _():
        resp = c.request("GET", "/metrics")
        assert resp.status == 404, f"HTTP {resp.status}: /metrics answered without a token"

    @check(r, "unknown paths give a JSON 404 without internals")
    def _():
        resp = c.request("GET", "/definitely-not-here")
        assert resp.status == 404 and resp.json().get("code") == "not_found", f"HTTP {resp.status}"
        assert "Traceback" not in resp.body.decode("utf-8", "replace")

    if args.metrics_token:
        @check(r, "/metrics works with the token and exposes counters")
        def _():
            resp = c.request("GET", "/metrics", headers={"Authorization": f"Bearer {args.metrics_token}"})
            assert resp.status == 200, f"HTTP {resp.status}"
            text = resp.body.decode("utf-8")
            assert "cs_requests_total" in text and "cs_scan_verdicts_total" in text, "expected counters missing"
            return f"{len(text.splitlines())} lines"

    # ------------------------------------------------------------------ rate limiting (opt-in, last)
    if args.rate_limit_test:
        @check(r, "rate limiting returns 429 with Retry-After")
        def _():
            tester = Client(base, insecure=args.insecure)
            codes, retry = [], None
            for _ in range(args.rate_limit_requests):
                resp = tester.request("POST", "/scan", json_body={"url": "x"}, use_cookies=False)   # cheap: rejected as invalid
                codes.append(resp.status)
                if resp.status == 429:
                    retry = resp.header("retry-after")
                    assert resp.json().get("code") == "rate_limited", "429 without the standard error body"
                    break
            assert 429 in codes, f"no 429 after {len(codes)} requests (is RATE_LIMIT_PER_MINUTE higher than {args.rate_limit_requests}?)"
            assert retry and retry.isdigit(), f"Retry-After header missing or odd: {retry!r}"
            return f"429 after {codes.index(429)} requests, Retry-After {retry}s"
    else:
        r.add("SKIP", "rate limiting returns 429 with Retry-After", "pass --rate-limit-test to run it (uses up your scan allowance for a minute)")

    return r


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Smoke test a running Cyber Solutions server.")
    ap.add_argument("base_url", nargs="?", default="http://127.0.0.1:5000", help="e.g. https://scanner.example.com")
    ap.add_argument("--allow-http", action="store_true", help="accept plain http:// (local runs only)")
    ap.add_argument("--insecure", action="store_true", help="do not verify the TLS certificate (self-signed testing only)")
    ap.add_argument("--expect-intel", action="store_true", help="fail unless a threat database answers (proves the API key works)")
    ap.add_argument("--metrics-token", default="", help="also verify /metrics with this bearer token")
    ap.add_argument("--rate-limit-test", action="store_true", help="fire a burst and expect HTTP 429 (run last, own server only)")
    ap.add_argument("--rate-limit-requests", type=int, default=45, help="burst size for --rate-limit-test (default 45)")
    ap.add_argument("--max-scan-seconds", type=float, default=12.0)
    ap.add_argument("--json", metavar="PATH", help="also write the results to this JSON file")
    args = ap.parse_args(argv)
    if urlsplit(args.base_url).scheme not in ("http", "https") or not urlsplit(args.base_url).hostname:
        print("base_url must look like https://host[:port]", file=sys.stderr)
        return 2
    try:
        report = run(args)
    except KeyboardInterrupt:
        return 2
    counts = {k: sum(1 for x in report.rows if x["status"] == k) for k in ("PASS", "FAIL", "SKIP", "INFO")}
    print(f"\n{counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped, {counts['INFO']} info")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"base_url": args.base_url, "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "counts": counts, "checks": report.rows}, fh, indent=2)
    return 1 if report.failed else 0


if __name__ == "__main__":
    sys.exit(main())
