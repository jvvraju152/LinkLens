"""Cyber Solutions backend.

Run (local development only):   python urldetection.py      then open http://127.0.0.1:5000
Run (deployment):               gunicorn wsgi:app           (or waitress-serve wsgi:app on Windows), behind HTTPS

Security notes live in docs/DEVELOPMENT.md ("Security"). Everything configurable is read in detection/settings.py.
"""
from __future__ import annotations

import hmac
import io
import logging
import os
import secrets
import time
import zipfile
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, g, jsonify, make_response, request, send_file, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from detection.classifier import Config, classify_url, default_checkers, model_from_env
from detection.contact_store import ContactStore, ContactUnavailable, is_honeypot, validate
from detection.evaluation_summary import summarise
from detection.history import ScanHistory, parse_filters, to_csv, to_json
from detection.observability import Metrics, configure_logging
from detection.security import (RateLimiter, hash_client_id, install_secret_filter, new_client_id, valid_client_id)
from detection.settings import Settings, env_float, env_secret, load_settings, production_warnings
from detection.url_features import InvalidURLError

BASE_DIR = Path(__file__).resolve().parent
# Only these files are served to the browser; the project folder (.env, data/, source) is never exposed.
PUBLIC_FILES = {"index.html", "style.css", "script.js", "theme.js", "robots.txt"}
API_PATHS = {"/scan", "/history", "/contact", "/evaluation", "/privacy", "/health", "/ready", "/metrics", "/download-extension"}
HISTORY_PREFIX = "/history/"   # /history/export and /history/<id>
# A browser extension is allowed to call only these. Everything else (contact form, history) stays same-site only.
EXTENSION_PATHS = {"/scan", "/health"}


def is_api_path(path: str) -> bool:
    return path in API_PATHS or path.startswith(HISTORY_PREFIX)
COOKIE_NAME = "cs_client"

STATUS_CODES = {
    400: ("bad_request", "That request wasn't valid."),
    403: ("forbidden", "That isn't allowed."),
    404: ("not_found", "Not found."),
    405: ("method_not_allowed", "Method not allowed."),
    413: ("payload_too_large", "Request is too large."),
    415: ("unsupported_media_type", "Send the request as JSON (Content-Type: application/json)."),
    429: ("rate_limited", "Too many requests. Please wait a moment and try again."),
}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")


def config_from_env(settings: Settings | None = None, env=None) -> Config:
    env = os.environ if env is None else env
    settings = settings or load_settings(env)
    return Config(
        safe_browsing_key=(env_secret(env, "GOOGLE_SAFE_BROWSING_API_KEY") or None),   # NAME or NAME_FILE (Docker secrets)
        urlhaus_key=(env_secret(env, "URLHAUS_AUTH_KEY") or None),
        connect_timeout=env_float(env, "THREAT_INTEL_CONNECT_TIMEOUT", 3.0, 0.5, 15.0),
        read_timeout=env_float(env, "THREAT_INTEL_READ_TIMEOUT", 5.0, 0.5, 15.0),
        send_query=settings.send_query_to_providers,
        lookup_deadline=settings.lookup_deadline_seconds,
        model=model_from_env(env),  # None unless ENABLE_ML_MODEL=1 and the artifact passed its evidence gates
    )


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, **extra):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra


def create_app(config: Config | None = None, checkers=None, history_path: str | None = None,
               rate_limit: int | None = None, contact_path: str | None = None,
               evaluation_path: str | None = None, settings: Settings | None = None) -> Flask:
    if settings is None:
        load_dotenv(BASE_DIR / ".env")
        settings = load_settings()
    config = config or config_from_env(settings)
    checkers = checkers if checkers is not None else default_checkers(config)

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_body_bytes  # a URL or a 2000-character message; nothing larger
    app.json.sort_keys = False
    if settings.trusted_proxies:
        # Only believe X-Forwarded-* when told how many proxies sit in front; otherwise any client could spoof its IP.
        n = settings.trusted_proxies
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)

    secret_filter = install_secret_filter([config.safe_browsing_key or "", config.urlhaus_key or ""])
    install_secret_filter_for(app, config)
    configure_logging(app.logger, settings.log_level, settings.log_format, scrub=secret_filter.scrub)
    problems = production_warnings(settings, bool(config.safe_browsing_key or config.urlhaus_key))
    if settings.app_env == "production" and settings.debug:
        raise RuntimeError("Refusing to start: FLASK_DEBUG=1 with APP_ENV=production exposes an interactive debugger.")
    for warning in (*settings.cors_warnings, *settings.extension_warnings, *problems):
        app.logger.warning(warning)
    metrics = Metrics()
    _warn_if_env_file_is_open(app)

    allowed_origins = set(settings.cors_origins)
    extension_origins = set(settings.extension_origins)
    history = None
    if settings.history_enabled:
        history = ScanHistory(history_path or os.getenv("HISTORY_DB", str(BASE_DIR / "data" / "scans.db")),
                              settings.history_retention_days, settings.history_max_per_client)
    contact_store = ContactStore(
        contact_path or os.getenv("CONTACT_FILE", str(BASE_DIR / "data" / "contact_messages.jsonl")),
        enabled=settings.contact_enabled, retention_days=settings.contact_retention_days, max_bytes=settings.contact_max_bytes)
    if settings.contact_enabled:
        try:
            contact_store.purge_expired()
        except OSError:
            app.logger.warning("Could not purge old contact messages at startup")
    evaluation_file = Path(evaluation_path) if evaluation_path else BASE_DIR / "reports" / "evaluation_results.json"

    scan_limiter = RateLimiter(rate_limit if rate_limit is not None else settings.scan_limit_per_minute)
    global_limiter = RateLimiter(settings.global_scan_limit_per_minute, max_keys=1)
    api_limiter = RateLimiter(settings.api_limit_per_minute)
    contact_limiter = RateLimiter(settings.contact_limit_per_minute)

    # ------------------------------------------------------------------ helpers
    def ip() -> str:
        return request.remote_addr or "unknown"

    def too_many(wait: float, message: str | None = None):
        resp = make_response(jsonify({"error": message or STATUS_CODES[429][1], "code": "rate_limited",
                                      "request_id": g.request_id}), 429)
        resp.headers["Retry-After"] = str(int(wait) + 1)
        return resp

    def origin_allowed(origin: str | None) -> bool:
        return bool(origin) and origin in allowed_origins

    def extension_origin_allowed(origin: str | None) -> bool:
        """A listed browser extension, and only on the endpoints an extension needs."""
        return bool(origin) and origin in extension_origins and request.path in EXTENSION_PATHS

    def read_json() -> dict:
        """The request body as a JSON object. Anything else is rejected before it is looked at."""
        if not request.get_data(cache=True):
            raise ApiError(400, "bad_request", "The request had no body.")
        if request.mimetype != "application/json":
            raise ApiError(415, *STATUS_CODES[415])
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ApiError(400, "bad_request", 'Send JSON like {"url": "https://example.com"}.')
        return data

    def client_hash(create: bool) -> str | None:
        """Hash of this browser's anonymous id. With ``create`` a new id is issued (and set as a cookie) if needed."""
        raw = request.cookies.get(COOKIE_NAME)
        if valid_client_id(raw):
            return hash_client_id(raw)
        if not create:
            return None
        g.new_client_id = new_client_id()
        return hash_client_id(g.new_client_id)

    def route_group() -> str:
        """A small fixed set of names, so metrics labels and log lines never contain attacker-chosen text."""
        path = request.path
        if path == "/scan":
            return "scan"
        if path == "/history" or path.startswith(HISTORY_PREFIX):
            return "history"
        if path in API_PATHS:
            return path.lstrip("/")
        if request.url_rule is not None:
            return "frontend"
        return "unmatched"

    def record_request(status: int) -> None:
        seconds = time.perf_counter() - g.get("started", time.perf_counter())
        group = route_group()
        metrics.request(group, status, seconds)
        if not settings.log_requests:
            return
        quiet = group in ("health", "ready", "metrics")   # probes and scrapes arrive every few seconds: debug level only
        app.logger.log(logging.DEBUG if quiet else logging.INFO, "request", extra={
            "event": "request", "request_id": g.get("request_id"), "method": request.method,
            # the matched route pattern (e.g. /history/<int:scan_id>), never the raw path or query string
            "path": request.url_rule.rule if request.url_rule is not None else "(no route)",
            "status": status, "duration_ms": round(seconds * 1000, 1)})

    # ------------------------------------------------------------------ request / response hooks
    @app.before_request
    def start_request():
        g.started = time.perf_counter()
        g.request_id = secrets.token_hex(4)
        g.new_client_id = None
        origin = request.headers.get("Origin")
        if is_api_path(request.path) and request.method == "OPTIONS":
            resp = make_response("", 204)  # CORS headers are added in after_request only for allowed origins
            return resp
        if request.method in ("POST", "DELETE") and origin:
            same_origin = origin == request.host_url.rstrip("/")
            if not same_origin and not origin_allowed(origin) and not extension_origin_allowed(origin):
                return make_response(jsonify({"error": "This origin isn't allowed to use the API.", "code": "origin_not_allowed",
                                              "request_id": g.request_id}), 403)

    @app.after_request
    def finish_response(resp):
        h = resp.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Content-Security-Policy", CSP)
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        if settings.hsts and request.is_secure:
            h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if "request_id" in g:
            h["X-Request-ID"] = g.request_id
        record_request(resp.status_code)
        if is_api_path(request.path):
            h["Cache-Control"] = "no-store"
            h.add("Vary", "Origin")
            origin = request.headers.get("Origin")
            if origin_allowed(origin) or extension_origin_allowed(origin):
                h["Access-Control-Allow-Origin"] = origin  # exact match only, never '*', never with credentials
                if request.method == "OPTIONS":
                    h["Access-Control-Allow-Methods"] = "GET, POST, DELETE"
                    h["Access-Control-Allow-Headers"] = "Content-Type"
                    h["Access-Control-Max-Age"] = "600"
        else:
            h.setdefault("Cache-Control", "no-cache")
        if g.get("new_client_id"):
            resp.set_cookie(
                COOKIE_NAME, g.new_client_id, max_age=settings.history_retention_days * 86400, httponly=True,
                samesite="Strict", path="/",
                secure=settings.cookie_secure if settings.cookie_secure is not None else request.is_secure)
        return resp

    # ------------------------------------------------------------------ errors: one shape, nothing internal
    @app.errorhandler(ApiError)
    def api_error(exc: ApiError):
        body = {"error": exc.message, "code": exc.code, "request_id": g.get("request_id"), **exc.extra}
        return make_response(jsonify(body), exc.status)

    @app.errorhandler(HTTPException)
    def http_error(exc: HTTPException):
        code, message = STATUS_CODES.get(exc.code, ("http_error", "The request couldn't be completed."))
        return make_response(jsonify({"error": message, "code": code, "request_id": g.get("request_id")}), exc.code or 500)

    @app.errorhandler(Exception)
    def unexpected(exc: Exception):
        # The traceback goes to the server log (with the request id), never to the client.
        app.logger.error("Unhandled error (request %s): %s", g.get("request_id"), type(exc).__name__, exc_info=exc)
        return make_response(jsonify({"error": "Something went wrong on the server. Please try again.", "code": "server_error",
                                      "request_id": g.get("request_id")}), 500)

    # ------------------------------------------------------------------ frontend (explicit allow-list)
    @app.get("/")
    def index():
        return send_from_directory(BASE_DIR, "index.html")

    for _name in sorted(PUBLIC_FILES - {"index.html"}):
        app.add_url_rule(f"/{_name}", endpoint=f"static_{_name}", view_func=lambda _n=_name: send_from_directory(BASE_DIR, _n))

    # ------------------------------------------------------------------ API
    @app.get("/health")
    def health():
        body = {"status": "ok"}
        if settings.health_detail:  # provider configuration is operator information, off by default
            body.update({
                "threat_intel_configured": bool(config.safe_browsing_key or config.urlhaus_key),
                "sources": {"google_safe_browsing": bool(config.safe_browsing_key), "urlhaus": bool(config.urlhaus_key)},
                "history_enabled": history is not None,
            })
        return jsonify(body)

    @app.get("/ready")
    def ready():
        """Readiness for a load balancer: can this process write the files it needs? Liveness is /health."""
        failed = []
        if history is not None and not _writable(Path(history.path)):
            failed.append("history_store")
        if settings.contact_enabled and not _writable(Path(contact_store.path)):
            failed.append("contact_store")
        if failed:
            return make_response(jsonify({"status": "not_ready", "failed": failed, "request_id": g.request_id}), 503)
        return jsonify({"status": "ready"})

    @app.get("/metrics")
    def metrics_endpoint():
        """Prometheus text. Off (404) unless METRICS_TOKEN is set; a wrong or missing token also gets 404."""
        wait = api_limiter.check(ip())   # also slows down anyone guessing the token
        if wait:
            return too_many(wait)
        header = request.headers.get("Authorization", "")
        presented = header[7:].strip() if header[:7].lower() == "bearer " else ""
        if not settings.metrics_token or not hmac.compare_digest(presented.encode(), settings.metrics_token.encode()):
            raise ApiError(404, "not_found", STATUS_CODES[404][1])
        resp = make_response(metrics.render())
        resp.headers["Content-Type"] = "text/plain; version=0.0.4; charset=utf-8"
        return resp

    @app.get("/download-extension")
    def download_extension():
        """Package and stream the browser extension folder as a zip archive."""
        wait = api_limiter.check(ip())
        if wait:
            return too_many(wait)
        ext_dir = BASE_DIR / "extension"
        if not ext_dir.is_dir():
            raise ApiError(404, "not_found", "Extension directory not found.")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(ext_dir):
                for f in files:
                    if f.startswith(".") or f.endswith(".pyc"):
                        continue
                    full_p = Path(root) / f
                    arcname = full_p.relative_to(ext_dir)
                    zf.write(full_p, arcname)
        buf.seek(0)
        return send_file(
            buf,
            mimetype="application/zip",
            as_attachment=True,
            download_name="linklens-extension.zip",
        )

    @app.get("/privacy")
    def privacy():
        """What this server does with data, as configured, so the privacy page is never out of date."""
        wait = api_limiter.check(ip())
        if wait:
            return too_many(wait)
        return jsonify({
            "lookup_providers": [n for n, on in (("Google Safe Browsing", config.safe_browsing_key), ("URLhaus", config.urlhaus_key)) if on],
            "lookup_sent_query": bool(config.send_query),
            "history_enabled": history is not None,
            "history_retention_days": settings.history_retention_days,
            "contact_enabled": settings.contact_enabled,
            "contact_retention_days": settings.contact_retention_days,
            "extension_enabled": bool(extension_origins),
        })

    @app.get("/evaluation")
    def evaluation():
        """Latest measured accuracy of the URL-structure rules, as written by ``python evaluate.py --report``."""
        wait = api_limiter.check(ip())
        if wait:
            return too_many(wait)
        return jsonify(summarise(evaluation_file))

    @app.post("/scan")
    def scan():
        wait = scan_limiter.check(ip())
        if wait:
            return too_many(wait, "Too many scans. Please wait a moment and try again.")
        wait = global_limiter.check("all")  # protects the threat-database quotas from many clients at once
        if wait:
            return too_many(wait, "The scanner is very busy. Please try again shortly.")

        data = read_json()
        if "url" not in data:
            raise ApiError(400, "bad_request", 'Send JSON like {"url": "https://example.com"}.')
        try:
            result = classify_url(data["url"], checkers, config.lookup_deadline, model=config.model)
        except InvalidURLError as exc:
            raise ApiError(400, "invalid_url", str(exc)) from None

        metrics.verdict(result.get("verdict_code", "unknown"),
                        any(src.get("status") == "error" for src in result.get("sources", []) if isinstance(src, dict)))

        # An extension sends no cookie, so its checks have no browser to belong to: they are not saved (and no cookie is issued).
        if history and not extension_origin_allowed(request.headers.get("Origin")):
            try:
                history.add(client_hash(create=True), result["normalized_url"], result["verdict"], result["severity"], result)
            except Exception:
                app.logger.error("Could not save scan history (request %s)", g.request_id, exc_info=True)
        result["lookup_sent_query"] = bool(config.send_query)
        return jsonify(result)

    @app.post("/contact")
    def contact():
        wait = contact_limiter.check(ip())
        if wait:
            return too_many(wait, "Too many messages. Please wait a moment and try again.")
        data = read_json()
        if is_honeypot(data):
            return jsonify({"ok": True}), 201  # looks like success to a bot; nothing is stored
        clean, errors = validate(data)
        if errors:
            first = next(iter(errors.values()))
            raise ApiError(400, "invalid_contact", first, fields=errors)
        try:
            contact_store.save(clean)
        except ContactUnavailable as exc:
            raise ApiError(503, "contact_unavailable", str(exc)) from None
        return jsonify({"ok": True}), 201

    def tz_minutes() -> int:
        """Minutes east of UTC the browser says it is in, so daily totals follow the person's own calendar days."""
        return max(-840, min(request.args.get("tz", default=0, type=int) or 0, 840))

    @app.get("/history")
    def get_history():
        """This browser's scans, filtered and paged. Query: q, verdict (comma list of codes), source, days, confirmed,
        sort (newest|oldest|risk), limit, offset. The first page also carries dashboard totals over all saved scans."""
        wait = api_limiter.check(ip())
        if wait:
            return too_many(wait)
        if not history:
            return jsonify({"enabled": False, "scans": []})
        client = client_hash(create=False)
        f = parse_filters(request.args)
        found = history.search(client, **f)
        body = {"enabled": True, "scans": found["scans"], "total": found["total"], "limit": f["limit"], "offset": f["offset"]}
        if f["offset"] == 0:
            body["stats"] = history.stats(client, tz_minutes())
        return jsonify(body)

    @app.get("/history/export")
    def export_history():
        """Download this browser's saved scans (the same filters as /history) as CSV or JSON."""
        wait = api_limiter.check(ip())
        if wait:
            return too_many(wait)
        if not history:
            raise ApiError(404, "not_found", STATUS_CODES[404][1])
        fmt = "csv" if request.args.get("format", "json").lower() == "csv" else "json"
        client = client_hash(create=False)
        f = parse_filters(request.args)
        scans = history.search(client, **{**f, "limit": None, "offset": 0})["scans"]
        resp = make_response(to_csv(scans) if fmt == "csv" else to_json(scans))
        resp.headers["Content-Type"] = "text/csv; charset=utf-8" if fmt == "csv" else "application/json"
        resp.headers["Content-Disposition"] = f'attachment; filename="scan-history.{fmt}"'
        return resp

    @app.delete("/history/<int:scan_id>")
    def delete_scan(scan_id: int):
        """Delete one scan. A scan that belongs to another browser is reported exactly like one that does not exist."""
        wait = api_limiter.check(ip())
        if wait:
            return too_many(wait)
        client = client_hash(create=False)
        if not (history and client and history.delete(client, scan_id)):
            raise ApiError(404, "not_found", STATUS_CODES[404][1])
        return jsonify({"deleted": True})

    @app.delete("/history")
    def clear_history():
        wait = api_limiter.check(ip())
        if wait:
            return too_many(wait)
        client = client_hash(create=False)
        if history and client:
            history.clear(client)
        return jsonify({"cleared": True})

    return app


def install_secret_filter_for(app: Flask, config: Config) -> None:
    """Also scrub keys from this app's own logger (Flask names it after the module)."""
    from detection.security import SecretFilter
    app.logger.addFilter(SecretFilter([config.safe_browsing_key or "", config.urlhaus_key or ""]))


def _writable(path: Path) -> bool:
    """True if ``path`` can be written (or created) by this process."""
    try:
        return os.access(path if path.exists() else path.parent, os.W_OK)
    except OSError:
        return False


def _warn_if_env_file_is_open(app: Flask) -> None:
    env_file = BASE_DIR / ".env"
    try:
        if os.name == "posix" and env_file.exists() and env_file.stat().st_mode & 0o077:
            app.logger.warning(".env is readable by other users on this machine. Run: chmod 600 .env")
    except OSError:
        pass


def main() -> None:
    settings = load_settings()
    host, port = os.getenv("HOST", "127.0.0.1"), int(os.getenv("PORT", "5000"))
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if settings.debug and not loopback:
        raise SystemExit("Refusing to start: FLASK_DEBUG=1 exposes an interactive debugger and may only be used on "
                         "127.0.0.1. Set FLASK_DEBUG=0 or HOST=127.0.0.1.")
    if not loopback:
        logging.warning("This is Flask's development server. For deployment use gunicorn/waitress behind HTTPS (see README).")
    create_app(settings=settings).run(host=host, port=port, debug=settings.debug)


if __name__ == "__main__":
    load_dotenv(BASE_DIR / ".env")
    main()
