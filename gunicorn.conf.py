"""Gunicorn settings for production:  gunicorn -c gunicorn.conf.py wsgi:app

Everything can be overridden with an environment variable, so the same file works in Docker, on a VM and on a PaaS.

One worker with several threads is the default ON PURPOSE. The rate limiter, the threat-lookup cache, the circuit
breaker and the /metrics counters all live in process memory. With N workers each would keep its own copy, so a client
could make N times the allowed requests and the counters would describe one random worker. Threads give the
concurrency this I/O-bound app needs (it mostly waits for threat databases). If you raise WEB_CONCURRENCY, also rate-limit
at the reverse proxy (see deploy/nginx.conf.example).
"""
import os

if os.getenv("BIND"):
    bind = os.environ["BIND"]
elif os.getenv("PORT"):                      # Render, Railway, Fly, Heroku-style platforms hand you a port
    bind = f"0.0.0.0:{os.environ['PORT']}"
else:
    bind = "127.0.0.1:8000"                  # safe default: reachable only from this machine (put a proxy in front)


def _int(name, default, lo, hi):
    try:
        return max(lo, min(hi, int(os.getenv(name, default))))
    except ValueError:
        return default


workers = _int("WEB_CONCURRENCY", 1, 1, 8)
threads = _int("GUNICORN_THREADS", 8, 1, 64)
worker_class = "gthread"
timeout = _int("GUNICORN_TIMEOUT", 60, 10, 300)            # gthread: this watches the worker's heartbeat, not each request; the app bounds scans itself
graceful_timeout = 30                                       # in-flight scans get 30 s to finish on SIGTERM / redeploy
keepalive = 5                                               # seconds; keep below the proxy's idle timeout
limit_request_line = 4094                                   # the app caps a URL at 2048 characters
limit_request_fields = 50
limit_request_field_size = 8190
errorlog = "-"                                              # stderr -> container / platform log collector
loglevel = os.getenv("GUNICORN_LOG_LEVEL", "info")
# The app writes its own structured request log (no query strings, no IPs). Gunicorn's access log would add both,
# so it is off unless you ask for it.
accesslog = "-" if os.getenv("GUNICORN_ACCESSLOG") == "1" else None
if os.path.isdir("/dev/shm"):
    worker_tmp_dir = "/dev/shm"                             # heartbeat files in RAM; avoids stalls on slow container disks
