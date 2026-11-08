# Cyber Solutions: production image (Flask backend + bundled frontend, served by gunicorn).
# Build:  docker build -t cyber-solutions .
# Run behind an HTTPS proxy, e.g. with docker-compose.yml in this folder (Caddy gets and renews the certificate).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_ENV=production \
    LOG_FORMAT=json \
    BIND=0.0.0.0:8000

# A fixed non-root user. The container never runs as root.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY requirements-prod.txt .
RUN pip install -r requirements-prod.txt

# Only what the server reads at run time. Tests, datasets, the extension and docs stay out of the image (see .dockerignore).
COPY urldetection.py wsgi.py gunicorn.conf.py index.html style.css script.js theme.js robots.txt ./
COPY detection/ detection/
# The operator tool for honouring deletion requests: docker compose exec app python tools/contact_admin.py list
COPY tools/contact_admin.py tools/contact_admin.py
COPY reports/evaluation_results.json reports/evaluation_results.json
# data/ holds the scan-history database and contact messages. Mount a volume here to keep them across redeploys.
RUN mkdir -p data && chown app:app data && chmod 700 data

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT','8000'), timeout=4).status == 200 else 1)"]

CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:app"]
