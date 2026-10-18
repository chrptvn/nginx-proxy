FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    HP_DATA_DIR=/data \
    HP_API_HOST=0.0.0.0 \
    HP_PROXY_HOST=0.0.0.0

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Non-root runtime; /data holds the SQLite database and the CA keypair.
# (Debian ships a system "proxy" user, hence the explicit name/uid.)
RUN useradd --create-home --uid 1000 headerproxy \
    && mkdir -p /data \
    && chown headerproxy:headerproxy /data
USER headerproxy

VOLUME /data
EXPOSE 8080 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request as u,sys;sys.exit(0 if u.urlopen('http://127.0.0.1:8080/api/health',timeout=3).status==200 else 1)"]

CMD ["python", "-m", "headerproxy"]
