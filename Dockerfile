FROM python:3.12-slim

# wireproxy (userspace WireGuard -> SOCKS5) powers the optional VPN egress.
# Repo moved pufferffish/wireproxy -> windtf/wireproxy (old URLs redirect).
# Asset naming: wireproxy_linux_<arch>.tar.gz, amd64/arm64/... (Go arch names).
ARG WIREPROXY_VERSION=v1.1.3
ARG WIREPROXY_ARCH=amd64

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

# Single tidy layer: fetch + extract the release archive (the tarball itself is
# never written to disk), verify the binary runs, then drop the helper packages.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL \
        "https://github.com/windtf/wireproxy/releases/download/${WIREPROXY_VERSION}/wireproxy_linux_${WIREPROXY_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin wireproxy \
    && chmod 0755 /usr/local/bin/wireproxy \
    && wireproxy --version \
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/*

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
