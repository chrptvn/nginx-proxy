"""Shared fixtures: origin servers and a proxy harness on its own loop."""

from __future__ import annotations

import asyncio
import ssl
import threading
import datetime as _dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from headerproxy.ca import CertificateAuthority
from headerproxy.config import Config
from headerproxy.engine import Engine
from headerproxy.proxy import ProxyServer
from headerproxy.relay import UpstreamClient
from headerproxy.store import Store

from origin import OriginServer


class ProxyHarness:
    """Runs a ProxyServer in a dedicated thread + event loop (ephemeral port)."""

    def __init__(self, tmp_path) -> None:
        self.cfg = Config(
            data_dir=tmp_path / "data",
            proxy_host="127.0.0.1",
            proxy_port=0,  # ephemeral; the real port is read after bind
            api_host="127.0.0.1",
            log_level="WARNING",
            client_idle_timeout=10.0,
        )
        self.store = Store(self.cfg.data_dir / "headerproxy.db")
        self.store.ensure_default_session(self.cfg.stealth_default)
        self.engine = Engine(self.store)
        self.engine.reload()
        self.ca = CertificateAuthority.load_or_create(
            self.cfg.data_dir, self.cfg.cert_cache_size
        )
        self.upstream = UpstreamClient(self.cfg.impersonate, self.cfg.upstream_timeout)
        self.proxy = ProxyServer(self.cfg, self.engine, self.ca, self.upstream)
        self.port: int | None = None
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._wait_ready()

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._start())
        self._loop.run_forever()

    async def _start(self) -> None:
        await self.proxy.serve()
        self.port = self.proxy._server.sockets[0].getsockname()[1]

    def _wait_ready(self, timeout: float = 10.0) -> None:
        import time

        deadline = time.monotonic() + timeout
        while self.port is None:
            if time.monotonic() > deadline or not self._thread.is_alive():
                raise RuntimeError("proxy failed to start")
            time.sleep(0.02)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def ca_pem_path(self):
        path = self.cfg.data_dir / "ca" / "ca.crt"
        path.write_bytes(self.ca.ca_pem)
        return path

    def trust_ca(self, pem_path) -> None:
        """Make upstream requests trust a custom CA (used for test origins)."""
        self.upstream.set_verify(str(pem_path))

    # -- control helpers (store + engine reload, thread-safe) --------------

    def add_override(self, **kwargs):
        override = self.store.add_override("default", **kwargs)
        self.engine.reload()
        return override

    def add_filter(self, **kwargs):
        f = self.store.add_filter("default", **kwargs)
        self.engine.reload()
        return f

    def activate(self, name: str) -> None:
        self.store.activate_session(name)
        self.engine.reload()

    def create_session(self, name: str, stealth: bool = True) -> None:
        self.store.create_session(name, stealth)
        self.engine.reload()

    def stop(self) -> None:
        async def _stop():
            await self.proxy.stop()
            await self.upstream.close()

        try:
            asyncio.run_coroutine_threadsafe(_stop(), self._loop).result(10)
        except Exception:
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(10)
        self.store.close()


@pytest.fixture
def origin():
    server = OriginServer()
    yield server
    server.stop()


@pytest.fixture
def tls_origin():
    key = ec.generate_private_key(ec.SECP256R1())
    now = _dt.datetime.now(_dt.timezone.utc)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress_or("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    pem_path = None  # built below as an in-memory file for the server
    import tempfile
    from pathlib import Path

    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        pem_path = Path(f.name)
    ctx.load_cert_chain(str(pem_path))
    server = OriginServer(tls_ctx=ctx)
    server.stop_pem = pem_path
    yield server
    server.stop()
    pem_path.unlink(missing_ok=True)


def ipaddress_or(addr: str):
    import ipaddress

    return ipaddress.ip_address(addr)


@pytest.fixture
def harness(tmp_path):
    h = ProxyHarness(tmp_path)
    yield h
    h.stop()


@pytest.fixture
def proxy_url(harness) -> str:
    return harness.url


@pytest.fixture
def ca_pem(harness, tmp_path):
    return harness.ca_pem_path
