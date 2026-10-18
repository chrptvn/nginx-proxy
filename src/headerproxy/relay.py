"""Upstream HTTP client with Chrome-grade TLS and HTTP/2 fingerprints.

Outgoing requests are performed by ``curl_cffi`` backed by ``curl-impersonate``,
which reproduces a real Chrome TLS (JA3/JA4), HTTP/2 SETTINGS/window/priority
fingerprint and header casing.  This is what keeps the MITM proxy from
becoming the weakest link: the origin sees a Chrome-like client even though
the proxy terminates the browser's TLS.

Responses are streamed (``aiter_content``) so large downloads and SSE pass
through with low memory usage.  Response bodies are transparently
decompressed by curl; the relay layer therefore strips ``Content-Encoding``
and re-frames the body (see :mod:`headerproxy.proxy`).
"""

from __future__ import annotations

import logging
import ssl
from typing import AsyncIterator

from curl_cffi.requests import AsyncSession

log = logging.getLogger("headerproxy.relay")


def build_client_context(verify: str | bool) -> ssl.SSLContext:
    """Build the upstream TLS client context for a given verify setting."""
    if verify is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    ctx = ssl.create_default_context()
    if isinstance(verify, str):
        ctx.load_verify_locations(verify)
    return ctx


class UpstreamResponse:
    """Status + headers plus an async body iterator of an upstream exchange."""

    def __init__(self, status: int, headers: list[tuple[str, str]], raw) -> None:
        self.status = status
        self.headers = headers
        self._raw = raw
        self._closed = False

    async def iter_content(self, chunk_size: int = 16384) -> AsyncIterator[bytes]:
        try:
            async for chunk in self._raw.aiter_content():
                if chunk:
                    yield chunk
        finally:
            await self.aclose()

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                await self._raw.aclose()
            except Exception:  # pragma: no cover - best effort release
                pass


class UpstreamClient:
    """Thin async wrapper around one shared ``curl_cffi`` session."""

    def __init__(
        self,
        impersonate: str = "chrome",
        timeout: float = 180.0,
        verify: str | bool = True,
    ) -> None:
        self._timeout = timeout
        self._verify = verify
        self._tls_context: ssl.SSLContext | None = None
        self._session = AsyncSession(impersonate=impersonate, allow_redirects=False)

    def set_verify(self, verify: str | bool) -> None:
        """Trust a custom CA bundle for upstream connections (path or bool)."""
        self._verify = verify
        self._tls_context = None

    @property
    def tls_context(self) -> ssl.SSLContext:
        """TLS context shared with raw relays (WebSocket tunnels)."""
        if self._tls_context is None:
            self._tls_context = build_client_context(self._verify)
        return self._tls_context

    async def request(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes | None = None,
    ) -> UpstreamResponse:
        response = await self._session.request(
            method=method,
            url=url,
            headers=headers,
            data=body if body is not None else b"",
            stream=True,
            allow_redirects=False,
            timeout=self._timeout,
            verify=self._verify,
        )
        status = int(response.status_code)
        raw_headers: list[tuple[str, str]] = []
        multi = getattr(response.headers, "multi_items", None)
        if callable(multi):
            raw_headers = [(str(k), str(v)) for k, v in multi()]
        else:  # pragma: no cover - older curl_cffi fallback
            raw_headers = [(str(k), str(v)) for k, v in response.headers.items()]
        return UpstreamResponse(status, raw_headers, response)

    async def close(self) -> None:
        try:
            await self._session.close()
        except Exception:  # pragma: no cover - best effort
            pass
