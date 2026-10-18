"""The asyncio forward proxy (data plane).

Capabilities
------------
* **Plain HTTP** (absolute-form, as browsers send through a proxy).
* **HTTPS via CONNECT** — the proxy answers the CONNECT, performs a server-side
  TLS handshake with a per-host leaf certificate (see :mod:`headerproxy.ca`),
  parses the inner requests, rewrites headers and forwards them upstream.
* **WebSocket** upgrades are relayed as raw tunnels (header rules still apply
  to the upgrade request).
* **Streaming** — response bodies are piped through chunk-by-chunk (chunked
  transfer-encoding to the client), so large downloads and SSE work.

Framing note: the upstream client (curl-impersonate) transparently decompresses
responses; the relay therefore strips ``Content-Encoding``/``Content-Length``
from upstream headers and re-frames the body towards the client.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from dataclasses import dataclass
from http import HTTPStatus
from urllib.parse import urlsplit

from .ca import CertificateAuthority
from .config import Config
from .engine import Engine, SessionRules, apply_rules
from .headers import Headers
from .relay import UpstreamClient, UpstreamResponse
from .stealth import apply_stealth

log = logging.getLogger("headerproxy.proxy")

_HOP_HEADERS = (
    "Connection",
    "Keep-Alive",
    "Proxy-Connection",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "TE",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
)
_RESPONSE_STRIP = _HOP_HEADERS + ("Content-Length", "Content-Encoding")

_DEFAULT_PORTS = {"http": 80, "https": 443}


class BadRequest(Exception):
    pass


class BodyTooLarge(Exception):
    pass


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: Headers
    body: bytes


class ProxyServer:
    def __init__(
        self,
        cfg: Config,
        engine: Engine,
        ca: CertificateAuthority,
        upstream: UpstreamClient,
    ) -> None:
        self._cfg = cfg
        self._engine = engine
        self._ca = ca
        self._upstream = upstream
        self._server: asyncio.Server | None = None
        self._req_counter = 0

    # -- lifecycle ----------------------------------------------------------

    async def serve(self) -> None:
        self._server = await asyncio.start_server(
            self._client_connected,
            host=self._cfg.proxy_host,
            port=self._cfg.proxy_port,
            limit=1024 * 1024,
        )
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets or [])
        log.info("proxy listening on %s", addrs)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            log.info("proxy stopped")

    async def serve_forever(self) -> None:
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    # -- connection handling --------------------------------------------------

    async def _client_connected(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            first_line = await asyncio.wait_for(
                reader.readline(), timeout=self._cfg.client_idle_timeout
            )
        except (asyncio.TimeoutError, ConnectionError):
            first_line = b""
        if not first_line:
            self._close(writer)
            return

        try:
            if first_line.upper().startswith(b"CONNECT"):
                await self._handle_connect(first_line, reader, writer)
            else:
                await self._handle_plain(first_line, reader, writer)
        except asyncio.IncompleteReadError:
            pass
        except (BadRequest, BodyTooLarge) as exc:
            log.warning("bad request from %s: %s", peer, exc)
            await self._simple_response(writer, 400, f"{exc}\n".encode())
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("connection error from %s", peer)
        finally:
            self._close(writer)

    async def _handle_plain(self, first_line: bytes, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = first_line
        while line:
            req = await self._read_request(line, reader, writer)
            if req is None:
                return
            scheme, host, port, path = self._resolve_target(req, default_scheme="http")
            if self._is_websocket(req) and self._cfg.ws_relay:
                await self._relay_websocket(req, scheme, host, port, reader, writer)
                return
            keep = await self._proxy_one(req, scheme, host, port, path, writer)
            if not keep:
                return
            line = await self._read_line(reader)

    async def _handle_connect(self, first_line: bytes, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        parts = first_line.split()
        if len(parts) < 2:
            raise BadRequest("malformed CONNECT line")
        authority = parts[1].decode("latin-1")
        host, _, port_str = authority.rpartition(":")
        if not host:
            host, port_str = authority, "443"
        port = int(port_str) if port_str.isdigit() else 443

        # Consume the remainder of the CONNECT request headers.  This is
        # essential: bytes left in the StreamReader buffer would be orphaned
        # by the TLS upgrade below (they would no longer reach the TLS layer).
        await reader.readuntil(b"\r\n\r\n")

        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        loop = asyncio.get_running_loop()
        tls_ctx = self._ca.leaf_context(host)
        try:
            transport = writer.transport
            protocol = transport.get_protocol()
            new_transport = await loop.start_tls(
                transport, protocol, tls_ctx, server_side=True
            )
        except (ssl.SSLError, ConnectionError, OSError) as exc:
            # Chromium fires speculative preconnects whose certificate errors
            # are retried inside the real navigation — too noisy at INFO.
            log.debug("TLS handshake with client failed for %s: %s", host, exc)
            return
        writer = asyncio.StreamWriter(new_transport, protocol, reader, loop)

        line = await self._read_line(reader)
        while line:
            req = await self._read_request(line, reader, writer)
            if req is None:
                return
            path = _origin_path(req)
            if self._is_websocket(req) and self._cfg.ws_relay:
                await self._relay_websocket(req, "https", host, port, reader, writer)
                return
            keep = await self._proxy_one(req, "https", host, port, path, writer)
            if not keep:
                return
            line = await self._read_line(reader)

    # -- request pipeline -----------------------------------------------------

    async def _proxy_one(
        self,
        req: Request,
        scheme: str,
        host: str,
        port: int,
        path: str,
        writer: asyncio.StreamWriter,
    ) -> bool:
        """Rewrite + forward one request, stream the response back.

        Returns True when the client connection may be reused.
        """
        snapshot: SessionRules = self._engine.current()
        session = snapshot.name or "default"
        hostport = host if port == _DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
        started = time.monotonic()

        keep = _client_wants_keepalive(req)
        headers = req.headers
        for name in _HOP_HEADERS:
            headers.remove(name)
        headers.remove("Content-Length")  # curl sets it from the body
        headers.remove("Content-Encoding")  # curl sets its own from impersonation
        headers.remove("Host")  # curl derives it from the URL
        headers.remove("Expect")  # curl manages 100-continue itself

        stealth_notes: list[str] = []
        if snapshot.stealth:
            stealth_notes = apply_stealth(headers)
        applied = apply_rules(snapshot.request_rules, headers, host, hostport, path)

        if port == _DEFAULT_PORTS.get(scheme):
            url = f"{scheme}://{host}{path}"
        else:
            url = f"{scheme}://{host}:{port}{path}"

        try:
            upstream = await self._upstream.request(
                method=req.method, url=url, headers=headers.to_list(), body=req.body or None
            )
        except Exception as exc:
            log.warning("[%s] upstream failure %s %s: %s", session, req.method, url, exc)
            await self._simple_response(writer, 502, b"upstream request failed\n")
            return False

        resp_headers = Headers(upstream.headers)
        for name in _RESPONSE_STRIP:
            resp_headers.remove(name)
        resp_applied = apply_rules(
            snapshot.response_rules, resp_headers, host, hostport, path
        )

        status = upstream.status
        try:
            reason = HTTPStatus(status).phrase
        except ValueError:
            reason = "Unknown"

        no_body = (
            req.method == "HEAD" or status < 200 or status in (204, 205, 304)
        )
        head = [f"HTTP/1.1 {status} {reason}\r\n".encode("latin-1")]
        head += [f"{n}: {v}\r\n".encode("latin-1") for n, v in resp_headers]
        if no_body:
            head.append(b"\r\n")
            writer.write(b"".join(head))
            await writer.drain()
            await upstream.aclose()
        else:
            head.append(b"Transfer-Encoding: chunked\r\n\r\n")
            writer.write(b"".join(head))
            await writer.drain()
            try:
                async for chunk in upstream.iter_content():
                    writer.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    if writer.transport is None:
                        break
                    if len(chunk) >= 16384:
                        await writer.drain()
                else:
                    writer.write(b"0\r\n\r\n")
                    await writer.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            finally:
                await upstream.aclose()

        log.info(
            "[%s] #%d %s %s%s -> %s (%d req rules, %d resp rules, %.0f ms)",
            session,
            self._next_id(),
            req.method,
            hostport,
            path,
            status,
            len(applied),
            len(resp_applied),
            (time.monotonic() - started) * 1000,
        )
        if stealth_notes:
            log.debug("[%s] stealth: %s", session, "; ".join(stealth_notes))
        if applied:
            log.debug("[%s] request rules applied: %s", session, applied)
        return keep

    # -- websocket relay ------------------------------------------------------

    async def _relay_websocket(
        self,
        req: Request,
        scheme: str,
        host: str,
        port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Tunnel a WebSocket upgrade as raw bytes after header rewriting."""
        session = self._engine.current().name or "default"
        headers = req.headers
        headers.remove("Proxy-Connection")
        headers.remove("Proxy-Authorization")
        headers.remove("Content-Length")
        stealth_notes = apply_stealth(headers) if self._engine.current().stealth else []
        apply_rules(
            self._engine.current().request_rules,
            headers,
            host,
            f"{host}:{port}" if port != _DEFAULT_PORTS.get(scheme) else host,
            _origin_path(req),
        )

        upstream_tls = self._upstream.tls_context if scheme == "https" else None
        try:
            up_reader, up_writer = await asyncio.open_connection(
                host, port, ssl=upstream_tls, server_hostname=host if upstream_tls else None
            )
        except OSError as exc:
            log.warning("[%s] websocket connect to %s:%s failed: %s", session, host, port, exc)
            await self._simple_response(writer, 502, b"websocket upstream failed\n")
            return

        # Re-emit the upgrade request verbatim with rewritten headers.
        head = [f"{req.method} {_origin_path(req)} HTTP/1.1\r\n".encode("latin-1")]
        head += [f"{n}: {v}\r\n".encode("latin-1") for n, v in headers]
        head.append(b"\r\n")
        try:
            up_writer.write(b"".join(head))
            await up_writer.drain()
            await asyncio.gather(
                self._pipe(reader, up_writer, "client->origin"),
                self._pipe(up_reader, writer, "origin->client"),
            )
        except (ConnectionError, asyncio.CancelledError, OSError):
            pass
        finally:
            self._close(up_writer)
        log.info(
            "[%s] websocket tunnel %s:%s closed%s",
            session,
            host,
            port,
            f" ({'; '.join(stealth_notes)})" if stealth_notes else "",
        )

    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, label: str) -> None:
        try:
            while True:
                chunk = await src.read(65536)
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            try:
                if dst.transport is not None:
                    dst.transport.close()
            except Exception:  # pragma: no cover
                pass

    # -- request parsing ------------------------------------------------------

    async def _read_line(self, reader: asyncio.StreamReader) -> bytes:
        try:
            return await asyncio.wait_for(
                reader.readline(), timeout=self._cfg.client_idle_timeout
            )
        except asyncio.TimeoutError:
            return b""

    async def _read_request(
        self, first_line: bytes, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> Request | None:
        """Parse one request starting with ``first_line`` (already read)."""
        parts = first_line.decode("latin-1").rstrip("\r\n").split()
        if len(parts) != 3:
            raise BadRequest("malformed request line")
        method, target, version = parts
        if not version.startswith("HTTP/1"):
            raise BadRequest(f"unsupported protocol {version}")

        headers = Headers()
        last_name: str | None = None
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            if line[:1] in (b" ", b"\t") and last_name:
                prev = headers.get(last_name)
                if prev is not None:
                    headers.set(last_name, prev + " " + line.decode("latin-1").strip())
                continue
            name, sep, value = line.decode("latin-1").partition(":")
            if not sep:
                raise BadRequest("malformed header line")
            name = name.strip()
            headers.add(name, value.strip())
            last_name = name

        expect = headers.get("Expect", "")
        content_length = headers.get("Content-Length")
        chunked = "chunked" in headers.get("Transfer-Encoding", "").lower()

        body = b""
        if expect.lower() == "100-continue" and (chunked or content_length):
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            await writer.drain()

        if chunked:
            body = await self._read_chunked_body(reader)
        elif content_length:
            try:
                length = int(content_length)
            except ValueError as exc:
                raise BadRequest("invalid Content-Length") from exc
            if length < 0:
                raise BadRequest("invalid Content-Length")
            if length > self._cfg.max_body_bytes:
                raise BodyTooLarge(f"body of {length} bytes exceeds limit")
            body = await reader.readexactly(length) if length else b""

        return Request(method=method.upper(), target=target, version=version, headers=headers, body=body)

    async def _read_chunked_body(self, reader: asyncio.StreamReader) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            size_line = await reader.readline()
            if not size_line:
                raise BadRequest("truncated chunked body")
            size_str = size_line.split(b";", 1)[0].strip()
            try:
                size = int(size_str, 16)
            except ValueError as exc:
                raise BadRequest("invalid chunk size") from exc
            if size == 0:
                # consume trailers until the blank line
                while True:
                    trailer = await reader.readline()
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                return b"".join(chunks)
            total += size
            if total > self._cfg.max_body_bytes:
                raise BodyTooLarge(f"chunked body exceeds limit of {self._cfg.max_body_bytes} bytes")
            chunks.append(await reader.readexactly(size))
            await reader.readexactly(2)  # CRLF

    # -- helpers ---------------------------------------------------------------

    def _resolve_target(self, req: Request, default_scheme: str) -> tuple[str, str, int, str]:
        """Return (scheme, host, port, path) for a parsed request."""
        split = urlsplit(req.target)
        if split.scheme in ("http", "https"):
            scheme = split.scheme
            host = split.hostname or ""
            port = split.port or _DEFAULT_PORTS[scheme]
            path = split.path or "/"
            if split.query:
                path += "?" + split.query
        else:
            scheme = default_scheme
            host_header = req.headers.get("Host", "")
            host, _, port_str = host_header.rpartition(":")
            if not host or not port_str.isdigit():
                host, port_str = host_header, str(_DEFAULT_PORTS[scheme])
            port = int(port_str)
            path = req.target if req.target.startswith("/") else "/" + req.target
        if not host:
            raise BadRequest("no target host")
        return scheme, host.lower(), port, path or "/"

    @staticmethod
    def _is_websocket(req: Request) -> bool:
        if "upgrade" not in req.headers.get("Connection", "").lower():
            return False
        return req.headers.get("Upgrade", "").lower() == "websocket"

    def _next_id(self) -> int:
        self._req_counter += 1
        return self._req_counter

    @staticmethod
    async def _simple_response(writer: asyncio.StreamWriter, status: int, body: bytes) -> None:
        try:
            reason = HTTPStatus(status).phrase
            writer.write(
                b"".join(
                    [
                        f"HTTP/1.1 {status} {reason}\r\n".encode("latin-1"),
                        b"Content-Type: text/plain; charset=utf-8\r\n",
                        f"Content-Length: {len(body)}\r\n".encode("latin-1"),
                        b"Connection: close\r\n\r\n",
                        body,
                    ]
                )
            )
            await writer.drain()
        except (ConnectionError, RuntimeError):
            pass

    @staticmethod
    def _close(writer: asyncio.StreamWriter) -> None:
        try:
            writer.close()
        except Exception:  # pragma: no cover
            pass


def _client_wants_keepalive(req: Request) -> bool:
    connection = req.headers.get("Connection", "").lower()
    if "close" in connection:
        return False
    if req.version == "HTTP/1.0":
        return "keep-alive" in connection
    return True


def _origin_path(req: Request) -> str:
    """Origin-form path of a request (used inside CONNECT tunnels / relays)."""
    if req.target.startswith("http://") or req.target.startswith("https://"):
        split = urlsplit(req.target)
        path = split.path or "/"
        if split.query:
            path += "?" + split.query
        return path
    return req.target if req.target.startswith("/") else "/" + req.target
