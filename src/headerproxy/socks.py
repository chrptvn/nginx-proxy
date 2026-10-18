"""Minimal async SOCKS5 client (RFC1928): no-auth, CONNECT, hand-rolled.

Used to reach origins through a local SOCKS5 endpoint — the VPN egress chain
(see :mod:`headerproxy.vpn`) hands the connected socket to
``asyncio.open_connection(sock=...)`` for its TLS/raw relays.

socks5h semantics: when the target is a hostname it is transmitted as a
DOMAINNAME address, so DNS is resolved on the proxy side of the tunnel; IP
literals are sent in binary form (ATYP IPv4/IPv6).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import struct

log = logging.getLogger("headerproxy.socks")

_VERSION = 0x05
_CMD_CONNECT = 0x01
_METHOD_NONE = 0x00
_ATYP_IPV4 = 0x01
_ATYP_DOMAIN = 0x03
_ATYP_IPV6 = 0x04


class SocksError(Exception):
    """SOCKS5 negotiation, CONNECT, or transport failure."""


def _encode_target(host: str, port: int) -> bytes:
    """RFC1928 request tail: ATYP + DST.ADDR + DST.PORT for one target."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            raw = host.encode("idna") if not host.isascii() else host.encode("ascii")
        except UnicodeError as exc:
            raise SocksError(f"cannot encode target hostname {host!r}") from exc
        if not 0 < len(raw) < 256:
            raise SocksError(f"target hostname has invalid length: {host!r}") from None
        return bytes([_ATYP_DOMAIN, len(raw)]) + raw + struct.pack(">H", port)
    if ip.version == 4:
        return bytes([_ATYP_IPV4]) + ip.packed + struct.pack(">H", port)
    return bytes([_ATYP_IPV6]) + ip.packed + struct.pack(">H", port)


async def socks5_connect(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float = 10.0,
) -> socket.socket:
    """Open ``target_host:target_port`` through a SOCKS5 proxy (no-auth CONNECT).

    Performs the full RFC1928 handshake on a fresh socket and returns the
    connected raw socket, ready for ``asyncio.open_connection(sock=...)``.
    Raises :class:`SocksError` on any failure.
    """
    loop = asyncio.get_running_loop()
    try:
        sock = await asyncio.wait_for(
            loop.run_in_executor(
                None,
                lambda: socket.create_connection((socks_host, socks_port), timeout=timeout),
            ),
            timeout=timeout + 1,
        )
    except (OSError, asyncio.TimeoutError) as exc:
        raise SocksError(
            f"cannot reach SOCKS5 proxy {socks_host}:{socks_port}: {exc}"
        ) from exc

    async def _recv(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = await loop.sock_recv(sock, n - len(buf))
            if not chunk:
                raise SocksError("SOCKS5 proxy closed the connection mid-handshake")
            buf += chunk
        return buf

    try:
        async with asyncio.timeout(timeout):
            sock.setblocking(False)
            await loop.sock_sendall(sock, bytes([_VERSION, 1, _METHOD_NONE]))
            reply = await _recv(2)
            if reply[0] != _VERSION or reply[1] != _METHOD_NONE:
                raise SocksError(
                    f"SOCKS5 proxy rejected no-auth method (reply {reply.hex()})"
                )
            await loop.sock_sendall(
                sock,
                bytes([_VERSION, _CMD_CONNECT, 0x00]) + _encode_target(target_host, target_port),
            )
            head = await _recv(4)
            if head[1] != 0x00:
                raise SocksError(
                    f"SOCKS5 CONNECT to {target_host}:{target_port} failed (reply code {head[1]})"
                )
            atyp = head[3]
            if atyp == _ATYP_IPV4:
                addr_len = 4
            elif atyp == _ATYP_IPV6:
                addr_len = 16
            elif atyp == _ATYP_DOMAIN:
                addr_len = (await _recv(1))[0]
            else:
                raise SocksError(f"SOCKS5 proxy sent unknown address type {atyp}")
            await _recv(addr_len + 2)  # BND.ADDR + BND.PORT
    except SocksError:
        sock.close()
        raise
    except (OSError, asyncio.TimeoutError) as exc:
        sock.close()
        raise SocksError(
            f"SOCKS5 handshake with {socks_host}:{socks_port} failed: {exc}"
        ) from exc

    log.debug("socks5 tunnel to %s:%s established via %s:%s", target_host, target_port, socks_host, socks_port)
    return sock
