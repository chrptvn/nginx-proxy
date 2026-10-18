"""Managed wireproxy subprocess: optional WireGuard egress for the proxy.

`wireproxy <https://github.com/pufferffish/wireproxy>`_ is a userspace
WireGuard client that exposes a tunnel as a local SOCKS5 proxy.  A
:class:`VPNManager` generates a wrapper config for a wg-quick profile dropped
into ``<data_dir>/vpn/``, spawns the binary, health-checks the SOCKS and info
endpoints, and finally reroutes the shared upstream client's egress through
the tunnel (``upstream.set_proxy("socks5h://127.0.0.1:<port>")``).  All
further upstream requests then leave through the VPN until the tunnel is
deactivated or dies (fail-closed: egress is cleared as soon as the process
exits).

Profiles are never copied or parsed here — wireproxy reads them directly from
the (typically read-only mounted) ``vpn/`` directory; generated wrapper
configs live in ``vpn-runtime/`` so they can never be mistaken for profiles.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

from .config import VPN_INFO_PORT, VPN_SOCKS_PORT, Config
from .relay import UpstreamClient

log = logging.getLogger("headerproxy.vpn")

# Readiness budget: wireproxy may need a while for the WireGuard handshake.
_READY_TIMEOUT = 25.0
_POLL_INTERVAL = 0.25
# If the SOCKS port accepts but the info endpoint never appears at all, the
# binary may predate the info API — proceed with unknown health instead of
# failing outright (a *present* endpoint answering 503 still keeps us waiting,
# since that is wireproxy's "tunnel not handshaked yet" signal).
_UNKNOWN_HEALTH_GRACE = 8.0
_SIGKILL_AFTER = 5.0
_LOG_TAIL = 4096


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class VPNManager:
    """Lifecycle of one wireproxy subprocess and its egress switchover."""

    def __init__(self, cfg: Config, upstream: UpstreamClient) -> None:
        self._cfg = cfg
        self._upstream = upstream
        self._proc: asyncio.subprocess.Process | None = None
        self._profile: str | None = None
        self._socks_port: int | None = None
        self._info_port: int | None = None
        self._started_at: float | None = None
        self._log_tail = b""
        self._lock = asyncio.Lock()
        self._tasks: set[asyncio.Task] = set()

    # -- profiles ----------------------------------------------------------------

    @property
    def _vpn_dir(self) -> Path:
        return self._cfg.data_dir / "vpn"

    @property
    def _runtime_dir(self) -> Path:
        return self._cfg.data_dir / "vpn-runtime"

    def profiles(self) -> list[str]:
        """Sorted basenames of ``*.conf`` profiles in ``<data_dir>/vpn/``."""
        try:
            entries = list(self._vpn_dir.iterdir())
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            return []
        return sorted(e.name for e in entries if e.is_file() and e.suffix == ".conf")

    @property
    def active_profile(self) -> str | None:
        """Profile name while the tunnel is alive, else ``None``."""
        proc = self._proc
        if proc is not None and proc.returncode is None:
            return self._profile
        return None

    def _profile_path(self, name: str) -> Path:
        if (
            not name.endswith(".conf")
            or "/" in name
            or name != Path(name).name
            or not (self._vpn_dir / name).is_file()
        ):
            raise RuntimeError(f"unknown VPN profile: {name!r}")
        return self._vpn_dir / name

    def _write_wrapper(self, profile_path: Path, socks_port: int) -> Path:
        """Generate the wireproxy wrapper config in ``vpn-runtime/``."""
        self._runtime_dir.mkdir(parents=True, exist_ok=True)
        wrapper = self._runtime_dir / f"{profile_path.stem}.wireproxy.conf"
        wrapper.write_text(
            f"WGConfig = {profile_path.resolve()}\n"
            "[Socks5]\n"
            f"BindAddress = 127.0.0.1:{socks_port}\n"
        )
        return wrapper

    # -- lifecycle -----------------------------------------------------------------

    async def activate(self, profile: str) -> None:
        """Spawn wireproxy for ``profile`` and switch egress through it."""
        async with self._lock:
            profile_path = self._profile_path(profile)  # unknown -> error first
            if self.active_profile is not None:
                raise RuntimeError(
                    f"VPN already active (profile {self._profile}); deactivate first"
                )
            socks_port, info_port = VPN_SOCKS_PORT, VPN_INFO_PORT
            wrapper = self._write_wrapper(profile_path, socks_port)
            log.info(
                "starting %s for profile %s (socks 127.0.0.1:%d)",
                self._cfg.vpn_binary,
                profile,
                socks_port,
            )
            self._log_tail = b""
            try:
                proc = await asyncio.create_subprocess_exec(
                    self._cfg.vpn_binary,
                    "-c", str(wrapper),
                    "-i", f"127.0.0.1:{info_port}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,
                )
            except OSError as exc:
                raise RuntimeError(f"cannot spawn {self._cfg.vpn_binary}: {exc}") from exc

            self._proc = proc
            self._profile = profile
            self._socks_port = socks_port
            self._info_port = info_port
            self._started_at = time.time()
            self._drain_output(proc)
            self._spawn(self._watch(proc))

            try:
                handshake_ready = await self._wait_ready(proc, socks_port, info_port)
            except Exception as exc:
                # Detach first so the exit watcher stays quiet, then clean up.
                self._clear()
                await self._kill(proc)
                if isinstance(exc, RuntimeError):
                    raise
                raise RuntimeError(f"wireproxy failed to become ready: {exc}") from exc

            self._upstream.set_proxy(f"socks5h://127.0.0.1:{socks_port}")
            log.info(
                "VPN profile %s active, egress via socks5h://127.0.0.1:%d (pid %d, handshake %s)",
                profile,
                socks_port,
                proc.pid,
                "ready" if handshake_ready else "unknown",
            )

    async def deactivate(self) -> None:
        """Stop the tunnel and restore direct egress (idempotent)."""
        async with self._lock:
            proc = self._proc
            if proc is None:
                return
            self._proc = None  # detach first so the exit watcher stays quiet
            await self._kill(proc)
            self._upstream.set_proxy(None)
            self._clear()
            log.info("VPN deactivated, egress direct")

    async def shutdown(self) -> None:
        """Tear the tunnel down (app lifespan exit)."""
        if self._proc is not None:
            await self.deactivate()

    async def status(self) -> dict:
        """Current tunnel state; also self-heals when the process died."""
        proc = self._proc
        if proc is not None and proc.returncode is not None and self._profile is not None:
            # The watcher task usually gets here first; this covers reads
            # before the watcher has been scheduled.
            log.warning("wireproxy exited (code %s); clearing VPN egress", proc.returncode)
            self._upstream.set_proxy(None)
            self._clear()
            proc = None
        active = proc is not None and proc.returncode is None
        payload = {
            "active": active,
            "profile": self._profile if active else None,
            "pid": proc.pid if active else None,
            "socks_endpoint": (
                f"socks5h://127.0.0.1:{self._socks_port}" if active else None
            ),
            "started_at": _iso(self._started_at) if active and self._started_at else None,
            "uptime_seconds": (
                round(time.time() - self._started_at, 3)
                if active and self._started_at
                else None
            ),
            "profiles": self.profiles(),
        }
        if active and self._info_port is not None:
            code = await _readyz_status(self._info_port)
            if code is not None:
                payload["handshake_ready"] = code == 200
        return payload

    # -- internals ------------------------------------------------------------------

    async def _wait_ready(
        self, proc: asyncio.subprocess.Process, socks_port: int, info_port: int
    ) -> bool:
        """Poll until the tunnel is usable.  True = /readyz said 200; False =
        only the SOCKS port came up (health unknown)."""
        deadline = time.monotonic() + _READY_TIMEOUT
        socks_up_since: float | None = None
        while time.monotonic() < deadline:
            if proc.returncode is not None:
                raise RuntimeError(self._failure_reason(proc.returncode))
            if await _tcp_probe(socks_port):
                socks_up_since = socks_up_since or time.monotonic()
                code = await _readyz_status(info_port)
                if code == 200:
                    return True
                if (
                    code is None
                    and time.monotonic() - socks_up_since > _UNKNOWN_HEALTH_GRACE
                ):
                    log.warning(
                        "wireproxy SOCKS port is up but the info endpoint on %d never "
                        "appeared; continuing with unknown handshake state",
                        info_port,
                    )
                    return False
            else:
                socks_up_since = None
            await asyncio.sleep(_POLL_INTERVAL)
        raise RuntimeError(
            f"wireproxy did not become ready within {_READY_TIMEOUT:.0f}s "
            f"(last output: {self._tail_text()})"
        )

    def _failure_reason(self, returncode: int | None) -> str:
        return (
            f"wireproxy exited during startup (code {returncode}); "
            f"output tail: {self._tail_text()}"
        )

    def _tail_text(self) -> str:
        return self._log_tail.decode(errors="replace").strip() or "<no output>"

    def _drain_output(self, proc: asyncio.subprocess.Process) -> None:
        """Log wireproxy's stdout/stderr lines and keep a tail for errors."""
        for stream, name in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
            if stream is not None:
                self._spawn(self._drain(stream, name))

    async def _drain(self, stream: asyncio.StreamReader, name: str) -> None:
        while True:
            try:
                line = await stream.readline()
            except (ConnectionError, OSError):  # pragma: no cover - process gone
                return
            if not line:
                return
            text = line.decode(errors="replace").rstrip()
            if text:
                log.warning("wireproxy %s: %s", name, text)
            self._log_tail = (self._log_tail + line)[-_LOG_TAIL:]

    async def _kill(self, proc: asyncio.subprocess.Process) -> None:
        """SIGTERM the process group, then SIGKILL after a grace period."""
        if proc.returncode is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):  # pragma: no cover
                proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=_SIGKILL_AFTER)
            except asyncio.TimeoutError:
                log.warning("wireproxy did not exit on SIGTERM; sending SIGKILL")
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):  # pragma: no cover
                    proc.kill()
                await proc.wait()
        else:
            await proc.wait()

    def _clear(self) -> None:
        self._proc = None
        self._profile = None
        self._socks_port = None
        self._info_port = None
        self._started_at = None

    def _spawn(self, coro) -> None:
        """Keep a strong reference to a background task until it finishes."""
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _watch(self, proc: asyncio.subprocess.Process) -> None:
        """Fail closed when the subprocess exits without being deactivated."""
        await proc.wait()
        if self._proc is not proc:
            return  # activate() failure path or deactivate() owns the teardown
        log.warning(
            "wireproxy exited unexpectedly (code %s); VPN egress disabled", proc.returncode
        )
        self._upstream.set_proxy(None)
        self._clear()


async def _tcp_probe(port: int, timeout: float = 1.0) -> bool:
    """True when a TCP listener on 127.0.0.1:<port> accepts a connection."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port), timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, asyncio.TimeoutError):  # pragma: no cover - best effort
        pass
    return True


async def _readyz_status(port: int, timeout: float = 2.0) -> int | None:
    """HTTP status of the wireproxy info endpoint's /readyz (None if absent)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port), timeout
        )
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        writer.write(b"GET /readyz HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout)
        parts = status_line.split()
        return int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
    except (OSError, asyncio.TimeoutError, ValueError, IndexError):
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError):  # pragma: no cover - best effort
            pass
