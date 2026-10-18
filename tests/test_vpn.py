"""VPNManager lifecycle end-to-end, driven by the fake wireproxy binary."""

from __future__ import annotations

import asyncio
import os
import signal

import pytest
from curl_cffi import requests as crequests

from headerproxy.config import VPN_SOCKS_PORT, Config
from headerproxy.relay import UpstreamClient
from headerproxy.vpn import VPNManager
from wsclient import ws_over_proxy

PROFILE = """[Interface]
PrivateKey = WPfnY37PznHNXvZeVBlueiMlYRSfCwUFl4PRvXTVREU=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = AabcDEfghijklmnopqrstuvwxyz0123456789+/ABCDE=
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.1:51820
"""


@pytest.fixture
async def vpn(harness, fake_wireproxy):
    """VPNManager sharing the harness's upstream client (egress observable)."""
    cfg = Config(
        data_dir=harness.cfg.data_dir,
        vpn_binary=str(fake_wireproxy.binary),
        log_level="WARNING",
    )
    (cfg.data_dir / "vpn").mkdir(parents=True, exist_ok=True)
    (cfg.data_dir / "vpn" / "dummy.conf").write_text(PROFILE)
    manager = VPNManager(cfg, harness.upstream)
    yield manager
    await manager.shutdown()


async def test_profiles_lists_conf_files_only(vpn, harness):
    (harness.cfg.data_dir / "vpn" / "notes.txt").write_text("ignored")
    assert vpn.profiles() == ["dummy.conf"]


def test_profiles_empty_when_dir_missing(tmp_path):
    manager = VPNManager(
        Config(data_dir=tmp_path / "no-such-dir"), UpstreamClient(timeout=5)
    )
    assert manager.profiles() == []


async def test_activate_unknown_profile_raises(vpn):
    with pytest.raises(RuntimeError, match="unknown VPN profile"):
        await vpn.activate("ghost.conf")
    assert (await vpn.status())["active"] is False


async def test_full_lifecycle(vpn, harness, origin, fake_wireproxy):
    await vpn.activate("dummy.conf")

    status = await vpn.status()
    assert status["active"] is True
    assert status["profile"] == "dummy.conf"
    assert isinstance(status["pid"], int)
    assert status["socks_endpoint"] == f"socks5h://127.0.0.1:{VPN_SOCKS_PORT}"
    assert status["handshake_ready"] is True
    assert status["started_at"]
    assert 0 <= status["uptime_seconds"] < 60
    assert status["profiles"] == ["dummy.conf"]

    # egress switched on the shared upstream client
    assert harness.upstream.proxy_url == f"socks5h://127.0.0.1:{VPN_SOCKS_PORT}"

    # wrapper config lives in vpn-runtime/ and is not offered as a profile
    wrapper = harness.cfg.data_dir / "vpn-runtime" / "dummy.wireproxy.conf"
    assert wrapper.is_file()
    assert vpn.profiles() == ["dummy.conf"]

    # proxied traffic really exits through the socks hop (target host logged)
    resp = crequests.get(f"{origin.url}/echo", proxy=harness.url, timeout=30)
    assert resp.status_code == 200
    assert origin.requests[-1]["path"] == "/echo"
    assert "127.0.0.1" in fake_wireproxy.log.read_text().splitlines()

    # double activate is refused
    with pytest.raises(RuntimeError, match="already active"):
        await vpn.activate("dummy.conf")

    await vpn.deactivate()
    status = await vpn.status()
    assert status["active"] is False
    assert status["profile"] is None
    assert status["pid"] is None
    assert status["socks_endpoint"] is None
    assert status["started_at"] is None
    assert harness.upstream.proxy_url is None
    assert vpn.profiles() == ["dummy.conf"]


async def test_websocket_relay_chains_through_socks_egress(vpn, harness, origin, fake_wireproxy):
    await vpn.activate("dummy.conf")
    echoed = ws_over_proxy(harness.port, "127.0.0.1", origin.port, "/ws", tls=False)
    assert echoed == b"hello-ws"
    # the raw WS tunnel reached the origin through the fake socks hop
    assert "127.0.0.1" in fake_wireproxy.log.read_text().splitlines()


async def test_deactivate_is_idempotent(vpn):
    await vpn.deactivate()  # nothing active: no error
    await vpn.activate("dummy.conf")
    await vpn.deactivate()
    await vpn.deactivate()
    assert (await vpn.status())["active"] is False


async def test_watcher_fails_closed_when_binary_dies(vpn, harness):
    await vpn.activate("dummy.conf")
    pid = (await vpn.status())["pid"]
    os.kill(pid, signal.SIGKILL)
    for _ in range(100):  # the watcher clears egress within a beat
        if harness.upstream.proxy_url is None:
            break
        await asyncio.sleep(0.05)
    assert harness.upstream.proxy_url is None
    assert (await vpn.status())["active"] is False
