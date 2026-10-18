"""Entrypoint: wires store, engine, CA, proxy and control plane together."""

from __future__ import annotations

import logging
import shutil

import uvicorn

from .api import create_app
from .ca import CertificateAuthority
from .config import Config
from .engine import Engine
from .mcp_server import create_mcp
from .proxy import ProxyServer
from .relay import UpstreamClient
from .runtime import Runtime
from .store import Store
from .vpn import VPNManager

log = logging.getLogger("headerproxy")


def build_runtime(cfg: Config) -> Runtime:
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(cfg.data_dir / "headerproxy.db")
    store.ensure_default_session(cfg.stealth_default)
    engine = Engine(store)
    engine.reload()
    ca = CertificateAuthority.load_or_create(cfg.data_dir, cfg.cert_cache_size)
    verify: str | bool = True
    if cfg.upstream_verify.lower() in ("none", "false", "0"):
        verify = False
    elif cfg.upstream_verify.lower() != "system":
        verify = cfg.upstream_verify
    upstream = UpstreamClient(
        impersonate=cfg.impersonate, timeout=cfg.upstream_timeout, verify=verify
    )
    proxy = ProxyServer(cfg, engine, ca, upstream)
    vpn: VPNManager | None = None
    if not cfg.vpn_enabled:
        log.info("VPN feature disabled (HP_VPN=0)")
    elif shutil.which(cfg.vpn_binary) is None:
        log.warning("VPN feature disabled (binary not found: %s)", cfg.vpn_binary)
    else:
        vpn = VPNManager(cfg, upstream)
    log.info(
        "data dir %s | active session: %s | impersonate: %s",
        cfg.data_dir,
        store.active_session_name(),
        cfg.impersonate,
    )
    return Runtime(
        cfg=cfg, store=store, engine=engine, ca=ca, upstream=upstream, proxy=proxy, vpn=vpn
    )


def main() -> None:
    cfg = Config.from_env()
    logging.basicConfig(
        level=cfg.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    rt = build_runtime(cfg)
    mcp = create_mcp(rt)
    mcp_app = mcp.streamable_http_app()
    app = create_app(rt, mcp_app=mcp_app)
    uvicorn.run(
        app,
        host=cfg.api_host,
        port=cfg.api_port,
        log_level=cfg.log_level.lower(),
        access_log=False,
    )


if __name__ == "__main__":
    main()
