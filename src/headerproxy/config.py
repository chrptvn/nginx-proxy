"""Environment-driven configuration.

Every option can be set through an environment variable prefixed with ``HP_``;
the table in README.md documents each one.  Defaults are chosen so the proxy
is usable out of the box inside a Docker network.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_bool(env: dict[str, str], key: str, default: bool) -> bool:
    raw = env.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(env: dict[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    return int(raw) if raw else default


def _env_float(env: dict[str, str], key: str, default: float) -> float:
    raw = env.get(key)
    return float(raw) if raw else default


# Local endpoints of the wireproxy subprocess (see headerproxy.vpn): the SOCKS5
# egress port and the HTTP info/health port.  One VPN manager per process, so
# fixed ports are unambiguous.
VPN_SOCKS_PORT = 40001
VPN_INFO_PORT = 40002


@dataclass(frozen=True)
class Config:
    """Runtime configuration for both the proxy and the control plane."""

    proxy_host: str = "0.0.0.0"
    proxy_port: int = 8088
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    data_dir: Path = field(default_factory=lambda: Path("/data"))
    log_level: str = "INFO"
    # When set, every /api and /mcp request must carry
    # "Authorization: Bearer <key>".  /api/health stays open for healthchecks.
    api_key: str | None = None
    # curl-impersonate target used for upstream requests, e.g. "chrome".
    impersonate: str = "chrome"
    # Stealth normalization applied to newly created sessions by default.
    stealth_default: bool = True
    # Cap for buffered request bodies (origin uploads are relayed in memory).
    max_body_bytes: int = 64 * 1024 * 1024
    # Idle time before an established client connection is closed.
    client_idle_timeout: float = 300.0
    # Upstream request timeout (single value, applies to the whole exchange).
    upstream_timeout: float = 180.0
    # Maximum number of MITM leaf certificates kept in the LRU cache.
    cert_cache_size: int = 2048
    # Relay WebSocket upgrades as raw tunnels.
    ws_relay: bool = True
    # Upstream TLS verification: "system" (default), "none", or a CA bundle path.
    upstream_verify: str = "system"
    # VPN egress: spawn wireproxy (userspace WireGuard -> SOCKS5) and route all
    # upstream traffic through the tunnel.  See headerproxy.vpn.
    vpn_enabled: bool = True
    vpn_binary: str = "wireproxy"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Config":
        env = dict(os.environ if env is None else env)
        return cls(
            proxy_host=env.get("HP_PROXY_HOST", "0.0.0.0"),
            proxy_port=_env_int(env, "HP_PROXY_PORT", 8088),
            api_host=env.get("HP_API_HOST", "0.0.0.0"),
            api_port=_env_int(env, "HP_API_PORT", 8080),
            data_dir=Path(env.get("HP_DATA_DIR", "/data")),
            log_level=env.get("HP_LOG_LEVEL", "INFO").upper(),
            api_key=env.get("HP_API_KEY") or None,
            impersonate=env.get("HP_IMPERSONATE", "chrome"),
            stealth_default=_env_bool(env, "HP_STEALTH_DEFAULT", True),
            max_body_bytes=_env_int(env, "HP_MAX_BODY_BYTES", 64 * 1024 * 1024),
            client_idle_timeout=_env_float(env, "HP_CLIENT_IDLE_TIMEOUT", 300.0),
            upstream_timeout=_env_float(env, "HP_UPSTREAM_TIMEOUT", 180.0),
            cert_cache_size=_env_int(env, "HP_CERT_CACHE_SIZE", 2048),
            ws_relay=_env_bool(env, "HP_WS_RELAY", True),
            upstream_verify=env.get("HP_UPSTREAM_VERIFY", "system"),
            vpn_enabled=_env_bool(env, "HP_VPN", True),
            vpn_binary=env.get("HP_VPN_BINARY", "wireproxy"),
        )
