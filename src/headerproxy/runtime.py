"""Process-wide runtime: config + shared singletons used by API and MCP."""

from __future__ import annotations

from dataclasses import dataclass

from .ca import CertificateAuthority
from .config import Config
from .engine import Engine
from .proxy import ProxyServer
from .relay import UpstreamClient
from .store import Store


@dataclass
class Runtime:
    """Everything the control plane and data plane share in one process."""

    cfg: Config
    store: Store
    engine: Engine
    ca: CertificateAuthority
    upstream: UpstreamClient
    proxy: ProxyServer | None = None
