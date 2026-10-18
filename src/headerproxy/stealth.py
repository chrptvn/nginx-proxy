"""Stealth normalization applied to requests leaving the proxy.

The goal is to remove the cheap, network-level tells that give an automated
browser away:

* the ``HeadlessChrome`` marker in ``User-Agent`` (rewritten to ``Chrome``);
* proxy hop headers a chain might have added (``Via``, ``X-Forwarded-*``,
  ``Forwarded``, ...) which reveal that traffic was proxied.

TLS-level and HTTP/2-level fingerprinting are covered separately: upstream
requests are sent through ``curl-impersonate`` (see :mod:`headerproxy.relay`),
so origins observe a Chrome-grade TLS (JA3/JA4) and HTTP/2 handshake.

Note that JS-visible browser surfaces (``navigator.webdriver``, canvas,
WebGL...) live inside the browser and cannot be altered by a proxy — pair
HeaderProxy with a stealth-patched Playwright image for full coverage.
"""

from __future__ import annotations

import re

from .headers import Headers

# Exact-match hop/proxy headers stripped from every relayed request.
_STRIP_HEADERS = (
    "Via",
    "Forwarded",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "X-Forwarded-Port",
    "X-Real-Ip",
    "Proxy-Connection",
    "Proxy-Authorization",
)

_HEADLESS_MARKER = re.compile(r"headless\s*chrome", re.IGNORECASE)


def apply_stealth(headers: Headers) -> list[str]:
    """Normalize ``headers`` in place.  Returns human-readable change notes."""
    changes: list[str] = []

    user_agent = headers.get("User-Agent")
    if user_agent and _HEADLESS_MARKER.search(user_agent):
        rewritten = _HEADLESS_MARKER.sub("Chrome", user_agent)
        rewritten = re.sub(r"([Cc]hrome)/(\d+)", r"\1/\2", rewritten)
        headers.set("User-Agent", rewritten)
        changes.append(f"user-agent: {user_agent!r} -> {rewritten!r}")

    for name in _STRIP_HEADERS:
        if headers.remove(name):
            changes.append(f"stripped {name.lower()}")
    if headers.remove_prefix("X-Forwarded-"):
        changes.append("stripped x-forwarded-*")

    return changes
