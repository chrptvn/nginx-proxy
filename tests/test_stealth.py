"""Stealth normalization."""

from headerproxy.headers import Headers
from headerproxy.stealth import apply_stealth


def test_headless_user_agent_rewritten():
    h = Headers(
        [
            (
                "User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                "HeadlessChrome/140.0.0.0 Safari/537.36",
            )
        ]
    )
    changes = apply_stealth(h)
    ua = h.get("User-Agent")
    assert "HeadlessChrome" not in ua
    assert "Chrome/140.0.0.0" in ua
    assert any("user-agent" in c for c in changes)


def test_regular_user_agent_untouched():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36"
    h = Headers([("User-Agent", ua)])
    apply_stealth(h)
    assert h.get("User-Agent") == ua


def test_proxy_leak_headers_stripped():
    h = Headers(
        [
            ("Via", "1.1squid"),
            ("Forwarded", "for=10.0.0.1"),
            ("X-Forwarded-For", "10.0.0.1"),
            ("X-Forwarded-Proto", "https"),
            ("X-Real-Ip", "10.0.0.1"),
            ("Proxy-Connection", "keep-alive"),
            ("Accept", "*/*"),
        ]
    )
    apply_stealth(h)
    names = {n.lower() for n in h.names()}
    assert names == {"accept"}


def test_client_hints_preserved():
    h = Headers(
        [
            ("User-Agent", "Mozilla/5.0 (X11; Linux) HeadlessChrome/140.0.0.0"),
            ("Sec-Ch-Ua", '"Chromium";v="140", "Not=A?Brand";v="24"'),
            ("Sec-Ch-Ua-Platform", '"Linux"'),
        ]
    )
    apply_stealth(h)
    # hints stay untouched: they already match the rewritten UA major version
    assert h.get("Sec-Ch-Ua") == '"Chromium";v="140", "Not=A?Brand";v="24"'
