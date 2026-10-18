"""End-to-end data plane tests over plain HTTP."""

import json

import pytest
from curl_cffi import requests as crequests

from wsclient import ws_over_proxy


def get(harness, url, **kwargs):
    kwargs.setdefault("timeout", 30)
    kwargs.setdefault("proxy", harness.url)
    return crequests.get(url, **kwargs)


def post(harness, url, data, **kwargs):
    kwargs.setdefault("timeout", 30)
    kwargs.setdefault("proxy", harness.url)
    return crequests.post(url, data=data, **kwargs)


def test_plain_http_passes_through(harness, origin):
    resp = get(harness, f"{origin.url}/echo")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["method"] == "GET"
    assert payload["headers"]["host"].startswith("127.0.0.1")


def test_inject_request_header(harness, origin):
    harness.add_override(direction="request", action="set", header="X-Injected", value="by-proxy")
    resp = get(harness, f"{origin.url}/echo")
    assert origin.requests[-1]["headers"]["x-injected"] == "by-proxy"
    # no override leaked to the client response
    assert "X-Injected" not in resp.headers


def test_inject_response_header(harness, origin):
    harness.add_override(direction="response", action="set", header="X-Res-Tag", value="proxy")
    resp = get(harness, f"{origin.url}/echo")
    assert resp.headers.get("X-Res-Tag") == "proxy"


def test_remove_header_falls_back_to_impersonated_ua(harness, origin):
    # curl-impersonate injects its own Chrome UA when none is forwarded, so
    # "remove" means: drop the client's UA (the impersonated one keeps the
    # traffic consistent — the stealth-friendly default).
    harness.add_override(direction="request", action="remove", header="User-Agent")
    crequests.get(
        f"{origin.url}/echo",
        proxy=harness.url,
        headers={"User-Agent": "TestAgent/9.9"},
        timeout=30,
    )
    ua = origin.requests[-1]["headers"]["user-agent"]
    assert "TestAgent" not in ua
    assert "Chrome" in ua


def test_filter_scopes_rule(harness, origin):
    f = harness.add_filter(host="*.example.com")
    harness.add_override(direction="request", action="set", header="X-Scoped", value="1", filter_id=f.id)
    # request to the test origin does not match the filter
    get(harness, f"{origin.url}/echo")
    assert "x-scoped" not in origin.requests[-1]["headers"]
    # wildcard rule applies everywhere
    harness.add_override(direction="request", action="set", header="X-Global", value="1")
    get(harness, f"{origin.url}/echo")
    assert origin.requests[-1]["headers"]["x-global"] == "1"


def test_stealth_rewrites_headless_ua(harness, origin):
    harness.store.set_session_stealth("default", True)
    harness.engine.reload()
    headless = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "HeadlessChrome/140.0.0.0 Safari/537.36"
    )
    crequests.get(
        f"{origin.url}/echo",
        proxy=harness.url,
        headers={"User-Agent": headless},
        timeout=30,
    )
    ua = origin.requests[-1]["headers"]["user-agent"]
    assert "HeadlessChrome" not in ua
    assert "Chrome/140" in ua

    # stealth off -> UA passes through untouched
    harness.store.set_session_stealth("default", False)
    harness.engine.reload()
    crequests.get(
        f"{origin.url}/echo",
        proxy=harness.url,
        headers={"User-Agent": headless},
        timeout=30,
    )
    assert origin.requests[-1]["headers"]["user-agent"] == headless
    harness.store.set_session_stealth("default", True)
    harness.engine.reload()


def test_post_body_relayed(harness, origin):
    resp = post(harness, f"{origin.url}/echo", data=b"payload=123&x=1")
    assert resp.json()["body"] == "payload=123&x=1"
    assert origin.requests[-1]["method"] == "POST"


def test_big_download_streamed(harness, origin):
    size = 4 * 1024 * 1024
    resp = get(harness, f"{origin.url}/big?size={size}")
    assert resp.status_code == 200
    assert len(resp.content) == size
    assert resp.content[:16] == b"0123456789abcdef"


def test_status_codes_passthrough(harness, origin):
    assert get(harness, f"{origin.url}/status/404").status_code == 404
    assert get(harness, f"{origin.url}/status/418").status_code == 418
    assert get(harness, f"{origin.url}/status/500").status_code == 500


def test_upstream_failure_yields_502(harness):
    resp = get(harness, "http://127.0.0.1:9/echo")  # nothing listens here
    assert resp.status_code == 502


def test_session_switch_changes_behavior(harness, origin):
    harness.create_session("clean", stealth=False)
    harness.add_override(direction="request", action="set", header="X-Profile", value="default-rules")
    get(harness, f"{origin.url}/echo")
    assert origin.requests[-1]["headers"].get("x-profile") == "default-rules"

    harness.activate("clean")
    get(harness, f"{origin.url}/echo")
    assert "x-profile" not in origin.requests[-1]["headers"]

    harness.activate("default")
    get(harness, f"{origin.url}/echo")
    assert origin.requests[-1]["headers"].get("x-profile") == "default-rules"


def test_websocket_over_plain_http_relay(harness, origin):
    echoed = ws_over_proxy(harness.port, "127.0.0.1", origin.port, "/ws", tls=False)
    assert echoed == b"hello-ws"
