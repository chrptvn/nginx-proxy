"""End-to-end data plane tests over HTTPS (CONNECT + TLS MITM)."""

import ssl

import pytest
from curl_cffi import requests as crequests

from wsclient import ws_over_proxy


@pytest.fixture
def mitm(harness, tls_origin):
    """Harness whose upstream trusts the self-signed test origin."""
    harness.trust_ca(tls_origin.stop_pem)
    return harness


def https_get(harness, ca, url, **kwargs):
    kwargs.setdefault("timeout", 30)
    kwargs.setdefault("proxy", harness.url)
    kwargs.setdefault("verify", str(ca))
    return crequests.get(url, **kwargs)


def test_https_mitm_injects_headers(mitm, tls_origin, ca_pem):
    mitm.add_override(direction="request", action="set", header="X-Https", value="mitm")
    mitm.add_override(direction="response", action="set", header="X-Https-Res", value="ok")
    resp = https_get(mitm, ca_pem, f"{tls_origin.url}/echo")
    assert resp.status_code == 200
    origin_header = resp.json()["headers"].get("x-https")
    assert origin_header == "mitm"
    assert resp.headers.get("X-Https-Res") == "ok"


def test_https_post_body(mitm, tls_origin, ca_pem):
    resp = crequests.post(
        f"{tls_origin.url}/echo",
        data=b"secret=data",
        proxy=mitm.url,
        verify=str(ca_pem),
        timeout=30,
    )
    assert resp.json()["body"] == "secret=data"


def test_https_rejects_unknown_ca(harness, tls_origin):
    ctx = ssl.create_default_context()
    with pytest.raises(Exception):
        crequests.get(
            f"{tls_origin.url}/echo",
            proxy=harness.url,
            verify=ctx,  # does not trust the proxy CA
            timeout=30,
        )


def test_https_big_download(mitm, tls_origin, ca_pem):
    resp = https_get(mitm, ca_pem, f"{tls_origin.url}/big?size=2097152")
    assert len(resp.content) == 2097152


def test_websocket_over_wss_relay(mitm, tls_origin, ca_pem):
    echoed = ws_over_proxy(
        mitm.port,
        "127.0.0.1",
        tls_origin.port,
        "/ws",
        tls=True,
        ca_pem=str(ca_pem),
    )
    assert echoed == b"hello-ws"
