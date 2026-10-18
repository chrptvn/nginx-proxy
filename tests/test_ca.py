"""Certificate authority behaviour."""

import ssl

from headerproxy.ca import CertificateAuthority


def test_ca_created_and_persisted(tmp_path):
    ca1 = CertificateAuthority.load_or_create(tmp_path, cache_size=4)
    assert (tmp_path / "ca" / "ca.crt").exists()
    assert (tmp_path / "ca" / "ca.key").exists()

    ca2 = CertificateAuthority.load_or_create(tmp_path, cache_size=4)
    assert ca1.cert == ca2.cert  # same CA reloaded, not regenerated


def test_leaf_context_host_and_ip(tmp_path):
    ca = CertificateAuthority.load_or_create(tmp_path, cache_size=4)
    for host in ("example.com", "sub.example.com", "127.0.0.1"):
        ctx = ca.leaf_context(host)
        assert isinstance(ctx, ssl.SSLContext)

    # cached: same object returned, LRU bounded
    ctx_a = ca.leaf_context("example.com")
    assert ca.leaf_context("example.com") is ctx_a
    for i in range(10):
        ca.leaf_context(f"host{i}.example.com")
    assert len(ca._cache) <= 4
