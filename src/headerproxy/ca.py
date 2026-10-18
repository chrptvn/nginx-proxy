"""Local certificate authority and on-the-fly leaf certificates.

To rewrite headers of HTTPS traffic the proxy must terminate TLS (MITM).  On
first start a private CA is generated under ``<data_dir>/ca/``; per-host leaf
certificates are signed on demand and cached in an LRU (memory + disk), so
the handshake cost is paid once per host.

Clients must trust the CA — either by disabling certificate errors (e.g.
Playwright's ``ignoreHTTPSErrors``) or by installing ``<data_dir>/ca/ca.crt``
into the browser/OS trust store.
"""

from __future__ import annotations

import ipaddress
import ssl
import datetime as _dt
from collections import OrderedDict
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_CA_DAYS = 3650
_LEAF_DAYS = 825


def _name(common_name: str, org: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


class CertificateAuthority:
    """Persistent CA + LRU cache of generated leaf ``ssl.SSLContext`` objects."""

    def __init__(
        self, cert: x509.Certificate, key: ec.EllipticCurvePrivateKey, cache_dir: Path, cache_size: int
    ) -> None:
        self.cert = cert
        self.key = key
        self._cache_dir = cache_dir
        self._cache_size = cache_size
        self._cache: OrderedDict[str, ssl.SSLContext] = OrderedDict()
        cache_dir.mkdir(parents=True, exist_ok=True)

    # -- lifecycle ----------------------------------------------------------

    @classmethod
    def load_or_create(cls, data_dir: Path, cache_size: int = 2048) -> "CertificateAuthority":
        ca_dir = data_dir / "ca"
        ca_dir.mkdir(parents=True, exist_ok=True)
        cert_path = ca_dir / "ca.crt"
        key_path = ca_dir / "ca.key"

        if cert_path.exists() and key_path.exists():
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        else:
            key = ec.generate_private_key(ec.SECP256R1())
            subject = _name("HeaderProxy Root CA", "HeaderProxy")
            now = _dt.datetime.now(_dt.timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - _dt.timedelta(minutes=5))
                .not_valid_after(now + _dt.timedelta(days=_CA_DAYS))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
                )
                .sign(key, hashes.SHA256())
            )
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            key_path.chmod(0o600)
        return cls(cert, key, ca_dir / "certs", cache_size)

    @property
    def ca_pem(self) -> bytes:
        """The CA certificate in PEM form, for clients to trust."""
        return self.cert.public_bytes(serialization.Encoding.PEM)

    # -- leaf certificates --------------------------------------------------

    def leaf_context(self, host: str) -> ssl.SSLContext:
        host = (host or "unknown").lower()
        cached = self._cache.get(host)
        if cached is not None:
            self._cache.move_to_end(host)
            return cached

        pem_path = self._leaf_pem_path(host)
        if not pem_path.exists():
            self._write_leaf_pem(host, pem_path)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(pem_path))
        self._cache[host] = ctx
        while len(self._cache) > self._cache_size:
            _, evicted = self._cache.popitem(last=False)
        return ctx

    def _leaf_pem_path(self, host: str) -> Path:
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in host)
        return self._cache_dir / f"{safe}.pem"

    def _write_leaf_pem(self, host: str, path: Path) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        try:
            ip = ipaddress.ip_address(host)
            san: x509.GeneralName = x509.IPAddress(ip)
        except ValueError:
            san = x509.DNSName(host)

        now = _dt.datetime.now(_dt.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name(host, "HeaderProxy"))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=_LEAF_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([san]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
        )
        try:
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key())
            builder = builder.add_extension(aki, critical=False)
        except x509.ExtensionNotFound:  # pragma: no cover - defensive
            pass
        cert = builder.sign(self.key, hashes.SHA256())

        bundle = (
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            + cert.public_bytes(serialization.Encoding.PEM)
        )
        path.write_bytes(bundle)
        path.chmod(0o600)
