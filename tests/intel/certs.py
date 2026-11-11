"""Synthetic X.509 certificate factory for infra tests (inert, throwaway keys)."""

from __future__ import annotations

import datetime as dt
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _name(cn: str, org: str | None = None) -> x509.Name:
    attrs = []
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
    return x509.Name(attrs)


def make_cert(
    cn: str = "example.test",
    sans: list[str] | None = None,
    *,
    issuer_cn: str | None = None,
    issuer_org: str | None = None,
    age_days: int = 1,
    valid_days: int = 90,
    now: dt.datetime | None = None,
) -> tuple[bytes, bytes]:
    """Return ``(der, private_key_pem)``. ``issuer_cn=None`` -> self-signed."""
    now = now or dt.datetime.now(dt.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = _name(cn)
    issuer = _name(issuer_cn, issuer_org) if issuer_cn else subject
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=age_days))
        .not_valid_after(now - dt.timedelta(days=age_days) + dt.timedelta(days=valid_days))
    )
    if sans:
        general: list[x509.GeneralName] = []
        for s in sans:
            try:
                general.append(x509.IPAddress(ipaddress.ip_address(s)))
            except ValueError:
                general.append(x509.DNSName(s))
        builder = builder.add_extension(x509.SubjectAlternativeName(general), critical=False)
    # An "issuer" cert is simulated by signing with the same throwaway key; only the
    # issuer *name* matters to the code under test.
    cert = builder.sign(key, hashes.SHA256())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert.public_bytes(serialization.Encoding.DER), pem


def der_to_pem(der: bytes) -> bytes:
    return x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)
