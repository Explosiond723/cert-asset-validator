import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_CERTS = REPO_ROOT / "test_certs"


# make_cert builds a self-signed certificate on the fly. Tests that depend on the
# current date (expiry warnings) must use this instead of the files in test_certs/,
# which have a fixed validity window and would start failing once they expire.
def make_cert(
    cn: str = "generated.example.com",
    not_before: datetime = None,
    not_after: datetime = None,
    sans: list = None,
    ekus: list = None,
    key_type: str = "rsa",
):
    now = datetime.now(timezone.utc)
    if not_before is None:
        not_before = now - timedelta(days=1)
    if not_after is None:
        not_after = now + timedelta(days=365)

    if key_type == "ec":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    if ekus:
        builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return cert, key


def cert_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def write_cert(tmp_path):
    """Write a generated cert as PEM into tmp_path and return the path as a string."""
    def _write(cert, filename: str = "cert.pem") -> str:
        path = tmp_path / filename
        path.write_bytes(cert_pem(cert))
        return str(path)
    return _write


@pytest.fixture
def make_keystore():
    """Return a function building a JKS store (password "changeit") with one trusted cert."""
    jks = pytest.importorskip("jks")

    def _make(password: str = "changeit") -> bytes:
        cert, _ = make_cert(cn="jks.example.com", sans=[x509.DNSName("jks.example.com")])
        der = cert.public_bytes(serialization.Encoding.DER)
        entry = jks.TrustedCertEntry.new("my-ca", der)
        return jks.KeyStore.new("jks", [entry]).saves(password)
    return _make


@pytest.fixture
def full_san_cert():
    """A cert carrying one SAN of each common type plus a custom EKU OID."""
    cert, _key = make_cert(
        sans=[
            x509.DNSName("api.example.com"),
            x509.IPAddress(ipaddress.ip_address("10.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("2001:db8::1")),
            x509.RFC822Name("ops@example.com"),
            x509.UniformResourceIdentifier("spiffe://example.com/ns/prod/sa/api"),
            x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dir")])),
            x509.RegisteredID(x509.ObjectIdentifier("1.2.3.4")),
            # Microsoft UPN: DER UTF8String (tag 0x0c, length 0x10)
            x509.OtherName(x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), b"\x0c\x10user@example.com"),
            # unknown otherName with a non-text value (DER INTEGER 5)
            x509.OtherName(x509.ObjectIdentifier("1.2.3.4.5"), b"\x02\x01\x05"),
        ],
        ekus=[
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.ObjectIdentifier("1.3.6.1.4.1.99999.1"),
        ],
    )
    return cert
