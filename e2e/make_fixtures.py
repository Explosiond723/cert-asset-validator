"""Generate the certificate material used by e2e/kind.sh.

Usage: python3 e2e/make_fixtures.py OUTDIR

Everything is signed by a throw-away test CA. Files written to OUTDIR:
  ca.pem                      test CA certificate
  web.crt / web.key           www.example.com, valid 90 days       -> kubernetes.io/tls
  api-keystore.jks            api.example.com private key entry    (store password: changeit)
  api-truststore.jks          the test CA as trusted cert          (store password: trustpass)
  billing.p12                 billing.internal.example.com, expires in 10 days (password: p12pass)
  legacy.crt                  old.example.com, expired 5 days ago
  mismatch.crt                other.example.com (inventory says www2.example.com / certType der)
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

try:
    import jks
except ImportError:
    sys.exit("pyjks is required to build the JKS fixtures: pip install pyjks")

NOW = datetime.now(timezone.utc)


def name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "cert-asset-validator e2e"),
    ])


def make_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name("e2e Test CA"))
        .issuer_name(name("e2e Test CA"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def make_leaf(ca, cn: str, not_before: datetime, not_after: datetime, ekus, key_type="rsa"):
    ca_cert, ca_key = ca
    if key_type == "ec":
        key = ec.generate_private_key(ec.SECP256R1())
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    ca = make_ca()
    server = [ExtendedKeyUsageOID.SERVER_AUTH]
    mtls = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]

    (out / "ca.pem").write_bytes(pem(ca[0]))

    web, web_key = make_leaf(ca, "www.example.com", NOW - timedelta(days=1), NOW + timedelta(days=90), server, "ec")
    (out / "web.crt").write_bytes(pem(web) + pem(ca[0]))
    (out / "web.key").write_bytes(key_pem(web_key))

    api, api_key = make_leaf(ca, "api.example.com", NOW - timedelta(days=1), NOW + timedelta(days=200), mtls)
    pk_der = api_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption())
    entry = jks.PrivateKeyEntry.new("api", [der(api), der(ca[0])], pk_der)
    (out / "api-keystore.jks").write_bytes(jks.KeyStore.new("jks", [entry]).saves("changeit"))
    trusted = jks.TrustedCertEntry.new("e2e-ca", der(ca[0]))
    (out / "api-truststore.jks").write_bytes(jks.KeyStore.new("jks", [trusted]).saves("trustpass"))

    billing, billing_key = make_leaf(ca, "billing.internal.example.com", NOW - timedelta(days=355),
                                     NOW + timedelta(days=10, hours=1), server)
    (out / "billing.p12").write_bytes(pkcs12.serialize_key_and_certificates(
        b"billing", billing_key, billing, [ca[0]], serialization.BestAvailableEncryption(b"p12pass")))

    legacy, _ = make_leaf(ca, "old.example.com", NOW - timedelta(days=370), NOW - timedelta(days=5), server)
    (out / "legacy.crt").write_bytes(pem(legacy))

    mismatch, _ = make_leaf(ca, "other.example.com", NOW - timedelta(days=1), NOW + timedelta(days=90), server)
    (out / "mismatch.crt").write_bytes(pem(mismatch))

    print(f"fixtures written to {out}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(Path(sys.argv[1]))
