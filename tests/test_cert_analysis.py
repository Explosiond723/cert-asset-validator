import sys
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

import cert_analysis
from cert_analysis import (
    _extract_cert_metadata,
    cert_format,
    cert_metadata_extract,
    csr_generate,
    eku_inspect,
    expiry_warning,
)
from conftest import TEST_CERTS, cert_pem, make_cert


def read(name: str) -> bytes:
    return (TEST_CERTS / name).read_bytes()


# --- format detection on the committed fixtures -----------------------------

@pytest.mark.parametrize("filename, password, expected", [
    ("full.pem", None, "PEM"),
    ("minimal.pem", None, "PEM"),
    ("full.der", None, "DER"),
    ("nopass.p12", None, "PKCS12"),
    ("withpass.p12", "secret", "PKCS12"),
    # without the password the 0x30 heuristic still classifies it as PKCS12
    ("withpass.p12", None, "PKCS12"),
])
def test_cert_format_detects_fixtures(filename, password, expected):
    assert cert_format(read(filename), filename, password) == expected


@pytest.mark.parametrize("filename", ["garbage.bin", "garbage.jks"])
def test_cert_format_returns_none_for_garbage(filename):
    assert cert_format(read(filename), str(TEST_CERTS / filename), "secret") is None


def test_cert_format_rejects_empty_file():
    with pytest.raises(ValueError, match="empty"):
        cert_format(read("empty.pem"), "empty.pem")


# --- metadata extraction ----------------------------------------------------

def test_metadata_full_pem_has_readable_san_and_eku():
    meta = cert_metadata_extract(read("full.pem"), "PEM")
    assert meta["subject"] == "CN=test.example.com,C=US"
    assert meta["san"] == ["DNS:test.example.com", "DNS:*.example.com"]
    assert meta["eku"] == ["serverAuth", "clientAuth"]


def test_metadata_der_matches_pem():
    pem = cert_metadata_extract(read("full.pem"), "PEM")
    der = cert_metadata_extract(read("full.der"), "DER")
    assert pem["serial_number"] == der["serial_number"]
    assert pem["san"] == der["san"]


def test_metadata_minimal_pem_has_empty_lists():
    meta = cert_metadata_extract(read("minimal.pem"), "PEM")
    assert meta["san"] == []
    assert meta["eku"] == []


def test_metadata_pkcs12_with_password_returns_leaf_and_ca():
    metas = cert_metadata_extract(read("withpass.p12"), "PKCS12", "secret")
    assert isinstance(metas, list) and len(metas) == 2
    assert metas[0]["subject"] == "CN=test.example.com,C=US"
    assert metas[1]["subject"] == "CN=Test CA,C=US"


def test_metadata_pkcs12_wrong_password_is_a_clean_error():
    with pytest.raises(ValueError, match="wrong password"):
        cert_metadata_extract(read("withpass.p12"), "PKCS12", "not-the-password")


def test_metadata_pem_chain_returns_one_entry_per_cert():
    leaf, _ = make_cert(cn="leaf.example.com")
    ca, _ = make_cert(cn="ca.example.com")
    metas = cert_metadata_extract(cert_pem(leaf) + cert_pem(ca), "PEM")
    assert len(metas) == 2
    assert "CN=leaf.example.com" in metas[0]["subject"]
    assert "CN=ca.example.com" in metas[1]["subject"]


def test_san_formatting_covers_all_common_types(full_san_cert):
    meta = _extract_cert_metadata(full_san_cert)
    assert meta["san"] == [
        "DNS:api.example.com",
        "IP:10.0.0.1",
        "IP:2001:db8::1",
        "email:ops@example.com",
        "URI:spiffe://example.com/ns/prod/sa/api",
        "DirName:CN=dir",
        "RID:1.2.3.4",
        "otherName:UPN:user@example.com",
        "otherName:1.2.3.4.5:020105",
    ]
    # no raw cryptography reprs must leak into the output
    assert not any("<" in s for s in meta["san"])


def test_eku_unknown_oid_falls_back_to_dotted_string(full_san_cert):
    meta = _extract_cert_metadata(full_san_cert)
    assert meta["eku"] == ["serverAuth", "clientAuth", "1.3.6.1.4.1.99999.1"]


# --- expiry fields (deterministic: `now` is fixed relative to the cert) -----

NOT_BEFORE = datetime(2026, 1, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2026, 7, 1, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def fixed_cert():
    cert, _ = make_cert(not_before=NOT_BEFORE, not_after=NOT_AFTER)
    return cert


@pytest.mark.parametrize("now, status, days, label", [
    (NOT_AFTER - timedelta(days=10), "valid", 10, "expires in 10 days"),
    (NOT_AFTER - timedelta(days=1), "valid", 1, "expires in 1 day"),
    (NOT_AFTER - timedelta(hours=23), "valid", 0, "expires today"),
    (NOT_AFTER, "valid", 0, "expires today"),  # notAfter itself is still inside the validity period
    # days_remaining and the label always agree; validity_status separates "today" cases
    (NOT_AFTER + timedelta(hours=1), "expired", 0, "expired today"),
    (NOT_AFTER + timedelta(days=1), "expired", -1, "expired 1 day ago"),
    (NOT_AFTER + timedelta(days=3, hours=2), "expired", -3, "expired 3 days ago"),
    (NOT_BEFORE - timedelta(days=2), "not_yet_valid", 183, "expires in 183 days"),
])
def test_expiry_fields(fixed_cert, now, status, days, label):
    meta = _extract_cert_metadata(fixed_cert, now=now)
    assert meta["validity_status"] == status
    assert meta["days_remaining"] == days
    assert meta["expiry"] == label


def test_expiry_defaults_to_current_time():
    cert, _ = make_cert(not_after=datetime.now(timezone.utc) + timedelta(days=10, hours=1))
    meta = _extract_cert_metadata(cert)
    assert meta["validity_status"] == "valid"
    assert meta["days_remaining"] == 10


@pytest.mark.parametrize("days_left, warn_days, warns", [
    (31, 30, False),
    (30, 30, True),   # threshold is inclusive
    (5, 30, True),
    (0, 0, True),
    (1, 0, False),
])
def test_expiry_warning_threshold(fixed_cert, days_left, warn_days, warns):
    meta = _extract_cert_metadata(fixed_cert, now=NOT_AFTER - timedelta(days=days_left))
    warning = expiry_warning(meta, warn_days)
    assert (warning is not None) == warns
    if warns:
        assert "threshold" in warning


def test_expiry_warning_expired_and_not_yet_valid(fixed_cert):
    expired = _extract_cert_metadata(fixed_cert, now=NOT_AFTER + timedelta(days=3))
    assert expiry_warning(expired, 30) == "certificate expired 3 days ago"

    future = _extract_cert_metadata(fixed_cert, now=NOT_BEFORE - timedelta(days=1))
    assert expiry_warning(future, 30) == f"certificate is not valid before {NOT_BEFORE.isoformat()}"


# --- mTLS heuristic -----------------------------------------------------------

def test_eku_inspect():
    assert eku_inspect({"eku": ["serverAuth", "clientAuth"]}) is True
    assert eku_inspect([{"eku": ["serverAuth"]}, {"eku": ["clientAuth"]}]) is True
    assert eku_inspect({"eku": ["serverAuth"]}) is False
    assert eku_inspect([]) is False
    assert eku_inspect(None) is False


# --- CSR generation -----------------------------------------------------------

@pytest.mark.parametrize("key_type", ["rsa", "ec"])
def test_csr_preserves_subject_and_extensions(key_type):
    cert, _ = make_cert(
        cn="csr.example.com",
        key_type=key_type,
        sans=[x509.DNSName("csr.example.com"), x509.DNSName("alt.example.com")],
        ekus=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    csr_pem, key_pem = csr_generate(cert_pem(cert), "PEM")
    csr = x509.load_pem_x509_csr(csr_pem)

    assert csr.is_signature_valid
    assert csr.subject == cert.subject
    sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sans.get_values_for_type(x509.DNSName) == ["csr.example.com", "alt.example.com"]
    assert b"PRIVATE KEY" in key_pem
    # a brand-new key pair of the same type, never the original public key
    expected = rsa.RSAPublicKey if key_type == "rsa" else ec.EllipticCurvePublicKey
    assert isinstance(csr.public_key(), expected)
    assert csr.public_key().public_numbers() != cert.public_key().public_numbers()


def test_csr_from_pkcs12_fixture():
    csr_pem, _ = csr_generate(read("withpass.p12"), "PKCS12", "secret")
    csr = x509.load_pem_x509_csr(csr_pem)
    assert csr.subject.rfc4514_string() == "CN=test.example.com,C=US"


def test_csr_rejects_unknown_format():
    with pytest.raises(ValueError, match="not supported"):
        csr_generate(b"irrelevant", "XYZ")


def test_csr_from_jks_uses_private_key_entry(make_keystore):
    data = make_keystore(leaf_cn="server.example.com")
    csr = x509.load_pem_x509_csr(csr_generate(data, "JKS", "changeit")[0])
    assert "CN=server.example.com" in csr.subject.rfc4514_string()

    with pytest.raises(ValueError, match="wrong password"):
        csr_generate(data, "JKS", "wrong")
    with pytest.raises(ValueError, match="no private key entry"):
        csr_generate(make_keystore(), "JKS", "changeit")


# --- JKS (generated with pyjks; skipped when pyjks is not installed) --------

def test_jks_trusted_cert_roundtrip(make_keystore):
    data = make_keystore()

    # format detection relies on the magic number: no password and any file name
    assert cert_format(data, "store.bin") == "JKS"
    metas = cert_metadata_extract(data, "JKS", "changeit")
    assert len(metas) == 1
    assert metas[0]["alias"] == "my-ca"
    assert metas[0]["san"] == ["DNS:jks.example.com"]

    with pytest.raises(ValueError, match="wrong password"):
        cert_metadata_extract(data, "JKS", "wrong")
    with pytest.raises(ValueError, match="require a password"):
        cert_metadata_extract(data, "JKS", None)


def test_jks_private_key_entry_chain_comes_first(make_keystore):
    metas = cert_metadata_extract(make_keystore(leaf_cn="server.example.com"), "JKS", "changeit")
    assert [(m["alias"], m["entry_type"], m["common_name"]) for m in metas] == [
        ("server", "PrivateKeyEntry", "server.example.com"),
        ("server", "PrivateKeyEntry", "jks.example.com"),
        ("my-ca", "TrustedCertEntry", "jks.example.com"),
    ]


def test_common_name_field():
    assert cert_metadata_extract(read("full.pem"), "PEM")["common_name"] == "test.example.com"


def test_corrupted_jks_mentions_corruption(make_keystore):
    data = bytearray(make_keystore())
    data[-25] ^= 0xFF  # flip a byte inside the stored certificate, before the integrity hash
    with pytest.raises(ValueError, match="corrupted"):
        cert_metadata_extract(bytes(data), "JKS", "changeit")


def test_jceks_detected_by_magic_number():
    # pyjks cannot write JCEKS stores, so only detection is covered here
    assert cert_format(cert_analysis.JCEKS_MAGIC + b"rest", "store.jceks") == "JKS"


def test_missing_pyjks_only_breaks_jks(monkeypatch):
    # sys.modules[name] = None makes `import name` raise ImportError
    monkeypatch.setitem(sys.modules, "jks", None)

    # PEM analysis and format detection do not need pyjks at all
    assert cert_metadata_extract(read("full.pem"), "PEM")["san"]
    assert cert_format(read("garbage.jks"), "store.jks", "changeit") is None
    assert cert_format(cert_analysis.JKS_MAGIC + b"rest", "store.jks") == "JKS"

    # parsing a real JKS does, and says so
    with pytest.raises(ValueError, match="pip install pyjks"):
        cert_metadata_extract(cert_analysis.JKS_MAGIC + b"rest", "JKS", "changeit")


# --- CSR: subject/SAN edits and key reuse -----------------------------------------

from cryptography.hazmat.primitives import serialization  # noqa: E402

from cert_analysis import build_csr, parse_san  # noqa: E402


def _csr(pem: bytes):
    return x509.load_pem_x509_csr(pem)


def _csr_sans(csr) -> list:
    try:
        return list(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        return []


@pytest.mark.parametrize("text, expected", [
    ("DNS:api.example.com", x509.DNSName("api.example.com")),
    ("dns: api.example.com ", x509.DNSName("api.example.com")),
    ("IP:10.0.0.5", x509.IPAddress(__import__("ipaddress").ip_address("10.0.0.5"))),
    ("email:ops@example.com", x509.RFC822Name("ops@example.com")),
    ("URI:spiffe://example.com/x", x509.UniformResourceIdentifier("spiffe://example.com/x")),
])
def test_parse_san(text, expected):
    assert parse_san(text) == expected


@pytest.mark.parametrize("text", ["api.example.com", "DNS:", "IP:not-an-ip", "RID:1.2.3"])
def test_parse_san_rejects_invalid(text):
    with pytest.raises(ValueError):
        parse_san(text)


@pytest.fixture
def renewal_cert():
    cert, key = make_cert(
        cn="old.example.com",
        sans=[x509.DNSName("old.example.com"), x509.DNSName("alias.example.com")],
        ekus=[ExtendedKeyUsageOID.SERVER_AUTH],
    )
    return cert, key


def test_build_csr_default_keeps_everything(renewal_cert):
    cert, _ = renewal_cert
    csr_pem, key_pem = build_csr(cert)
    csr = _csr(csr_pem)
    assert csr.subject == cert.subject
    assert _csr_sans(csr) == [x509.DNSName("old.example.com"), x509.DNSName("alias.example.com")]
    assert key_pem is not None


def test_build_csr_new_cn_renames_matching_san_and_keeps_rest_of_subject(renewal_cert):
    cert, _ = renewal_cert
    csr = _csr(build_csr(cert, cn="new.example.com")[0])
    assert csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "new.example.com"
    assert csr.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value == "Test Org"
    assert _csr_sans(csr) == [x509.DNSName("new.example.com"), x509.DNSName("alias.example.com")]
    # EKU is still copied
    assert csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage)


def test_build_csr_new_cn_keeps_rdn_order():
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Acme"),
        x509.NameAttribute(NameOID.COMMON_NAME, "old.example.com"),
    ])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    csr = _csr(build_csr(cert, cn="new.example.com")[0])
    assert [a.value for a in csr.subject] == ["IT", "Acme", "new.example.com"]


def test_build_csr_full_subject(renewal_cert):
    cert, _ = renewal_cert
    csr = _csr(build_csr(cert, subject="CN=api.example.com,OU=Ops,O=Acme,C=IT")[0])
    assert csr.subject.rfc4514_string() == "CN=api.example.com,OU=Ops,O=Acme,C=IT"
    assert x509.DNSName("api.example.com") in _csr_sans(csr)


def test_build_csr_add_and_remove_sans(renewal_cert):
    cert, _ = renewal_cert
    csr = _csr(build_csr(cert, add_sans=["IP:10.0.0.5", "DNS:alias.example.com"],
                         remove_sans=["DNS:alias.example.com"])[0])
    # removals happen before additions, so the same SAN can be removed and re-added
    assert [str(s.value) for s in _csr_sans(csr)] == ["old.example.com", "10.0.0.5", "alias.example.com"]


def test_build_csr_removing_all_sans_drops_the_extension(renewal_cert):
    cert, _ = renewal_cert
    csr = _csr(build_csr(cert, remove_sans=["DNS:old.example.com", "DNS:alias.example.com"])[0])
    assert _csr_sans(csr) == []


def test_build_csr_unknown_san_removal_fails(renewal_cert):
    cert, _ = renewal_cert
    with pytest.raises(ValueError, match="not in the certificate"):
        build_csr(cert, remove_sans=["DNS:nope.example.com"])


def test_build_csr_subject_and_cn_are_exclusive(renewal_cert):
    cert, _ = renewal_cert
    with pytest.raises(ValueError, match="not both"):
        build_csr(cert, subject="CN=a", cn="b")


def test_build_csr_reuses_key(renewal_cert):
    cert, key = renewal_cert
    csr_pem, key_pem = build_csr(cert, private_key=key)
    assert key_pem is None
    assert _csr(csr_pem).public_key().public_numbers() == cert.public_key().public_numbers()


def test_build_csr_rejects_foreign_key(renewal_cert):
    cert, _ = renewal_cert
    _, other_key = make_cert()
    with pytest.raises(ValueError, match="does not belong"):
        build_csr(cert, private_key=other_key)


def test_csr_reuse_key_from_pkcs12():
    from cryptography.hazmat.primitives.serialization import pkcs12
    _, cert, _ = pkcs12.load_key_and_certificates(read("withpass.p12"), b"secret")
    csr_pem, key_pem = csr_generate(read("withpass.p12"), "PKCS12", "secret", reuse_key=True)
    assert key_pem is None
    assert _csr(csr_pem).public_key().public_numbers() == cert.public_key().public_numbers()


def test_csr_reuse_key_from_jks(make_keystore):
    data = make_keystore(leaf_cn="server.example.com")
    leaf_pub = _csr(csr_generate(data, "JKS", "changeit", reuse_key=True)[0]).public_key()
    fresh_pub = _csr(csr_generate(data, "JKS", "changeit")[0]).public_key()
    assert leaf_pub.public_numbers() != fresh_pub.public_numbers()
    metas = cert_metadata_extract(data, "JKS", "changeit")
    assert metas[0]["common_name"] == "server.example.com"


def test_csr_reuse_key_from_pem_bundle_and_separate_key_file():
    cert, key = make_cert(cn="bundle.example.com")
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.BestAvailableEncryption(b"kpass"))
    bundle = cert_pem(cert) + key_pem

    csr_pem, new_key = csr_generate(bundle, "PEM", "kpass", reuse_key=True)
    assert new_key is None
    assert _csr(csr_pem).public_key().public_numbers() == cert.public_key().public_numbers()

    csr_pem, new_key = csr_generate(cert_pem(cert), "PEM", private_key_pem=key_pem, key_password="kpass")
    assert new_key is None
    with pytest.raises(ValueError, match="unable to load the private key file"):
        csr_generate(cert_pem(cert), "PEM", private_key_pem=key_pem, key_password="wrong")


def test_csr_reuse_key_without_key_in_material():
    with pytest.raises(ValueError, match="--key"):
        csr_generate(read("full.pem"), "PEM", reuse_key=True)
