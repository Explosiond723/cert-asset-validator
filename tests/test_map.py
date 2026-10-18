from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

pytest.importorskip("kubernetes")

import certmap
import live
import main
from test_cli import run_cli
from test_live import FakeClients, FakeCoreV1Api

NOW = datetime.now(timezone.utc)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(cn, days=3650):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return cert, key


def make_leaf(cn, ca, days=90):
    ca_cert, ca_key = ca
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return cert


def make_self_signed_leaf(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    return (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=90))
            .sign(key, hashes.SHA256()))


def pem(*certs) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def tls_asset(asset_id, namespace, secret, cn, cluster="prod", truststore=None):
    asset = {"id": asset_id, "cluster": cluster, "namespace": namespace, "cn": cn, "certType": "pem",
             "keystore": {"secret": {"name": secret, "key": "tls.crt"}}}
    if truststore:
        asset["truststore"] = {"secret": {"name": truststore, "key": "ca.pem"}}
    return asset


@pytest.fixture(scope="module")
def pki():
    corp_old = make_ca("Corp CA")
    corp_new = make_ca("Corp CA")          # CA renewal: same DN, new key
    partner = make_ca("Partner CA")
    public = make_ca("Public CA")          # never stored anywhere in the inventory
    www_v1 = make_leaf("www.example.com", corp_old)
    www_v2 = make_leaf("www.example.com", corp_new, days=365)
    api = make_leaf("api.example.com", corp_new)
    ext = make_leaf("shop.example.com", public)
    self_signed = make_self_signed_leaf("selfsigned.example.com")
    return locals()


@pytest.fixture(scope="module")
def report(pki):
    prod = FakeCoreV1Api({
        ("web", "web-tls"): {"tls.crt": pem(pki["www_v1"], pki["corp_old"][0])},
        ("web", "web-backup"): {"tls.crt": pem(pki["www_v1"])},            # same cert, no chain
        ("api", "api-tls"): {"tls.crt": pem(pki["api"], pki["corp_new"][0])},
        # trusts the OLD Corp CA (same DN as the issuer of api) and an unused partner CA
        ("api", "api-trust"): {"ca.pem": pem(pki["corp_old"][0], pki["partner"][0])},
        ("shop", "shop-tls"): {"tls.crt": pem(pki["ext"])},
        ("misc", "self-tls"): {"tls.crt": pem(pki["self_signed"])},
    })
    staging = FakeCoreV1Api({("web", "web-tls"): {"tls.crt": pem(pki["www_v2"], pki["corp_new"][0])}})
    assets = [
        tls_asset("web", "web", "web-tls", "www.example.com"),
        tls_asset("web-backup", "web", "web-backup", "www.example.com"),
        tls_asset("web-staging", "web", "web-tls", "www.example.com", cluster="staging"),
        tls_asset("api", "api", "api-tls", "api.example.com", truststore="api-trust"),
        tls_asset("shop", "shop", "shop-tls", "shop.example.com"),
        tls_asset("self", "misc", "self-tls", "selfsigned.example.com"),
        tls_asset("missing", "web", "nope", "x.example.com"),
    ]
    clients = FakeClients({"prod": "prod-ctx", "staging": "staging-ctx"},
                          {"prod-ctx": prod, "staging-ctx": staging})
    pairs = [(a, live.inspect_asset(a, clients, 30)) for a in assets]
    return certmap.build_map(pairs, 30)


def by(rows, key, value):
    return next(r for r in rows if r[key] == value)


# --- certificates -------------------------------------------------------------------

def test_same_certificate_in_two_secrets(report, pki):
    fp = pki["www_v1"].fingerprint(hashes.SHA256()).hex()
    row = by(report["certificates"], "fingerprint", fp)
    assert row["assets"] == ["web", "web-backup"]
    assert len(row["locations"]) == 2


def test_same_name_different_certificate_is_flagged(report, pki):
    v1 = pki["www_v1"].fingerprint(hashes.SHA256()).hex()
    v2 = pki["www_v2"].fingerprint(hashes.SHA256()).hex()
    assert by(report["certificates"], "fingerprint", v1)["other_versions"] == [v2]
    assert by(report["certificates"], "fingerprint", v2)["other_versions"] == [v1]
    assert by(report["certificates"], "fingerprint", pki["api"].fingerprint(hashes.SHA256()).hex())["other_versions"] == []


def test_ca_certificates_are_not_listed_as_certificates(report):
    assert all(r["common_name"] not in ("Corp CA", "Partner CA") for r in report["certificates"])


# --- CAs ----------------------------------------------------------------------------

def test_ca_renewal_with_same_dn_is_told_apart_by_key_id(report, pki):
    corp = [r for r in report["cas"] if r["subject"] == "CN=Corp CA"]
    assert len(corp) == 2
    old = by(corp, "fingerprint", pki["corp_old"][0].fingerprint(hashes.SHA256()).hex())
    new = by(corp, "fingerprint", pki["corp_new"][0].fingerprint(hashes.SHA256()).hex())
    assert old["signs"] == ["web", "web-backup"]
    assert new["signs"] == ["api", "web-staging"]
    assert old["trusted_by"] == ["api"] and new["trusted_by"] == []
    assert old["in_chain_of"] == ["web"]


def test_renewed_ca_is_flagged_and_self_signed_leaf_is_not_a_ca(report):
    corp = [r for r in report["cas"] if r["subject"] == "CN=Corp CA"]
    assert all(r["same_name_as_other_ca"] for r in corp)
    assert not by(report["cas"], "subject", "CN=Partner CA")["same_name_as_other_ca"]
    assert all(r["subject"] != "CN=selfsigned.example.com" for r in report["cas"])


def test_unused_ca_and_issuer_outside_inventory(report):
    partner = by(report["cas"], "subject", "CN=Partner CA")
    assert partner["signs"] == [] and partner["trusted_by"] == ["api"]
    public = by(report["cas"], "subject", "CN=Public CA")
    assert public["found_in_inventory"] is False and public["signs"] == ["shop"]


# --- assets -------------------------------------------------------------------------

def test_asset_relationships(report):
    rows = {r["id"]: r for r in report["assets"]}
    assert rows["web"]["chain_complete"] is True
    assert rows["web"]["shared_with"] == ["web-backup"]
    assert rows["web-backup"]["chain_complete"] is False       # leaf only, issuer known elsewhere
    assert rows["web-backup"]["issuer_in_inventory"] == "yes"
    # api is signed by the NEW Corp CA but its truststore holds the OLD one: same DN, not trusted
    assert rows["api"]["truststore_trusts_own_ca"] == "no"
    assert rows["api"]["unused_trusted_cas"] == ["CN=Partner CA"]
    assert rows["shop"]["issuer_in_inventory"] == "no" and rows["shop"]["chain_complete"] is False
    assert rows["self"]["issuer_in_inventory"] == "self-signed" and rows["self"]["chain_complete"] is True
    assert "not found" in rows["missing"]["errors"][0]


def test_dn_fallback_when_certificates_have_no_key_identifiers(make_keystore):
    # certificates from conftest.make_cert have no SKI/AKI: linkage falls back to the DN
    from conftest import make_cert
    ca, ca_key = make_cert(cn="Plain CA")
    leaf_meta = {"subject": "CN=leaf", "issuer": ca.subject.rfc4514_string(), "subject_key_id": None,
                 "authority_key_id": None, "fingerprint_sha256": "aa", "common_name": "leaf",
                 "serial_number": 1, "not_valid_after": "x", "expiry": "e", "days_remaining": 10,
                 "validity_status": "valid", "san": []}
    from cert_analysis import _extract_cert_metadata
    ca_meta = _extract_cert_metadata(ca)
    result = {"errors": [], "leaf": leaf_meta,
              "keystore": {"secret": "s", "key": "tls.crt", "format": "PEM", "certs": [leaf_meta, ca_meta]},
              "truststore": None}
    asset = {"id": "a", "namespace": "ns"}
    report = certmap.build_map([(asset, result)], 30)
    assert by(report["cas"], "fingerprint", ca_meta["fingerprint_sha256"])["signs"] == ["a"]
    assert report["assets"][0]["chain_complete"] is True


# --- rendering and CLI ----------------------------------------------------------------

def test_print_map_sections(report, capsys):
    certmap.print_map(report, ["certificates", "cas", "assets"])
    out = capsys.readouterr().out
    assert "== Certificates ==" in out and "== CAs ==" in out and "== Assets ==" in out
    assert "same name, different certificate(s) elsewhere" in out
    assert "CA (not in the inventory): CN=Public CA" in out
    assert "truststore trusts its own CA: no" in out
    assert "same certificate also used by: web-backup" in out
    assert "another CA has the same name with a different key" in out


@pytest.fixture
def map_cluster(monkeypatch, pki, tmp_path):
    import yaml
    prod = FakeCoreV1Api({
        ("web", "web-tls"): {"tls.crt": pem(pki["www_v1"], pki["corp_old"][0])},
        ("web", "web-backup"): {"tls.crt": pem(pki["www_v1"])},
    })
    inv = {"clusters": [{"name": "prod", "context": "prod-ctx"}],
           "assets": [tls_asset("web", "web", "web-tls", "www.example.com"),
                      tls_asset("web-backup", "web", "web-backup", "www.example.com")]}
    path = tmp_path / "inv.yaml"
    path.write_text(yaml.safe_dump(inv))
    monkeypatch.setattr(main, "make_live_clients",
                        lambda args, clusters: FakeClients({"prod": "prod-ctx"}, {"prod-ctx": prod}))
    return {"path": str(path), "prod": prod}


def test_cli_map_list(map_cluster, capsys):
    code, out = run_cli(["map", map_cluster["path"]], capsys)
    assert code == 0
    assert "found in 2 place(s):" in out
    assert "prod / web / web-backup (tls.crt)  [asset web-backup, keystore]" in out


def test_cli_map_csv_views(map_cluster, capsys):
    import csv, io
    code, out = run_cli(["map", map_cluster["path"], "--view", "certificates", "--format", "csv"], capsys)
    assert code == 0
    row = next(csv.DictReader(io.StringIO(out)))
    assert row["common_name"] == "www.example.com" and row["places"] == "2"
    assert row["assets"] == "web; web-backup"

    code, out = run_cli(["map", map_cluster["path"], "--view", "assets", "--format", "csv"], capsys)
    rows = {r["id"]: r for r in csv.DictReader(io.StringIO(out))}
    assert rows["web-backup"]["chain_complete"] == "False"


def test_cli_map_cn_filter_and_errors(map_cluster, capsys):
    code, out = run_cli(["map", map_cluster["path"], "--cn", "nothing-matches"], capsys)
    assert code == 0 and "Certificate:" not in out

    del map_cluster["prod"].secrets[("web", "web-backup")]
    code, out = run_cli(["map", map_cluster["path"], "--view", "assets"], capsys)
    assert code == 1
    assert "ERROR: keystore: Secret 'web/web-backup' not found" in out


def test_cli_map_table_needs_a_view(map_cluster):
    with pytest.raises(SystemExit) as exc:
        main.main(["map", map_cluster["path"], "--format", "table"])
    assert exc.value.code == 2


# --- chain Secret, private key, backups -------------------------------------------------

@pytest.fixture(scope="module")
def guide_report(pki):
    # The layout of the renewal guide: generic Secret tls.crt + tls.key + cacerts.pem, and the
    # <secret>-bck copy taken before the renewal (it still holds the old certificate).
    api = FakeCoreV1Api({
        ("portal", "portal-tls"): {"tls.crt": pem(pki["www_v2"]), "tls.key": b"k",
                                   "cacerts.pem": pem(pki["corp_new"][0])},
        ("portal", "portal-tls-bck"): {"tls.crt": pem(pki["www_v1"]), "tls.key": b"k",
                                       "cacerts.pem": pem(pki["corp_old"][0])},
        # chain Secret holding the wrong CA (same DN, other key)
        ("portal", "wrong-tls"): {"tls.crt": pem(pki["api"]), "cacerts.pem": pem(pki["corp_old"][0])},
    })

    def asset(asset_id, secret, cn):
        a = tls_asset(asset_id, "portal", secret, cn)
        a["chain"] = {"secret": {"name": secret, "key": "cacerts.pem"}}
        return a

    assets = [asset("portal", "portal-tls", "www.example.com"),
              asset("portal-bck", "portal-tls-bck", "www.example.com"),
              asset("wrong", "wrong-tls", "api.example.com")]
    clients = FakeClients({"prod": "prod-ctx"}, {"prod-ctx": api})
    pairs = [(a, live.inspect_asset(a, clients, 30)) for a in assets]
    return certmap.build_map(pairs, 30)


def test_chain_secret_certs_are_mapped(guide_report, pki):
    portal = by(guide_report["assets"], "id", "portal")
    assert portal["chain_complete"] is True
    assert portal["chain_source"] == "Secret portal-tls (cacerts.pem)"
    assert portal["private_key"] == "in Secret key 'tls.key'"
    ca = by(guide_report["cas"], "fingerprint", pki["corp_new"][0].fingerprint(hashes.SHA256()).hex())
    assert ca["in_chain_of"] == ["portal"] and ca["signs"] == ["portal", "wrong"]
    # verified by signature: a CA with the issuer's DN but another key does not complete the chain
    assert by(guide_report["assets"], "id", "wrong")["chain_complete"] is False


def test_backup_is_not_a_missing_renewal(guide_report, pki):
    current = by(guide_report["certificates"], "fingerprint", pki["www_v2"].fingerprint(hashes.SHA256()).hex())
    old = by(guide_report["certificates"], "fingerprint", pki["www_v1"].fingerprint(hashes.SHA256()).hex())
    assert current["other_versions"] == [] and current["backup_only"] is False
    assert old["backup_only"] is True and old["other_versions"] == [current["fingerprint"]]
    assert by(guide_report["assets"], "id", "portal-bck")["backup_of"] == "portal-tls"
    assert by(guide_report["assets"], "id", "portal")["backup_of"] is None


def test_print_map_marks_backups(guide_report, capsys):
    certmap.print_map(guide_report, ["certificates", "assets"])
    out = capsys.readouterr().out
    assert "[asset portal-bck, keystore, backup]" in out
    assert "NOTE: found only in backups; current version(s):" in out
    assert "same name, different certificate(s) elsewhere" not in out
    assert "backup of: portal-tls" in out
    assert "chain complete: yes (from Secret portal-tls (cacerts.pem))" in out
    assert "private key: in Secret key 'tls.key'" in out


def test_backup_from_note_and_custom_word(pki):
    api = FakeCoreV1Api({("p", "a-tls"): {"tls.crt": pem(pki["www_v2"])},
                         ("p", "a-tls-prev"): {"tls.crt": pem(pki["www_v1"])},
                         ("p", "copy"): {"tls.crt": pem(pki["www_v1"])}})
    noted = tls_asset("copy", "p", "copy", "www.example.com")
    noted["notes"] = {"backup": "backup copy of Secret 'a-tls'"}
    assets = [tls_asset("a", "p", "a-tls", "www.example.com"), tls_asset("prev", "p", "a-tls-prev", "www.example.com"),
              noted]
    clients = FakeClients({"prod": "prod-ctx"}, {"prod-ctx": api})
    pairs = [(a, live.inspect_asset(a, clients, 30)) for a in assets]
    assert by(certmap.build_map(pairs, 30)["assets"], "id", "copy")["backup_of"] == "a-tls"
    # "prev" is not a default backup word: the old certificate is a version missing a renewal
    assert by(certmap.build_map(pairs, 30)["assets"], "id", "prev")["backup_of"] is None
    report = certmap.build_map(pairs, 30, certmap.BACKUP_WORDS + ("prev",))
    assert by(report["assets"], "id", "prev")["backup_of"] == "a-tls"
    assert by(report["certificates"], "fingerprint", pki["www_v2"].fingerprint(hashes.SHA256()).hex())[
        "other_versions"] == []
