import base64
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization

pytest.importorskip("kubernetes")
from kubernetes.client.exceptions import ApiException

import discover
import main
from conftest import cert_pem, make_cert
from test_cli import run_cli


def secret(name, data: dict, type_="Opaque", annotations=None):
    encoded = {k: base64.b64encode(v).decode() for k, v in data.items()}
    return SimpleNamespace(metadata=SimpleNamespace(name=name, annotations=annotations),
                           type=type_, data=encoded or None)


# FakeCoreV1Api for discover: namespaces maps name -> list of fake Secrets;
# forbidden namespaces answer 403 to list.
class FakeCoreV1Api:
    def __init__(self, namespaces: dict, forbidden=(), list_namespaces_forbidden=False):
        self.namespaces = namespaces
        self.forbidden = forbidden
        self.list_namespaces_forbidden = list_namespaces_forbidden

    def list_namespaced_secret(self, namespace, _request_timeout=None):
        if namespace in self.forbidden:
            raise ApiException(status=403, reason="Forbidden")
        return SimpleNamespace(items=self.namespaces.get(namespace, []))

    def list_namespace(self, _request_timeout=None):
        if self.list_namespaces_forbidden:
            raise ApiException(status=403, reason="Forbidden")
        return SimpleNamespace(items=[SimpleNamespace(metadata=SimpleNamespace(name=n)) for n in self.namespaces])


def pem_and_key(cn, **kwargs):
    cert, key = make_cert(cn=cn, sans=[x509.DNSName(cn)], **kwargs)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return cert, key, cert_pem(cert), key_pem


def p12(cn, password: bytes):
    from cryptography.hazmat.primitives.serialization import pkcs12
    cert, key = make_cert(cn=cn, sans=[x509.DNSName(cn)])
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return pkcs12.serialize_key_and_certificates(b"x", key, cert, None, enc)


@pytest.fixture
def cluster_secrets(make_keystore):
    _, _, web_crt, web_key = pem_and_key("www.example.com")
    _, _, app_crt, app_key = pem_and_key("myapp.example.com")
    _, _, ca_pem, _ = pem_and_key("Corp CA")
    _, _, private_key_only, private_key = pem_and_key("ignored.example.com")
    return {
        "web-prod": [
            secret("web-tls", {"tls.crt": web_crt, "tls.key": web_key}, "kubernetes.io/tls",
                   annotations={"cert-manager.io/certificate-name": "web"}),
            secret("myapp-tls", {"tls.crt": app_crt, "tls.key": app_key}, "kubernetes.io/tls"),
            secret("myapp-truststore", {"truststore.pem": ca_pem}),
            secret("lonely-ca", {"truststore.pem": ca_pem}),
            secret("default-token-abc", {"token": b"eyJhbGciOi..."}, "kubernetes.io/service-account-token"),
            secret("registry", {".dockerconfigjson": b"{}"}, "kubernetes.io/dockerconfigjson"),
            secret("app-config", {"config.yaml": b"a: 1", "server.key": private_key}),
        ],
        "api-prod": [
            secret("api-tls", {"keystore.jks": make_keystore(leaf_cn="api.example.com"),
                               "truststore.jks": make_keystore(password="trustpass"),
                               "truststorePassword": b"trustpass"}),
            secret("api-pass", {"keystorePassword": b"changeit\n"}),
            secret("billing-tls", {"keystore.p12": p12("billing.example.com", b"p12pass")}),
            secret("billing-tls-pass", {"password": b"p12pass"}),
            secret("orphan-p12", {"keystore.p12": p12("orphan.example.com", b"lost")}),
            secret("wrong-pass", {"keystore.jks": make_keystore(password="only-wrong-knows",
                                                                leaf_cn="wrong.example.com"),
                                  "keystorePassword": b"not-the-password"}),
        ],
        "other": [
            secret("web-tls", {"tls.crt": web_crt, "tls.key": web_key}, "kubernetes.io/tls"),
        ],
        "kube-system": [
            secret("webhook-tls", {"tls.crt": web_crt, "tls.key": web_key}, "kubernetes.io/tls"),
        ],
    }


def discover_all(cluster_secrets, namespaces=("web-prod", "api-prod", "other")):
    used, out = set(), []
    for ns in namespaces:
        out += discover.discover_namespace(ns, cluster_secrets[ns], "kind", used)
    return {asset["id"]: (asset, asset.get("notes", {})) for asset, _comments in out}


# --- discover_namespace -------------------------------------------------------------

def test_tls_secret_becomes_pem_asset(cluster_secrets):
    asset, notes = discover_all(cluster_secrets)["web-tls"]
    assert asset == {"id": "web-tls", "cluster": "kind", "namespace": "web-prod", "cn": "www.example.com",
                     "certType": "pem", "keystore": {"secret": {"name": "web-tls", "key": "tls.crt"}},
                     "notes": {"private_key": "in Secret key 'tls.key'",
                               "managed_by": "cert-manager (Certificate 'web')"}}


def test_jks_with_passwords_found_and_verified(cluster_secrets):
    asset, notes = discover_all(cluster_secrets)["api-tls"]
    assert asset["certType"] == "keystore"
    assert asset["cn"] == "api.example.com"
    # keystore password lives in the related Secret api-pass (base name "api")
    assert asset["keystore"]["passwordRef"] == {"name": "api-pass", "key": "keystorePassword"}
    # truststore password lives in the same Secret, under the key naming its role
    assert asset["truststore"]["passwordRef"] == {"name": "api-tls", "key": "truststorePassword"}
    # keystore + truststore is not proof of mTLS: the field is not written, only a hint
    assert "mtls" not in asset
    note = notes["mtls"]
    # make_keystore's leaf has no EKU extension: no restriction, so client use is possible
    assert "no EKU" in note and "truststore present" in note and "possible" in note


def test_pkcs12_password_in_related_secret(cluster_secrets):
    asset, _ = discover_all(cluster_secrets)["billing-tls"]
    assert asset["certType"] == "pkcs12"
    assert asset["keystore"]["passwordRef"] == {"name": "billing-tls-pass", "key": "password"}


def test_missing_password_is_todo_never_guessed(cluster_secrets):
    found = discover_all(cluster_secrets)
    orphan, orphan_notes = found["orphan-p12"]
    assert orphan["keystore"]["passwordRef"] == {"name": "TODO", "key": "TODO"}
    assert orphan["cn"] == "TODO"
    assert "password not found" in orphan_notes["keystore_password"]
    assert "fill it in" in orphan_notes["cn"]

    # a password-looking key that does not open the store is not written
    wrong, _ = found["wrong-pass"]
    assert wrong["keystore"]["passwordRef"] == {"name": "TODO", "key": "TODO"}


@pytest.mark.parametrize("password_secret, key", [
    ("billing-pwd", "password"),
    ("billing-password", "password"),
    ("billing.password", "password"),
    ("billing-tls-pw", "password"),
    ("billing-keystore-pass", "password"),
    ("billing-creds", "keystore-pw"),
    ("billing-ssl-passphrase", "value"),    # any key of a Secret related by name
    ("pwd-billing", "password"),            # base name as suffix
    ("app-passwords", "billing"),           # shared password Secret, key named after the app
])
def test_password_secret_naming_variants(password_secret, key):
    secrets = [secret("billing-tls", {"keystore.p12": p12("b.example.com", b"Xy9-unique")}),
               secret(password_secret, {key: b"Xy9-unique"})]
    (asset, _), = discover.discover_namespace("ns", secrets, None, set())
    assert asset["keystore"]["passwordRef"] == {"name": password_secret, "key": key}
    assert "keystore_password" not in asset.get("notes", {})


def test_password_from_unrelated_secret_is_flagged(make_keystore):
    # two apps sharing the default password: found, but the reference is suspicious
    secrets = [secret("billing-tls", {"keystore.jks": make_keystore(leaf_cn="b.example.com")}),
               secret("orders-config", {"keystorePassword": b"changeit"})]
    (asset, _), = discover.discover_namespace("ns", secrets, None, set())
    assert asset["keystore"]["passwordRef"] == {"name": "orders-config", "key": "keystorePassword"}
    assert "not related by name" in asset["notes"]["keystore_password"]


def test_related_secret_wins_over_unrelated_with_same_password(make_keystore):
    secrets = [secret("billing-tls", {"keystore.jks": make_keystore(leaf_cn="b.example.com")}),
               secret("a-unrelated", {"keystorePassword": b"changeit"}),
               secret("billing-pwd", {"value": b"changeit"})]
    (asset, _), = discover.discover_namespace("ns", secrets, None, set())
    assert asset["keystore"]["passwordRef"] == {"name": "billing-pwd", "key": "value"}
    assert "keystore_password" not in asset.get("notes", {})


def test_unrelated_name_with_base_in_the_middle_is_not_related():
    assert not discover._related_by_name("billing", "old-billing-pwd-backup-x")
    assert discover._related_by_name("billing", "billing-tls-pw")
    assert not discover._related_by_name("billing", "billing")
    assert not discover._related_by_name("billing", "billing-config")


def test_private_key_is_reported_as_a_fact(cluster_secrets):
    found = discover_all(cluster_secrets)
    assert found["web-tls"][1]["private_key"] == "in Secret key 'tls.key'"
    assert found["api-tls"][1]["private_key"] == "in the keystore"     # JKS PrivateKeyEntry
    assert found["billing-tls"][1]["private_key"] == "in the keystore"  # PKCS12 key
    # store not opened (password unknown): nothing is claimed
    assert "private_key" not in found["orphan-p12"][1]
    # a CA bundle has no key of its own
    assert "private_key" not in found["lonely-ca"][1]
    # the key never implies mTLS: web-tls has a key but no truststore and no clientAuth
    assert "mtls" not in found["web-tls"][1]


def test_private_key_not_found_and_in_the_same_file():
    _, _, crt, key = pem_and_key("a.example.com")
    found = {a["id"]: a for a, _ in discover.discover_namespace("ns", [
        secret("only-crt", {"server.crt": crt}),
        secret("bundle", {"server.pem": crt + key}),
    ], "c", set())}
    assert found["only-crt"]["notes"]["private_key"] == "not found next to the certificate"
    assert found["bundle"]["notes"]["private_key"] == "in the same file"


def test_chain_key_becomes_the_asset_chain():
    # the layout of the renewal guide: generic Secret with tls.crt, tls.key, cacerts.pem
    _, _, crt, key = pem_and_key("portal.example.com")
    _, _, ca, _ = pem_and_key("Corp CA")
    found = discover.discover_namespace("ns", [
        secret("portal-tls", {"tls.crt": crt, "tls.key": key, "cacerts.pem": ca}),
    ], "c", set())
    assert len(found) == 1  # cacerts.pem is not a second keystore asset
    asset = found[0][0]
    assert asset["keystore"] == {"secret": {"name": "portal-tls", "key": "tls.crt"}}
    assert asset["chain"] == {"secret": {"name": "portal-tls", "key": "cacerts.pem"}}
    assert list(asset)[-2:] == ["chain", "notes"]  # chain before notes in the YAML
    main.validate_config(asset, ["c"])


@pytest.mark.parametrize("key", ["ca.crt", "chain.pem", "ca-bundle.crt", "cacert.pem", "intermediate.pem"])
def test_chain_key_names(key):
    _, _, crt, _ = pem_and_key("a.example.com")
    _, _, ca, _ = pem_and_key("Corp CA")
    found = discover.discover_namespace("ns", [secret("s", {"server.crt": crt, key: ca})], "c", set())
    assert [a["chain"]["secret"]["key"] for a, _ in found] == [key]


def test_fullchain_stays_a_keystore_and_chain_key_option():
    _, _, crt, _ = pem_and_key("a.example.com")
    _, _, ca, _ = pem_and_key("Corp CA")
    s = secret("s", {"fullchain.pem": crt + ca, "issuers.pem": ca})
    found = discover.discover_namespace("ns", [s], "c", set())
    assert sorted(a["keystore"]["secret"]["key"] for a, _ in found) == ["fullchain.pem", "issuers.pem"]

    options = discover.DiscoverOptions(chain_keys=("issuers.pem",))
    found = discover.discover_namespace("ns", [s], "c", set(), options)
    assert len(found) == 1
    assert found[0][0]["chain"]["secret"]["key"] == "issuers.pem"


def test_tls_secret_ca_crt_is_the_chain():
    _, _, crt, key = pem_and_key("a.example.com")
    _, _, ca, _ = pem_and_key("Corp CA")
    found = discover.discover_namespace("ns", [
        secret("a-tls", {"tls.crt": crt, "tls.key": key, "ca.crt": ca}, "kubernetes.io/tls"),
        secret("b-tls", {"tls.crt": crt, "tls.key": key, "ca.crt": b""}, "kubernetes.io/tls"),
    ], "c", set())
    assets = {a["id"]: a for a, _ in found}
    assert assets["a-tls"]["chain"] == {"secret": {"name": "a-tls", "key": "ca.crt"}}
    assert "chain" not in assets["b-tls"]  # cert-manager writes an empty ca.crt for some issuers


def test_ca_bundle_alone_is_a_truststore_and_java_cacerts(make_keystore):
    _, _, ca, _ = pem_and_key("Corp CA")
    found = discover.discover_namespace("ns", [
        secret("corp-ca", {"ca.crt": ca}),
        secret("java", {"keystore.jks": make_keystore(leaf_cn="j.example.com"),
                        "cacerts": make_keystore(password="changeit"), "password": b"changeit"}),
    ], "c", set())
    assets = {a["id"]: a for a, _ in found}
    assert assets["corp-ca"]["notes"]["content"].startswith("truststore only")
    assert assets["java"]["truststore"]["secret"] == {"name": "java", "key": "cacerts"}
    assert "chain" not in assets["java"]


def test_backup_of():
    names = {"api-tls", "api-tls-bck", "api-tls.backup-2024", "old-tls", "api"}
    assert discover.backup_of("api-tls-bck", names) == "api-tls"
    assert discover.backup_of("api-tls.backup-2024", names) == "api-tls"
    assert discover.backup_of("api-tls-bck-20240101", names) == "api-tls"
    assert discover.backup_of("old-tls", names) is None     # nothing called "old" exists
    assert discover.backup_of("api-tls", names) is None
    assert discover.backup_of("web-tls-bck", names) is None  # original not in the namespace
    assert discover.backup_of("api-tls-prev", names) is None
    assert discover.backup_of("api-tls-prev", names, ("prev",)) == "api-tls"


def test_backups_are_left_out_unless_asked():
    _, _, crt, key = pem_and_key("portal.example.com")
    _, _, old_crt, old_key = pem_and_key("portal.example.com")
    secrets = [secret("portal-tls", {"tls.crt": crt, "tls.key": key}, "kubernetes.io/tls"),
               secret("portal-tls-bck", {"tls.crt": old_crt, "tls.key": old_key}, "kubernetes.io/tls")]
    options = discover.DiscoverOptions()
    found = discover.discover_namespace("ns", secrets, "c", set(), options)
    assert [a["id"] for a, _ in found] == ["portal-tls"]
    assert options.skipped_backups == [("ns", "portal-tls-bck", "portal-tls")]

    options = discover.DiscoverOptions(include_backups=True)
    found = {a["id"]: a for a, _ in discover.discover_namespace("ns", secrets, "c", set(), options)}
    assert found["portal-tls-bck"]["notes"]["backup"] == "backup copy of Secret 'portal-tls'"
    assert "backup" not in found["portal-tls"].get("notes", {})
    assert options.skipped_backups == []


def test_truststore_secret_attached_by_base_name(cluster_secrets):
    found = discover_all(cluster_secrets)
    asset, _ = found["myapp-tls"]
    assert asset["truststore"] == {"secret": {"name": "myapp-truststore", "key": "truststore.pem"}}
    assert "mtls" not in asset
    assert "myapp-truststore" not in found  # not duplicated as its own asset


def test_unclaimed_truststore_becomes_its_own_asset(cluster_secrets):
    asset, notes = discover_all(cluster_secrets)["lonely-ca"]
    assert asset["keystore"]["secret"] == {"name": "lonely-ca", "key": "truststore.pem"}
    assert notes["content"].startswith("truststore only")


def test_non_certificate_secrets_are_skipped(cluster_secrets):
    found = discover_all(cluster_secrets)
    for name in ("default-token-abc", "registry", "app-config"):
        assert not any(asset["keystore"]["secret"]["name"] == name for asset, _ in found.values())


def test_id_collision_across_namespaces(cluster_secrets):
    found = discover_all(cluster_secrets)
    assert found["web-tls"][0]["namespace"] == "web-prod"
    assert found["web-tls.other"][0]["namespace"] == "other"


def test_multiple_keystores_in_one_secret_get_distinct_ids(make_keystore):
    s = secret("multi", {"keystore.jks": make_keystore(leaf_cn="a.example.com"),
                         "keystore.p12": p12("b.example.com", b"changeit"),
                         "password": b"changeit"})
    ids = sorted(a["id"] for a, _ in discover.discover_namespace("ns", [s], "c", set()))
    assert ids == ["multi-keystore.jks", "multi-keystore.p12"]


def test_rendered_yaml_passes_validate_and_has_no_secret_values(cluster_secrets, tmp_path, capsys):
    used, discovered = set(), []
    for ns in ("web-prod", "api-prod", "other"):
        discovered += discover.discover_namespace(ns, cluster_secrets[ns], "kind", used)
    text = discover.render_inventory("kind", "kind-ctx", discovered, ["header line"])

    for leaked in ("changeit", "trustpass", "p12pass", "not-the-password", "BEGIN"):
        assert leaked not in text

    path = tmp_path / "inv.yaml"
    path.write_text(text)
    parsed = yaml.safe_load(text)
    assert parsed["clusters"] == [{"name": "kind", "context": "kind-ctx"}]
    code, out = run_cli(["validate", str(path)], capsys)
    assert code == 0, out


def test_discovered_notes_reach_the_csv(cluster_secrets, tmp_path, capsys):
    import csv, io
    used, discovered = set(), []
    for ns in ("web-prod", "api-prod"):
        discovered += discover.discover_namespace(ns, cluster_secrets[ns], "kind", used)
    path = tmp_path / "inv.yaml"
    path.write_text(discover.render_inventory("kind", "kind-ctx", discovered, ["h"]))
    code, out = run_cli(["validate", str(path), "--format", "csv"], capsys)
    assert code == 0, out
    rows = {r["id"]: r for r in csv.DictReader(io.StringIO(out))}
    assert rows["web-tls"]["notes_managed_by"] == "cert-manager (Certificate 'web')"
    assert "password not found" in rows["orphan-p12"]["notes_keystore_password"]
    assert rows["api-tls"]["notes_mtls"].startswith("not set")


# --- CLI ------------------------------------------------------------------------------

@pytest.fixture
def fake_discover(monkeypatch, cluster_secrets):
    state = {"api": FakeCoreV1Api(cluster_secrets), "context": "kind-test"}
    monkeypatch.setattr(main, "make_discover_api", lambda args: (state["api"], state["context"]))
    return state


def run_discover(argv, capsys):
    try:
        main.main(["discover", *argv])
        code = 0
    except SystemExit as e:
        code = e.code
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_discover_to_stdout(fake_discover, capsys):
    code, out, err = run_discover(["-n", "web-prod", "-n", "api-prod"], capsys)
    assert code == 0
    inv = yaml.safe_load(out)
    assert inv["clusters"] == [{"name": "kind-test", "context": "kind-test"}]
    assert {a["id"] for a in inv["assets"]} >= {"web-tls", "api-tls", "billing-tls", "myapp-tls"}
    assert "keystore_password: 'password not found automatically" in out
    assert err.startswith("discovered ") and "with TODO values" in err


def test_cli_backups_and_chain_options(fake_discover, tmp_path, capsys):
    _, _, crt, key = pem_and_key("portal.example.com")
    _, _, ca, _ = pem_and_key("Corp CA")
    fake_discover["api"].namespaces["portal"] = [
        secret("portal-tls", {"tls.crt": crt, "tls.key": key, "issuers.pem": ca}),
        secret("portal-tls-bck", {"tls.crt": crt, "tls.key": key, "issuers.pem": ca}),
        secret("portal-tls-prev", {"tls.crt": crt, "tls.key": key, "issuers.pem": ca}),
    ]
    code, out, err = run_discover(["-n", "portal"], capsys)
    assert code == 0
    ids = [a["id"] for a in yaml.safe_load(out)["assets"]]
    assert "portal-tls-bck" not in ids and "portal-tls-prev-tls.crt" in ids
    assert "1 backup Secret(s) left out (portal-tls-bck; see --include-backups)" in err

    code, out, err = run_discover(["-n", "portal", "--backup-suffix", "prev", "--chain-key", "issuers.pem",
                                   "--include-backups"], capsys)
    assert code == 0
    assets = {a["id"]: a for a in yaml.safe_load(out)["assets"]}
    assert set(assets) == {"portal-tls", "portal-tls-bck", "portal-tls-prev"}
    assert assets["portal-tls-prev"]["notes"]["backup"] == "backup copy of Secret 'portal-tls'"
    assert assets["portal-tls"]["chain"]["secret"]["key"] == "issuers.pem"
    assert "left out" not in err

    # --update: a backup that is left out is not "gone" from the cluster
    path = tmp_path / "inv.yaml"
    path.write_text(out)
    code, _, err = run_discover(["-n", "portal", "--update", str(path)], capsys)
    assert code == 0, err
    assert "not found in the cluster any more" not in err


def test_cli_all_namespaces_skips_system_unless_asked(fake_discover, capsys):
    code, out, _ = run_discover(["-A"], capsys)
    assert code == 0
    namespaces = {a["namespace"] for a in yaml.safe_load(out)["assets"]}
    assert "kube-system" not in namespaces and "other" in namespaces

    code, out, _ = run_discover(["-A", "--include-system"], capsys)
    assert "kube-system" in {a["namespace"] for a in yaml.safe_load(out)["assets"]}


def test_cli_output_file_and_force(fake_discover, tmp_path, capsys):
    path = tmp_path / "inv.yaml"
    code, out, err = run_discover(["-n", "web-prod", "--output", str(path), "--cluster-name", "prod"], capsys)
    assert code == 0 and out == ""
    assert yaml.safe_load(path.read_text())["assets"][0]["cluster"] == "prod"

    code, out, _ = run_discover(["-n", "web-prod", "--output", str(path)], capsys)
    assert code == 1 and "already exists" in out
    code, _, _ = run_discover(["-n", "web-prod", "--output", str(path), "--force"], capsys)
    assert code == 0


def test_cli_forbidden_namespace_is_skipped_with_exit_1(fake_discover, capsys):
    fake_discover["api"].forbidden = ("api-prod",)
    code, out, err = run_discover(["-n", "web-prod", "-n", "api-prod"], capsys)
    assert code == 1
    assert "warning: permission denied listing secrets in namespace 'api-prod'" in err
    assert "1 namespace(s) skipped" in err
    assert {a["namespace"] for a in yaml.safe_load(out)["assets"]} == {"web-prod"}


def test_cli_list_namespaces_forbidden(fake_discover, capsys):
    fake_discover["api"].list_namespaces_forbidden = True
    code, out, _ = run_discover(["-A"], capsys)
    assert code == 1
    assert out.startswith("error: permission denied listing namespaces")


def test_cli_without_context_writes_legacy_format(fake_discover, tmp_path, capsys):
    fake_discover["context"] = None
    code, out, _ = run_discover(["-n", "web-prod"], capsys)
    assert code == 0
    inv = yaml.safe_load(out)
    assert "clusters" not in inv
    assert all("cluster" not in a for a in inv["assets"])
    path = tmp_path / "legacy.yaml"
    path.write_text(out)
    assert run_cli(["validate", str(path)], capsys)[0] == 0


@pytest.mark.parametrize("argv", [
    [],                                   # neither -n nor -A
    ["-n", "x", "-A"],
    ["-n", "x", "--include-system"],
])
def test_cli_discover_usage_errors(argv):
    with pytest.raises(SystemExit) as exc:
        main.main(["discover", *argv])
    assert exc.value.code == 2


def test_cli_repeated_namespace_is_scanned_once(fake_discover, capsys):
    code, out, _ = run_discover(["-n", "other", "-n", "other"], capsys)
    assert [a["id"] for a in yaml.safe_load(out)["assets"]] == ["web-tls"]


def test_jks_without_pyjks_says_so(monkeypatch, make_keystore):
    import sys
    data = make_keystore(leaf_cn="api.example.com")
    monkeypatch.setitem(sys.modules, "jks", None)
    s = secret("api-tls", {"keystore.jks": data, "keystorePassword": b"changeit"})
    (asset, _), = discover.discover_namespace("ns", [s], None, set())
    assert asset["keystore"]["passwordRef"] == {"name": "TODO", "key": "TODO"}
    assert "pyjks is not installed" in asset["notes"]["keystore_password"]


@pytest.mark.parametrize("eku, has_truststore, expected", [
    ([], False, None),
    ([], True, "possible"),                       # no EKU extension = any usage
    (["serverAuth"], False, None),
    (["serverAuth"], True, "EKU without clientAuth (serverAuth); truststore present): unlikely as client"),
    (["serverAuth", "clientAuth"], False, "possible"),
    (["serverAuth", "clientAuth"], True, "possible"),
])
def test_mtls_note(eku, has_truststore, expected):
    note = discover._mtls_note({"eku": eku}, has_truststore)
    if expected is None:
        assert note is None
    else:
        assert note.startswith("not set") and expected in note


def test_system_namespace_filter():
    assert main.is_system_namespace("default")
    assert main.is_system_namespace("kube-system")
    assert main.is_system_namespace("openshift-ingress")
    assert not main.is_system_namespace("defaultapp")
    assert not main.is_system_namespace("web-prod")


# --- discover --update ------------------------------------------------------------------

HAND_EDITED = """\
# Inventory of the payments team. Edited by hand: keep this comment!
clusters:
  - name: prod
    context: kind-test   # same context as the fake cluster

assets:
  # web certificate, renewed every 90 days by cert-manager
  - id: www-frontend          # renamed by hand (discover called it web-tls)
    cluster: prod
    namespace: web-prod
    cn: www.example.com
    certType: pem
    keystore: {secret: {name: web-tls, key: tls.crt}}
    notes:
      owner: team-web
  - id: gone-app
    cluster: prod
    namespace: web-prod
    cn: gone.example.com
    certType: pem
    keystore: {secret: {name: removed-tls, key: tls.crt}}
"""


def write_inventory(tmp_path, text=HAND_EDITED):
    path = tmp_path / "inventory.yaml"
    path.write_text(text)
    return path


def test_update_appends_only_new_assets_and_keeps_the_file(fake_discover, tmp_path, capsys):
    path = write_inventory(tmp_path)
    code, out, err = run_discover(["-n", "web-prod", "--update", str(path)], capsys)
    assert code == 0, err
    assert out == ""
    text = path.read_text()

    # everything that was there is still there, byte for byte, comments included
    assert text.startswith(HAND_EDITED)
    inv = yaml.safe_load(text)
    ids = [a["id"] for a in inv["assets"]]
    assert ids[:2] == ["www-frontend", "gone-app"]
    # web-tls is recognised by its Secret reference although its id was renamed
    assert "web-tls" not in ids
    assert {"myapp-tls", "lonely-ca"} <= set(ids)
    assert all(a["cluster"] == "prod" for a in inv["assets"])
    assert "added by `main.py discover --update`" in text

    assert "new asset(s) appended" in err and "1 already in the inventory" in err
    assert "not found in the cluster any more (kept in the file): gone-app" in err
    assert run_cli(["validate", str(path)], capsys)[0] == 0


def test_update_twice_is_a_no_op(fake_discover, tmp_path, capsys):
    path = write_inventory(tmp_path)
    run_discover(["-n", "web-prod", "--update", str(path)], capsys)
    after_first = path.read_text()
    code, _, err = run_discover(["-n", "web-prod", "--update", str(path)], capsys)
    assert code == 0
    assert path.read_text() == after_first
    assert "no new assets" in err and "unchanged" in err


def test_update_new_ids_do_not_collide_with_existing(fake_discover, tmp_path, capsys):
    path = write_inventory(tmp_path, HAND_EDITED.replace("id: gone-app", "id: myapp-tls"))
    run_discover(["-n", "web-prod", "--update", str(path)], capsys)
    ids = [a["id"] for a in yaml.safe_load(path.read_text())["assets"]]
    assert len(ids) == len(set(ids))
    assert "myapp-tls.web-prod" in ids


def test_update_cluster_must_exist_in_the_file(fake_discover, tmp_path, capsys):
    path = write_inventory(tmp_path)
    fake_discover["context"] = "other-context"
    code, out, _ = run_discover(["-n", "web-prod", "--update", str(path)], capsys)
    assert code == 1
    assert "no cluster in" in out and "other-context" in out
    assert path.read_text() == HAND_EDITED

    code, out, _ = run_discover(["-n", "web-prod", "--update", str(path), "--cluster-name", "nope"], capsys)
    assert code == 1 and "cluster 'nope' is not defined" in out

    code, _, _ = run_discover(["-n", "web-prod", "--update", str(path), "--cluster-name", "prod"], capsys)
    assert code == 0


@pytest.mark.parametrize("text", [
    # legacy flat list, items at column 0
    "- id: old\n  namespace: web-prod\n  cn: old.example.com\n  certType: pem\n"
    "  keystore: {secret: {name: removed-tls, key: tls.crt}}\n",
    # empty flow list
    "# empty for now\nassets: []\n",
    # block list with items at column 0 under assets:
    "assets:\n- id: old\n  namespace: web-prod\n  cn: old.example.com\n  certType: pem\n"
    "  keystore: {secret: {name: removed-tls, key: tls.crt}}\n",
])
def test_update_layouts(fake_discover, tmp_path, capsys, text):
    path = write_inventory(tmp_path, text)
    code, _, err = run_discover(["-n", "web-prod", "--update", str(path)], capsys)
    assert code == 0, err
    new_text = path.read_text()
    assert new_text.startswith(text.rstrip("\n").replace("assets: []", "assets:"))
    assert run_cli(["validate", str(path)], capsys)[0] == 0
    # no clusters section in these files: appended assets carry no cluster field
    inv = main.normalize_config(yaml.safe_load(new_text))
    assert all("cluster" not in a for a in inv["assets"])


def test_update_refuses_when_assets_is_not_the_last_section(fake_discover, tmp_path, capsys):
    text = ("assets:\n  - id: old\n    namespace: web-prod\n    cn: old.example.com\n    certType: pem\n"
            "    keystore: {secret: {name: removed-tls, key: tls.crt}}\n"
            "clusters: []\n")
    path = write_inventory(tmp_path, text)
    code, out, _ = run_discover(["-n", "web-prod", "--update", str(path)], capsys)
    assert code == 1
    assert "cannot append safely" in out
    assert path.read_text() == text
    assert not (tmp_path / "inventory.yaml.tmp").exists()


def test_update_refuses_an_invalid_inventory_before_scanning(fake_discover, tmp_path, capsys):
    path = write_inventory(tmp_path, "assets:\n  - id: broken\n")
    fake_discover["api"] = None  # scanning would crash: proves the file is checked first
    code, out, _ = run_discover(["-n", "web-prod", "--update", str(path)], capsys)
    assert code == 1
    assert "is not valid, fix it before --update" in out


def test_update_and_output_are_exclusive(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main.main(["discover", "-n", "x", "--update", "a.yaml", "--output", "b.yaml"])
    assert exc.value.code == 2
