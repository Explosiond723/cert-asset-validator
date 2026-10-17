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
    return {asset["id"]: (asset, notes) for asset, notes in out}


# --- discover_namespace -------------------------------------------------------------

def test_tls_secret_becomes_pem_asset(cluster_secrets):
    asset, notes = discover_all(cluster_secrets)["web-tls"]
    assert asset == {"id": "web-tls", "cluster": "kind", "namespace": "web-prod", "cn": "www.example.com",
                     "certType": "pem", "keystore": {"secret": {"name": "web-tls", "key": "tls.crt"}}}
    assert any("cert-manager" in n and "'web'" in n for n in notes)


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
    note = next(n for n in notes if n.startswith("mtls:"))
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
    assert any("password not found" in n for n in orphan_notes)

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
    (asset, notes), = discover.discover_namespace("ns", secrets, None, set())
    assert asset["keystore"]["passwordRef"] == {"name": password_secret, "key": key}
    assert not any("not related" in n for n in notes)


def test_password_from_unrelated_secret_is_flagged(make_keystore):
    # two apps sharing the default password: found, but the reference is suspicious
    secrets = [secret("billing-tls", {"keystore.jks": make_keystore(leaf_cn="b.example.com")}),
               secret("orders-config", {"keystorePassword": b"changeit"})]
    (asset, notes), = discover.discover_namespace("ns", secrets, None, set())
    assert asset["keystore"]["passwordRef"] == {"name": "orders-config", "key": "keystorePassword"}
    assert any("not related by name" in n for n in notes)


def test_related_secret_wins_over_unrelated_with_same_password(make_keystore):
    secrets = [secret("billing-tls", {"keystore.jks": make_keystore(leaf_cn="b.example.com")}),
               secret("a-unrelated", {"keystorePassword": b"changeit"}),
               secret("billing-pwd", {"value": b"changeit"})]
    (asset, notes), = discover.discover_namespace("ns", secrets, None, set())
    assert asset["keystore"]["passwordRef"] == {"name": "billing-pwd", "key": "value"}
    assert not any("not related" in n for n in notes)


def test_unrelated_name_with_base_in_the_middle_is_not_related():
    assert not discover._related_by_name("billing", "old-billing-pwd-backup-x")
    assert discover._related_by_name("billing", "billing-tls-pw")
    assert not discover._related_by_name("billing", "billing")
    assert not discover._related_by_name("billing", "billing-config")


def test_truststore_secret_attached_by_base_name(cluster_secrets):
    found = discover_all(cluster_secrets)
    asset, _ = found["myapp-tls"]
    assert asset["truststore"] == {"secret": {"name": "myapp-truststore", "key": "truststore.pem"}}
    assert "mtls" not in asset
    assert "myapp-truststore" not in found  # not duplicated as its own asset


def test_unclaimed_truststore_becomes_its_own_asset(cluster_secrets):
    asset, notes = discover_all(cluster_secrets)["lonely-ca"]
    assert asset["keystore"]["secret"] == {"name": "lonely-ca", "key": "truststore.pem"}
    assert notes[0].startswith("truststore only")


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
    assert "# keystore: password not found automatically" in out
    assert err.startswith("discovered ") and "with TODO values" in err


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
    (asset, notes), = discover.discover_namespace("ns", [s], None, set())
    assert asset["keystore"]["passwordRef"] == {"name": "TODO", "key": "TODO"}
    assert any("pyjks is not installed" in n for n in notes)


@pytest.mark.parametrize("eku, has_truststore, expected", [
    ([], False, None),
    ([], True, "possible"),                       # no EKU extension = any usage
    (["serverAuth"], False, None),
    (["serverAuth"], True, "unlikely as client (EKU without clientAuth)"),
    (["serverAuth", "clientAuth"], False, "possible"),
    (["serverAuth", "clientAuth"], True, "possible"),
])
def test_mtls_note(eku, has_truststore, expected):
    note = discover._mtls_note({"eku": eku}, has_truststore)
    if expected is None:
        assert note is None
    else:
        assert note.startswith("mtls: not set") and expected in note


def test_system_namespace_filter():
    assert main.is_system_namespace("default")
    assert main.is_system_namespace("kube-system")
    assert main.is_system_namespace("openshift-ingress")
    assert not main.is_system_namespace("defaultapp")
    assert not main.is_system_namespace("web-prod")
