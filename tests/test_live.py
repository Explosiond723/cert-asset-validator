import base64
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509

pytest.importorskip("kubernetes")
from kubernetes.client.exceptions import ApiException

import cluster
import live
import main
from conftest import REPO_ROOT, cert_pem, make_cert
from test_cli import run_cli

EXAMPLE_CFG = str(REPO_ROOT / "example-cfg.yaml")


# FakeCoreV1Api stands in for kubernetes.client.CoreV1Api: secrets maps
# (namespace, name) -> {key: raw bytes}; forbidden lists namespaces that answer 403.
class FakeCoreV1Api:
    def __init__(self, secrets: dict, forbidden: tuple = ()):
        self.secrets = secrets
        self.forbidden = forbidden

    def read_namespaced_secret(self, name, namespace, _request_timeout=None):
        if namespace in self.forbidden:
            raise ApiException(status=403, reason="Forbidden")
        if (namespace, name) not in self.secrets:
            raise ApiException(status=404, reason="Not Found")
        data = {k: base64.b64encode(v).decode() for k, v in self.secrets[(namespace, name)].items()}
        return SimpleNamespace(data=data or None)


# FakeClients replaces live.ClusterClients: one fake API per kubeconfig context,
# or a ClusterError for contexts listed as unreachable.
class FakeClients(live.ClusterClients):
    def __init__(self, cluster_contexts, apis: dict, unreachable: tuple = ()):
        super().__init__(cluster_contexts)
        self.apis = apis
        self.unreachable = unreachable

    def api_for(self, asset):
        context = self.context_for(asset)
        if context in self.unreachable:
            raise cluster.ClusterError(f"failed to load context '{context}': connection refused")
        return self.apis[context]


CONTEXTS = {"prod-ocp": "prod-ctx", "staging-gke": "staging-ctx"}


def pem_asset(**overrides):
    asset = {"id": "web", "cluster": "prod-ocp", "namespace": "web-prod", "cn": "www.example.com",
             "certType": "pem", "keystore": {"secret": {"name": "web-tls", "key": "tls.crt"}}}
    asset.update(overrides)
    return asset


def jks_asset(**overrides):
    asset = {"id": "api", "cluster": "prod-ocp", "namespace": "api-prod", "cn": "api.example.com",
             "certType": "keystore", "mtls": True,
             "keystore": {"secret": {"name": "api-tls", "key": "keystore.jks"},
                          "passwordRef": {"name": "api-pass", "key": "keystorePassword"}},
             "truststore": {"secret": {"name": "api-tls", "key": "truststore.jks"},
                            "passwordRef": {"name": "api-tls", "key": "truststorePassword"}}}
    asset.update(overrides)
    return asset


def www_pem(**kwargs):
    cert, _ = make_cert(cn="www.example.com", sans=[x509.DNSName("www.example.com")], **kwargs)
    return cert_pem(cert)


# --- inspect_asset --------------------------------------------------------------

def test_pem_asset_ok():
    api = FakeCoreV1Api({("web-prod", "web-tls"): {"tls.crt": www_pem()}})
    result = live.inspect_asset(pem_asset(), FakeClients(CONTEXTS, {"prod-ctx": api}), 30)
    assert result["errors"] == [] and result["warnings"] == []
    assert result["context"] == "prod-ctx"
    assert result["keystore"]["format"] == "PEM"
    assert result["leaf"]["common_name"] == "www.example.com"


def test_jks_asset_with_password_from_secret(make_keystore):
    keystore = make_keystore(leaf_cn="api.example.com")
    truststore = make_keystore(password="trustpass")
    api = FakeCoreV1Api({
        ("api-prod", "api-tls"): {"keystore.jks": keystore, "truststore.jks": truststore,
                                  # trailing newline as left by `echo trustpass | oc create secret`
                                  "truststorePassword": b"trustpass\n"},
        ("api-prod", "api-pass"): {"keystorePassword": b"changeit"},
    })
    result = live.inspect_asset(jks_asset(), FakeClients(CONTEXTS, {"prod-ctx": api}), 30)
    assert result["errors"] == []
    assert result["warnings"] == []
    assert result["keystore"]["format"] == "JKS"
    assert result["leaf"]["common_name"] == "api.example.com"
    assert result["truststore"]["certs"][0]["entry_type"] == "TrustedCertEntry"


def test_wrong_password_in_secret_is_reported(make_keystore):
    api = FakeCoreV1Api({
        ("api-prod", "api-tls"): {"keystore.jks": make_keystore(leaf_cn="api.example.com")},
        ("api-prod", "api-pass"): {"keystorePassword": b"not-it"},
    })
    asset = jks_asset()
    del asset["truststore"]
    result = live.inspect_asset(asset, FakeClients(CONTEXTS, {"prod-ctx": api}), 30)
    assert any("keystore: wrong password" in e for e in result["errors"])


def test_cross_checks_produce_warnings():
    now = datetime.now(timezone.utc)
    api = FakeCoreV1Api({("web-prod", "web-tls"): {"tls.crt": www_pem(not_after=now + timedelta(days=5, hours=1))}})
    asset = pem_asset(cn="other.example.com", certType="pkcs12", mtls=True)
    result = live.inspect_asset(asset, FakeClients(CONTEXTS, {"prod-ctx": api}), 30)
    warnings = "\n".join(result["warnings"])
    assert "expires in 5 days" in warnings
    assert "certType 'pkcs12' declared, but the Secret contains PEM" in warnings
    assert "YAML cn 'other.example.com' does not match" in warnings
    assert "mtls: true but no truststore" in warnings


def test_cn_matches_dns_san_case_insensitively():
    leaf = {"common_name": "something-else", "san": ["DNS:WWW.example.com"]}
    assert live._cn_matches("www.example.com", leaf)


@pytest.mark.parametrize("secrets, forbidden, expected", [
    ({}, (), "Secret 'web-prod/web-tls' not found"),
    ({("web-prod", "web-tls"): {"other": b"x"}}, (), "does not contain key 'tls.crt'"),
    ({("web-prod", "web-tls"): {}}, (), "does not contain key 'tls.crt'"),  # Secret with no data
    ({}, ("web-prod",), "permission denied reading Secret 'web-prod/web-tls'"),
    ({("web-prod", "web-tls"): {"tls.crt": b"garbage"}}, (), "unable to detect certificate format"),
])
def test_cluster_errors_are_collected_not_raised(secrets, forbidden, expected):
    api = FakeCoreV1Api(secrets, forbidden)
    result = live.inspect_asset(pem_asset(), FakeClients(CONTEXTS, {"prod-ctx": api}), 30)
    assert len(result["errors"]) == 1
    assert expected in result["errors"][0]


def test_password_never_appears_in_output(make_keystore, capsys):
    api = FakeCoreV1Api({
        ("api-prod", "api-tls"): {"keystore.jks": make_keystore(leaf_cn="api.example.com")},
        ("api-prod", "api-pass"): {"keystorePassword": b"S3cr3t-Value"},
    })
    asset = jks_asset()
    del asset["truststore"]
    result = live.inspect_asset(asset, FakeClients(CONTEXTS, {"prod-ctx": api}), 30)
    live.print_inspection(result)
    assert "S3cr3t-Value" not in capsys.readouterr().out
    assert "S3cr3t-Value" not in repr(result)


def test_context_resolution():
    clients = live.ClusterClients(CONTEXTS)
    assert clients.context_for({"cluster": "staging-gke"}) == "staging-ctx"
    assert clients.context_for({}) is None  # legacy config: in-cluster / current context
    override = live.ClusterClients(CONTEXTS, context_override="kind-test")
    assert override.context_for({"cluster": "staging-gke"}) == "kind-test"


def test_connection_failure_is_cached_per_context(monkeypatch):
    calls = []

    def fake_connect(config_file=None, context=None):
        calls.append(context)
        raise cluster.ClusterError(f"failed to load context '{context}'")

    monkeypatch.setattr(cluster, "connect", fake_connect)
    clients = live.ClusterClients(CONTEXTS)
    for _ in range(3):
        result = live.inspect_asset(pem_asset(), clients, 30)
        assert "failed to load context 'prod-ctx'" in result["errors"][0]
    assert calls == ["prod-ctx"]


# --- cluster.get_secret_key -----------------------------------------------------

def test_get_secret_key_decodes_base64():
    api = FakeCoreV1Api({("ns", "s"): {"k": b"\x00raw-bytes"}})
    assert cluster.get_secret_key("ns", "s", "k", api) == b"\x00raw-bytes"


def test_connect_with_missing_kubeconfig_raises_cluster_error(tmp_path):
    with pytest.raises(cluster.ClusterError, match="failed to load"):
        cluster.connect(config_file=str(tmp_path / "missing"), context="x")


# --- CLI --------------------------------------------------------------------------

@pytest.fixture
def fake_cluster(monkeypatch):
    """Route `--live` in main.py to fake clusters built from example-cfg.yaml."""
    now = datetime.now(timezone.utc)
    prod = FakeCoreV1Api({("web-prod", "web-tls"): {"tls.crt": www_pem(not_after=now + timedelta(days=10, hours=1))}})
    holder = {}

    def fake_make_live_clients(args, clusters):
        contexts = {c["name"]: c["context"] for c in clusters}
        clients = FakeClients(contexts, {"prod-ocp-admin": prod}, unreachable=("gke_myproject_us-east1_staging",))
        clients.context_override = args.context
        holder["args"] = args
        return clients

    monkeypatch.setattr(main, "make_live_clients", fake_make_live_clients)
    return holder


def test_validate_live_reports_per_asset_and_fails_on_errors(fake_cluster, capsys):
    code, out = run_cli(["validate", EXAMPLE_CFG, "--live"], capsys)
    assert code == 1  # energia-api secret missing, staging cluster unreachable
    assert "Live: public-web  (context: prod-ocp-admin)" in out
    assert "  leaf: " in out and "CN=www.example.com" in out
    assert "WARNING: keystore: " in out and "expires in 10 days" in out
    assert "ERROR: keystore: Secret 'energia-prod/tls-secret' not found" in out
    assert "ERROR: failed to load context 'gke_myproject_us-east1_staging'" in out


def test_search_live_matches_real_san(fake_cluster, capsys):
    # "www" is in the YAML cn too; search a string only present in the real cert instead
    code, out = run_cli(["search", EXAMPLE_CFG, "--live", "--cluster", "prod-ocp", "--namespace", "web-prod",
                         "--cn", "DNS:www"], capsys)
    assert code == 0
    assert "Found 1 matching assets" in out
    assert "live: " in out and "expires in 10 days" in out


def test_search_live_csv_has_live_columns_and_errors(fake_cluster, capsys):
    import csv, io
    code, out = run_cli(["search", EXAMPLE_CFG, "--live", "--format", "csv"], capsys)
    assert code == 1  # errors on two assets
    rows = {r["id"]: r for r in csv.DictReader(io.StringIO(out))}
    assert rows["public-web"]["days_remaining"] == "10"
    assert rows["public-web"]["errors"] == ""
    assert "not found" in rows["energia-api"]["errors"]
    assert "failed to load context" in rows["billing-api"]["errors"]


def test_live_expiring_flag(make_keystore):
    now = datetime.now(timezone.utc)
    soon = FakeCoreV1Api({("web-prod", "web-tls"): {"tls.crt": www_pem(not_after=now + timedelta(days=5, hours=1))}})
    later = FakeCoreV1Api({("web-prod", "web-tls"): {"tls.crt": www_pem(not_after=now + timedelta(days=400))}})
    assert live.inspect_asset(pem_asset(), FakeClients(CONTEXTS, {"prod-ctx": soon}), 30)["expiring"] is True
    assert live.inspect_asset(pem_asset(), FakeClients(CONTEXTS, {"prod-ctx": later}), 30)["expiring"] is False
    # a cn mismatch is a warning, but not an expiry
    mismatch = live.inspect_asset(pem_asset(cn="other"), FakeClients(CONTEXTS, {"prod-ctx": later}), 30)
    assert mismatch["warnings"] and mismatch["expiring"] is False


@pytest.fixture
def healthy_fake_cluster(monkeypatch):
    """Only public-web, reachable, cert valid for 10 days."""
    now = datetime.now(timezone.utc)
    prod = FakeCoreV1Api({("web-prod", "web-tls"): {"tls.crt": www_pem(not_after=now + timedelta(days=10, hours=1))}})

    def fake_make_live_clients(args, clusters):
        return FakeClients({c["name"]: c["context"] for c in clusters}, {"prod-ocp-admin": prod})

    monkeypatch.setattr(main, "make_live_clients", fake_make_live_clients)


@pytest.mark.parametrize("extra, expected_code", [
    ([], 0),                                        # warning only
    (["--fail-on-expiry"], 1),                      # 10 days left < 30
    (["--fail-on-expiry", "--warn-days", "5"], 0),  # 10 days left > 5
])
@pytest.mark.parametrize("command", ["validate", "search"])
def test_live_fail_on_expiry(healthy_fake_cluster, tmp_path, capsys, command, extra, expected_code):
    import yaml
    # only the healthy asset, so errors on the others do not mask the expiry exit code
    cfg = yaml.safe_load(open(EXAMPLE_CFG))
    cfg["assets"] = [a for a in cfg["assets"] if a["id"] == "public-web"]
    path = tmp_path / "assets.yaml"
    path.write_text(yaml.safe_dump(cfg))

    code, _ = run_cli([command, str(path), "--live", *extra], capsys)
    assert code == expected_code


def test_search_without_live_never_connects(fake_cluster, capsys):
    code, out = run_cli(["search", EXAMPLE_CFG, "--cn", "www"], capsys)
    assert code == 0
    assert "args" not in fake_cluster
    assert "live:" not in out


def test_context_and_kubeconfig_require_live(capsys):
    for flag in (["--context", "x"], ["--kubeconfig", "/tmp/k"]):
        with pytest.raises(SystemExit) as exc:
            main.main(["validate", EXAMPLE_CFG, *flag])
        assert exc.value.code == 2
