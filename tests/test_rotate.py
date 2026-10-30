import base64
import json
import os
import stat
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12

pytest.importorskip("kubernetes")
from kubernetes.client.exceptions import ApiException

import main
from test_live import FakeClients
from test_map import make_ca, name, pem

NOW = datetime.now(timezone.utc)


def leaf(cn, ca, key=None, days=90, sans=None, start_days_ago=1):
    ca_cert, ca_key = ca
    key = key or ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=start_days_ago)).not_valid_after(NOW + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in (sans or [cn])]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    return cert, key


def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


# FakeApi: Secrets as (namespace, name) -> {"data": {key: bytes}, "type", "annotations"};
# workloads as namespace -> {kind: [(name, secret used)]}. Mirrors what rotate reads.
class FakeApi:
    def __init__(self, secrets, workloads=None, apps_forbidden=False):
        self.secrets = secrets
        self.apps_api = FakeApps(workloads or {}, apps_forbidden)

    def read_namespaced_secret(self, name, namespace, _request_timeout=None):
        entry = self.secrets.get((namespace, name))
        if entry is None:
            raise ApiException(status=404, reason="Not Found")
        data = {k: base64.b64encode(v).decode() for k, v in entry["data"].items()}
        return SimpleNamespace(data=data, type=entry.get("type", "Opaque"),
                               metadata=SimpleNamespace(name=name, resource_version="4242",
                                                        annotations=entry.get("annotations")))


class FakeApps:
    def __init__(self, workloads, forbidden):
        self.workloads, self.forbidden = workloads, forbidden

    def _list(self, kind, namespace):
        if self.forbidden:
            raise ApiException(status=403, reason="Forbidden")
        items = []
        for wl_name, secret in self.workloads.get(namespace, {}).get(kind, []):
            volume = SimpleNamespace(secret=SimpleNamespace(secret_name=secret), projected=None)
            spec = SimpleNamespace(volumes=[volume], containers=[], init_containers=None)
            items.append(SimpleNamespace(metadata=SimpleNamespace(name=wl_name),
                                         spec=SimpleNamespace(template=SimpleNamespace(spec=spec))))
        return SimpleNamespace(items=items)

    def list_namespaced_deployment(self, namespace, _request_timeout=None):
        return self._list("deployment", namespace)

    def list_namespaced_stateful_set(self, namespace, _request_timeout=None):
        return self._list("statefulset", namespace)

    def list_namespaced_daemon_set(self, namespace, _request_timeout=None):
        return self._list("daemonset", namespace)


@pytest.fixture(scope="module")
def pki():
    ca = make_ca("Corp CA")
    other_ca = make_ca("Other CA")
    v1, v1_key = leaf("www.example.com", ca)
    v2, v2_key = leaf("www.example.com", ca, days=365)           # renewal with a new key
    v3, _ = leaf("www.example.com", ca, key=v1_key, days=365)     # renewal reusing the key
    other, other_key = leaf("www.example.com", other_ca, days=365)
    expired, expired_key = leaf("www.example.com", ca, days=-1, start_days_ago=10)
    fewer_sans, fewer_key = leaf("www.example.com", ca, days=365, sans=["other.example.com"])
    return locals()


INVENTORY = """\
clusters:
  - name: prod
    context: prod-ctx
assets:
  - id: web
    cluster: prod
    namespace: web
    cn: www.example.com
    certType: pem
    keystore: {secret: {name: web-tls, key: tls.crt}}
  - id: portal
    cluster: prod
    namespace: web
    cn: www.example.com
    certType: pem
    keystore: {secret: {name: portal-tls, key: tls.crt}}
    chain: {secret: {name: portal-tls, key: cacerts.pem}}
  - id: web-bck
    cluster: prod
    namespace: web
    cn: www.example.com
    certType: pem
    keystore: {secret: {name: web-tls-bck, key: tls.crt}}
  - id: api
    cluster: prod
    namespace: api
    cn: api.example.com
    certType: pem
    keystore: {secret: {name: api-tls, key: tls.crt}}
"""


@pytest.fixture
def env(pki, tmp_path, monkeypatch):
    ca = pki["ca"][0]
    api_leaf, api_key = leaf("api.example.com", pki["ca"])
    secrets = {
        ("web", "web-tls"): {"type": "kubernetes.io/tls",
                             "data": {"tls.crt": pem(pki["v1"], ca), "tls.key": key_pem(pki["v1_key"])}},
        ("web", "portal-tls"): {"data": {"tls.crt": pem(pki["v1"]), "tls.key": key_pem(pki["v1_key"]),
                                         "cacerts.pem": pem(ca)}},
        ("web", "web-tls-bck"): {"data": {"tls.crt": pem(pki["v1"], ca), "tls.key": key_pem(pki["v1_key"])}},
        ("api", "api-tls"): {"data": {"tls.crt": pem(api_leaf), "tls.key": key_pem(api_key)}},
    }
    api = FakeApi(secrets, workloads={"web": {"deployment": [("web", "web-tls"), ("unrelated", "x")],
                                              "statefulset": [("portal", "portal-tls")]}})
    clients = FakeClients({"prod": "prod-ctx"}, {"prod-ctx": api})
    monkeypatch.setattr(main, "make_live_clients", lambda args, clusters: clients)
    inv = tmp_path / "inv.yaml"
    inv.write_text(INVENTORY)

    def write(filename, data):
        path = tmp_path / filename
        path.write_bytes(data)
        return str(path)

    files = {
        "v2": write("v2.pem", pem(pki["v2"])), "v2_key": write("v2.key", key_pem(pki["v2_key"])),
        "v2_chain": write("v2-chain.pem", pem(pki["v2"], ca)),
        "v3": write("v3.pem", pem(pki["v3"])),
        "other": write("other.pem", pem(pki["other"])), "other_key": write("other.key", key_pem(pki["other_key"])),
        "other_ca": write("other-ca.pem", pem(pki["other_ca"][0])),
        "expired": write("expired.pem", pem(pki["expired"])),
        "expired_key": write("expired.key", key_pem(pki["expired_key"])),
        "fewer": write("fewer.pem", pem(pki["fewer_sans"])), "fewer_key": write("fewer.key", key_pem(pki["fewer_key"])),
    }
    return SimpleNamespace(inv=str(inv), api=api, secrets=secrets, files=files, tmp=tmp_path)


def run_rotate(argv, capsys):
    try:
        main.main(["rotate", *argv])
        code = 0
    except SystemExit as e:
        code = e.code
    return code, capsys.readouterr().out


def decode_patch(path):
    patch = json.loads(open(path).read())
    return patch["metadata"], {k: base64.b64decode(v) for k, v in patch["data"].items()}


# --- plan ----------------------------------------------------------------------------------

def test_dry_run_plan_finds_every_copy_and_skips_backups(env, capsys):
    code, out = run_rotate([env.inv, "--id", "web", "--cert", env.files["v2"], "--key", env.files["v2_key"]], capsys)
    assert code == 0, out
    assert "Rotation plan (nothing is written to the cluster)" in out
    assert "held by: web, portal" in out
    assert "Secret prod / web / web-tls  (assets: web)" in out
    assert "tls.crt: replace (certificate + chain, PEM)" in out
    assert "tls.key: replace (private key)" in out
    # the chain Secret key is kept: the same CA signed the new certificate
    assert "cacerts.pem: unchanged (its CA signed the new certificate)" in out
    # web-tls-bck already exists, so the backup gets a dated name
    assert f"backup: web-tls-bck-{NOW.strftime('%Y%m%d')} (created before the change)" in out
    assert "backup: portal-tls-bck (created before the change)" in out
    assert "restart: not requested (-r/--restart)" in out
    assert "Assets that backup copies keep the current certificate (not changed): web-bck" in out
    assert "Dry run: add -o DIR" in out
    assert "PRIVATE KEY" not in out


def test_manifests_and_script(env, pki, capsys):
    out_dir = env.tmp / "out"
    code, out = run_rotate([env.inv, "-i", "web", "--cert", env.files["v2_chain"], "-k", env.files["v2_key"],
                            "-o", str(out_dir), "-r"], capsys)
    assert code == 0, out
    assert "do not commit them" in out
    assert stat.S_IMODE(os.stat(out_dir).st_mode) == 0o700
    assert (out_dir / ".gitignore").read_text().endswith("*\n")

    meta, data = decode_patch(out_dir / "prod/web/web-tls.patch.json")
    assert meta == {"resourceVersion": "4242"}  # optimistic concurrency
    assert sorted(data) == ["tls.crt", "tls.key"]
    certs = x509.load_pem_x509_certificates(data["tls.crt"])
    assert certs[0] == pki["v2"]
    assert len(certs) == 2  # the chain stays with the certificate, as before
    assert stat.S_IMODE(os.stat(out_dir / "prod/web/web-tls.patch.json").st_mode) == 0o600

    # portal: leaf only in tls.crt, chain in cacerts.pem. The layout is kept: tls.crt stays
    # leaf only although --cert carried a chain, and cacerts.pem already holds that chain
    _meta, portal = decode_patch(out_dir / "prod/web/portal-tls.patch.json")
    assert sorted(portal) == ["tls.crt", "tls.key"]
    assert x509.load_pem_x509_certificates(portal["tls.crt"]) == [pki["v2"]]
    assert "cacerts.pem: unchanged (CA chain)" in out

    backup = yaml.safe_load((out_dir / "prod/web/portal-tls-bck.yaml").read_text())
    assert backup["metadata"]["name"] == "portal-tls-bck"
    assert backup["metadata"]["annotations"]["cert-asset-validator/backup-of"] == "portal-tls"
    assert base64.b64decode(backup["data"]["tls.crt"]) == env.secrets[("web", "portal-tls")]["data"]["tls.crt"]

    script = (out_dir / "rotate.sh").read_text()
    lines = [line for line in script.splitlines() if line.startswith('"$KUBECTL"')]
    stamp = NOW.strftime("%Y%m%d")
    assert lines == [
        f'"$KUBECTL" --context prod-ctx -n web create -f prod/web/web-tls-bck-{stamp}.yaml',
        '"$KUBECTL" --context prod-ctx -n web patch secret web-tls --type merge --patch-file prod/web/web-tls.patch.json',
        '"$KUBECTL" --context prod-ctx -n web rollout restart deployment/web',
        '"$KUBECTL" --context prod-ctx -n web create -f prod/web/portal-tls-bck.yaml',
        '"$KUBECTL" --context prod-ctx -n web patch secret portal-tls --type merge --patch-file prod/web/portal-tls.patch.json',
        '"$KUBECTL" --context prod-ctx -n web rollout restart statefulset/portal',
    ]
    assert "set -euo pipefail" in script
    assert os.access(out_dir / "rotate.sh", os.X_OK)


def test_no_backup_and_output_dir_must_be_empty(env, capsys):
    out_dir = env.tmp / "out"
    args = [env.inv, "--id", "web", "--cert", env.files["v2"], "--key", env.files["v2_key"], "-o", str(out_dir), "-B"]
    code, out = run_rotate(args, capsys)
    assert code == 0, out
    assert "backup: disabled (--no-backup)" in out
    assert not list(out_dir.glob("**/*-bck*"))
    assert " create " not in (out_dir / "rotate.sh").read_text()

    code, out = run_rotate(args, capsys)
    assert code == 1 and "is not empty, use --force" in out
    assert run_rotate(args + ["--force"], capsys)[0] == 0


def test_key_reused_when_the_new_certificate_keeps_it(env, capsys):
    code, out = run_rotate([env.inv, "--id", "web", "--cert", env.files["v3"]], capsys)
    assert code == 0, out
    assert "tls.key: unchanged (same key as the new certificate)" in out
    assert "tls.crt: replace" in out


def test_new_key_required_when_the_key_changed(env, tmp_path, capsys):
    out_dir = tmp_path / "never"
    code, out = run_rotate([env.inv, "--id", "web", "--cert", env.files["v2"], "-o", str(out_dir)], capsys)
    assert code == 1
    assert "has a new key: pass --key" in out
    assert "Not written" in out and not out_dir.exists()


def test_key_must_match_the_certificate(env, capsys):
    code, out = run_rotate([env.inv, "--id", "web", "--cert", env.files["v2"], "--key", env.files["other_key"]], capsys)
    assert code == 1 and "is not the private key of" in out


def test_other_ca_needs_a_new_chain(env, capsys):
    code, out = run_rotate([env.inv, "--id", "web", "--cert", env.files["other"], "--key", env.files["other_key"]], capsys)
    assert code == 1
    assert "the current chain did not sign the new certificate: pass --chain" in out
    assert "did not sign the new certificate: pass --chain" in out

    code, out = run_rotate([env.inv, "--id", "web", "--cert", env.files["other"], "--key", env.files["other_key"],
                            "--chain", env.files["other_ca"]], capsys)
    assert code == 0, out
    assert "cacerts.pem: replace (CA chain)" in out


def test_expired_and_san_checks(env, capsys):
    code, out = run_rotate([env.inv, "--id", "web", "--cert", env.files["expired"], "--key", env.files["expired_key"]], capsys)
    assert code == 1 and "ERROR: the new certificate is expired" in out

    args = [env.inv, "--id", "web", "--cert", env.files["fewer"], "--key", env.files["fewer_key"]]
    code, out = run_rotate(args, capsys)
    assert code == 1
    assert "SANs of the current certificate missing from the new one: DNS:www.example.com" in out
    code, out = run_rotate(args + ["--allow-san-removal"], capsys)
    assert code == 0 and "WARNING: SANs of the current certificate missing" in out


def test_same_certificate_and_unknown_asset(env, pki, tmp_path, capsys):
    same = tmp_path / "v1.pem"
    same.write_bytes(pem(pki["v1"]))
    code, out = run_rotate([env.inv, "--id", "web", "--cert", str(same)], capsys)
    assert code == 1 and "already in place" in out
    code, out = run_rotate([env.inv, "--id", "nope", "--cert", str(same)], capsys)
    assert code == 1 and "asset 'nope' not found" in out
    code, out = run_rotate([env.inv, "--id", "web-bck", "--cert", env.files["v2"]], capsys)
    assert code == 1 and "is a backup copy of Secret 'web-tls'" in out


def test_cn_selection_must_hold_one_certificate(env, capsys):
    code, out = run_rotate([env.inv, "--cn", "example.com", "--cert", env.files["v2"], "--key", env.files["v2_key"]], capsys)
    assert code == 1 and "hold 2 different certificates" in out and "rotate one at a time with --id" in out
    code, out = run_rotate([env.inv, "--cn", "www", "--cert", env.files["v2"], "--key", env.files["v2_key"]], capsys)
    assert code == 0, out
    assert "held by: web, portal" in out


def test_cert_manager_secret_and_restart_without_rbac(env, capsys):
    env.secrets[("web", "web-tls")]["annotations"] = {"cert-manager.io/certificate-name": "www"}
    env.api.apps_api.forbidden = True
    code, out = run_rotate([env.inv, "--id", "web", "--cert", env.files["v2"], "--key", env.files["v2_key"], "-r"], capsys)
    assert code == 0, out
    assert "managed by cert-manager (Certificate 'www')" in out
    assert "restart: permission denied listing deployments in namespace 'web'" in out
    assert "restart: none found" in out


# --- keystores -----------------------------------------------------------------------------

def keystore_env(env, secret_data, asset_yaml):
    env.secrets[("ks", "ks-tls")] = {"data": secret_data}
    env.secrets[("ks", "ks-pass")] = {"data": {"password": b"storepass"}}
    inv = env.tmp / "ks.yaml"
    inv.write_text("clusters:\n  - {name: prod, context: prod-ctx}\nassets:\n" + asset_yaml)
    return str(inv)


def test_pkcs12_rebuilt_with_the_same_password(env, pki, capsys):
    p12 = pkcs12.serialize_key_and_certificates(b"www", pki["v1_key"], pki["v1"], [pki["ca"][0]],
                                                serialization.BestAvailableEncryption(b"storepass"))
    inv = keystore_env(env, {"keystore.p12": p12}, """\
  - id: ks
    cluster: prod
    namespace: ks
    cn: www.example.com
    certType: pkcs12
    keystore:
      secret: {name: ks-tls, key: keystore.p12}
      passwordRef: {name: ks-pass, key: password}
""")
    out_dir = env.tmp / "p12"
    code, out = run_rotate([inv, "--id", "ks", "--cert", env.files["v2"], "--key", env.files["v2_key"],
                            "-o", str(out_dir)], capsys)
    assert code == 0, out
    assert "keystore.p12: replace (PKCS12 rebuilt with the same password)" in out
    _meta, data = decode_patch(out_dir / "prod/ks/ks-tls.patch.json")
    key, cert, cas = pkcs12.load_key_and_certificates(data["keystore.p12"], b"storepass")
    assert cert == pki["v2"] and cas == [pki["ca"][0]]
    assert key.public_key().public_numbers() == pki["v2_key"].public_key().public_numbers()


def test_jks_rebuilt_keeping_other_entries(env, pki, capsys):
    jks = pytest.importorskip("jks")
    der = lambda c: c.public_bytes(serialization.Encoding.DER)
    pk = pki["v1_key"].private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())
    store = jks.KeyStore.new("jks", [jks.PrivateKeyEntry.new("www", [der(pki["v1"]), der(pki["ca"][0])], pk),
                                     jks.TrustedCertEntry.new("partner", der(pki["other_ca"][0]))])
    inv = keystore_env(env, {"keystore.jks": store.saves("storepass")}, """\
  - id: ks
    cluster: prod
    namespace: ks
    cn: www.example.com
    certType: keystore
    keystore:
      secret: {name: ks-tls, key: keystore.jks}
      passwordRef: {name: ks-pass, key: password}
""")
    out_dir = env.tmp / "jks"
    code, out = run_rotate([inv, "--id", "ks", "--cert", env.files["v2"], "--key", env.files["v2_key"],
                            "-o", str(out_dir)], capsys)
    assert code == 0, out
    _meta, data = decode_patch(out_dir / "prod/ks/ks-tls.patch.json")
    rebuilt = jks.KeyStore.loads(data["keystore.jks"], "storepass")
    entry = rebuilt.private_keys["www"]
    assert [c[1] for c in entry.cert_chain] == [der(pki["v2"]), der(pki["ca"][0])]
    assert rebuilt.certs["partner"].cert == der(pki["other_ca"][0])


def test_short_options_parse():
    args = main.build_parser().parse_args(["rotate", "inv.yaml", "-i", "web", "--cert", "c.pem", "-k", "k.pem",
                                           "-o", "out", "-B", "-r", "-c", "ctx", "-w", "10"])
    assert (args.id, args.key, args.output, args.no_backup, args.restart, args.context, args.warn_days) == \
        ("web", "k.pem", "out", True, True, "ctx", 10)
    args = main.build_parser().parse_args(["search", "inv.yaml", "-n", "ns", "-C", "prod", "-s", "web-tls",
                                           "-l", "-f", "csv"])
    assert (args.namespace, args.cluster, args.secret, args.live, args.format) == ("ns", "prod", "web-tls", True, "csv")
    args = main.build_parser().parse_args(["csr", "c.pem", "-o", "x.csr", "-k", "k.pem", "-p", "pw"])
    assert (args.output, args.key, args.password) == ("x.csr", "k.pem", "pw")
    args = main.build_parser().parse_args(["discover", "-n", "ns", "-c", "ctx", "-u", "inv.yaml"])
    assert (args.context, args.update) == ("ctx", "inv.yaml")
