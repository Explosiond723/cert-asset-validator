import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest
import yaml

import main
from conftest import REPO_ROOT, TEST_CERTS, cert_pem, make_cert

EXAMPLE_CFG = str(REPO_ROOT / "example-cfg.yaml")


def run_cli(argv, capsys):
    """Run main.main(argv) and return (exit_code, stdout)."""
    try:
        main.main(argv)
        code = 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    return code, capsys.readouterr().out


def write_yaml(tmp_path, data) -> str:
    path = tmp_path / "assets.yaml"
    path.write_text(yaml.safe_dump(data))
    return str(path)


def test_no_command_prints_help(capsys):
    code, out = run_cli([], capsys)
    assert code == 0
    assert "usage:" in out


@pytest.mark.parametrize("argv", [
    ["-v", "analyse", str(TEST_CERTS / "full.pem")],
    ["analyse", str(TEST_CERTS / "full.pem"), "-v"],
])
def test_verbose_flag_before_and_after_subcommand(argv):
    assert main.build_parser().parse_args(argv).verbose is True


def test_verbose_defaults_to_false():
    assert main.build_parser().parse_args(["analyse", "x.pem"]).verbose is False


# --- validate -------------------------------------------------------------------

def test_validate_example_config(capsys):
    code, out = run_cli(["validate", EXAMPLE_CFG], capsys)
    assert code == 0
    assert "Clusters defined: prod-ocp, staging-gke" in out
    for asset_id in ("energia-api", "billing-api", "public-web"):
        assert asset_id in out


def test_validate_reports_every_invalid_asset(tmp_path, capsys):
    cfg = write_yaml(tmp_path, {
        "clusters": [{"name": "c1", "context": "ctx"}],
        "assets": [
            {"id": "ok", "cluster": "c1", "namespace": "ns", "cn": "ok.example.com", "certType": "pem"},
            {"id": "no-cn", "cluster": "c1", "namespace": "ns", "certType": "pem"},
            {"id": "bad-cluster", "cluster": "nope", "namespace": "ns", "cn": "x", "certType": "pem"},
            {"id": "no-password", "cluster": "c1", "namespace": "ns", "cn": "x", "certType": "pkcs12",
             "keystore": {"secret": {"name": "s", "key": "k"}}},
            "not-a-dict",
        ],
    })
    code, out = run_cli(["validate", cfg], capsys)
    assert code == 1
    assert "Asset ID:  ok" in out
    assert "error: no-cn: missing required field: cn" in out
    assert "error: bad-cluster: cluster 'nope' is not defined" in out
    assert "error: no-password: missing required field: keystore.passwordRef" in out
    assert "error: asset[4]:" in out


def test_validate_missing_file_is_a_clean_error(tmp_path, capsys):
    code, out = run_cli(["validate", str(tmp_path / "missing.yaml")], capsys)
    assert code == 1
    assert out.startswith("error:")


def test_validate_legacy_flat_list(tmp_path, capsys):
    cfg = write_yaml(tmp_path, [
        {"id": "legacy", "namespace": "ns", "cn": "legacy.example.com", "certType": "pem"},
    ])
    code, out = run_cli(["validate", cfg], capsys)
    assert code == 0
    assert "Asset ID:  legacy" in out


# --- search ---------------------------------------------------------------------

@pytest.mark.parametrize("filters, expected", [
    (["--cn", "energia"], {"energia-api"}),
    (["--cluster", "prod-ocp"], {"energia-api", "public-web"}),
    (["--namespace", "billing-prod"], {"billing-api"}),
    (["--secret", "tls-secret"], {"energia-api"}),
    (["--cluster", "prod-ocp", "--cn", "www"], {"public-web"}),
    (["--cluster", "staging-gke", "--cn", "energia"], set()),
])
def test_search_filters(capsys, filters, expected):
    code, out = run_cli(["search", EXAMPLE_CFG, *filters], capsys)
    assert code == 0
    assert f"Found {len(expected)} matching assets" in out
    found = {line.split("|")[0].strip() for line in out.splitlines() if "|" in line}
    assert found == expected


# --- analyse --------------------------------------------------------------------

def test_analyse_output_is_human_readable(capsys):
    code, out = run_cli(["analyse", str(TEST_CERTS / "full.pem")], capsys)
    assert code == 0
    assert "  san: DNS:test.example.com, DNS:*.example.com" in out
    assert "  eku: serverAuth, clientAuth" in out
    assert "mTLS candidate: True" in out
    assert "<DNSName" not in out and "ObjectIdentifier" not in out


def test_analyse_empty_lists_print_none(capsys):
    code, out = run_cli(["analyse", str(TEST_CERTS / "minimal.pem")], capsys)
    assert code == 0
    assert "  san: (none)" in out
    assert "  eku: (none)" in out


def test_analyse_warns_for_cert_expiring_soon(write_cert, capsys):
    cert, _ = make_cert(not_after=datetime.now(timezone.utc) + timedelta(days=10, hours=1))
    path = write_cert(cert)

    code, out = run_cli(["analyse", path], capsys)
    assert code == 0
    assert "  expiry: expires in 10 days" in out
    assert "  WARNING: certificate expires in 10 days (threshold: 30 days)" in out

    code, out = run_cli(["analyse", path, "--warn-days", "5"], capsys)
    assert code == 0
    assert "WARNING" not in out


def test_analyse_warns_for_expired_cert(write_cert, capsys):
    now = datetime.now(timezone.utc)
    cert, _ = make_cert(not_before=now - timedelta(days=100), not_after=now - timedelta(days=3, hours=1))
    code, out = run_cli(["analyse", write_cert(cert)], capsys)
    assert code == 0
    assert "  validity_status: expired" in out
    assert "  WARNING: certificate expired 3 days ago" in out


def test_analyse_no_warning_for_long_lived_cert(write_cert, capsys):
    cert, _ = make_cert(not_after=datetime.now(timezone.utc) + timedelta(days=400))
    code, out = run_cli(["analyse", write_cert(cert)], capsys)
    assert code == 0
    assert "WARNING" not in out


def test_analyse_warns_per_cert_in_a_chain(tmp_path, capsys):
    now = datetime.now(timezone.utc)
    leaf, _ = make_cert(cn="leaf", not_after=now + timedelta(days=5, hours=1))
    ca, _ = make_cert(cn="ca", not_after=now + timedelta(days=3650))
    from conftest import cert_pem
    path = tmp_path / "chain.pem"
    path.write_bytes(cert_pem(leaf) + cert_pem(ca))

    code, out = run_cli(["analyse", str(path)], capsys)
    assert code == 0
    assert out.count("WARNING") == 1
    assert "certificate expires in 5 days" in out


@pytest.mark.parametrize("value", ["-1", "abc"])
def test_analyse_rejects_invalid_warn_days(value, capsys):
    with pytest.raises(SystemExit) as exc:
        main.main(["analyse", str(TEST_CERTS / "full.pem"), "--warn-days", value])
    assert exc.value.code == 2  # argparse usage error


def test_analyse_pkcs12_without_password_is_a_clean_error(capsys):
    code, out = run_cli(["analyse", str(TEST_CERTS / "withpass.p12")], capsys)
    assert code == 1
    assert out.startswith("error: unable to decrypt PKCS12")


def test_analyse_garbage_and_missing_files(tmp_path, capsys):
    code, out = run_cli(["analyse", str(TEST_CERTS / "garbage.bin")], capsys)
    assert code == 1
    assert "unable to detect certificate format" in out

    code, out = run_cli(["analyse", str(tmp_path / "missing.pem")], capsys)
    assert code == 1
    assert out.startswith("error:")


def test_analyse_jks_password_errors_reach_the_cli(make_keystore, tmp_path, capsys):
    path = tmp_path / "store.jks"
    path.write_bytes(make_keystore())

    code, out = run_cli(["analyse", str(path), "--password", "wrong"], capsys)
    assert code == 1
    assert out.startswith("error: wrong password for JKS keystore")

    code, out = run_cli(["analyse", str(path)], capsys)
    assert code == 1
    assert out.startswith("error: JKS keystores require a password")

    code, out = run_cli(["analyse", str(path), "--password", "changeit"], capsys)
    assert code == 0
    assert "  alias: my-ca" in out


# --- --fail-on-expiry -----------------------------------------------------------------

@pytest.mark.parametrize("days_left, extra, expected_code", [
    (400, [], 0),                         # healthy cert: never fails
    (10, [], 0),                          # warning only, flag not given: exit code unchanged
    (10, ["--fail-on-expiry"], 1),
    (10, ["--fail-on-expiry", "--warn-days", "5"], 0),
    (-3, ["--fail-on-expiry"], 1),        # already expired
])
def test_analyse_fail_on_expiry(write_cert, capsys, days_left, extra, expected_code):
    now = datetime.now(timezone.utc)
    cert, _ = make_cert(not_before=now - timedelta(days=30), not_after=now + timedelta(days=days_left, hours=1))
    code, _ = run_cli(["analyse", write_cert(cert), *extra], capsys)
    assert code == expected_code


def test_analyse_fail_on_expiry_counts_any_cert_in_chain(tmp_path, capsys):
    now = datetime.now(timezone.utc)
    leaf, _ = make_cert(cn="leaf", not_after=now + timedelta(days=400))
    ca, _ = make_cert(cn="ca", not_after=now + timedelta(days=2, hours=1))
    path = tmp_path / "chain.pem"
    path.write_bytes(cert_pem(leaf) + cert_pem(ca))
    code, _ = run_cli(["analyse", str(path), "--fail-on-expiry"], capsys)
    assert code == 1


def test_analyse_fail_on_expiry_keeps_csv_stdout_clean(write_cert, capsys):
    import csv, io
    cert, _ = make_cert(not_after=datetime.now(timezone.utc) + timedelta(days=3, hours=1))
    try:
        main.main(["analyse", write_cert(cert), "--format", "csv", "--fail-on-expiry"])
        code = 0
    except SystemExit as e:
        code = e.code
    captured = capsys.readouterr()
    assert code == 1
    assert len(list(csv.DictReader(io.StringIO(captured.out)))) == 1
    assert "expiring within 30 days" in captured.err


@pytest.mark.parametrize("command", ["validate", "search"])
def test_fail_on_expiry_requires_live_for_inventory_commands(command):
    with pytest.raises(SystemExit) as exc:
        main.main([command, EXAMPLE_CFG, "--fail-on-expiry"])
    assert exc.value.code == 2


# --- --format ---------------------------------------------------------------------

def test_search_csv_is_parseable(capsys):
    import csv, io
    code, out = run_cli(["search", EXAMPLE_CFG, "--format", "csv", "--cluster", "prod-ocp"], capsys)
    assert code == 0
    rows = list(csv.DictReader(io.StringIO(out)))
    assert [r["id"] for r in rows] == ["energia-api", "public-web"]
    assert rows[0]["cn"] == "energia-api.example.com"


def test_search_table_has_header_and_aligned_rows(capsys):
    code, out = run_cli(["search", EXAMPLE_CFG, "--format", "table"], capsys)
    lines = out.splitlines()
    assert code == 0
    assert lines[0].split() == ["ID", "CLUSTER", "NAMESPACE", "CN", "CERTTYPE"]
    assert len(lines) == 4
    # every column starts at the same offset on every line
    offset = lines[0].index("CLUSTER")
    assert all(line[offset - 2:offset] == "  " for line in lines[1:])


def test_search_table_with_no_match_prints_only_header(capsys):
    code, out = run_cli(["search", EXAMPLE_CFG, "--format", "table", "--cn", "nothing"], capsys)
    assert code == 0
    assert out.splitlines() == ["ID  CLUSTER  NAMESPACE  CN  CERTTYPE"]


def test_analyse_csv_one_row_per_cert(capsys):
    import csv, io
    code, out = run_cli(["analyse", str(TEST_CERTS / "withpass.p12"), "--password", "secret", "--format", "csv"], capsys)
    assert code == 0
    rows = list(csv.DictReader(io.StringIO(out)))
    assert [r["subject"] for r in rows] == ["CN=test.example.com,C=US", "CN=Test CA,C=US"]
    assert rows[0]["san"] == "DNS:test.example.com; DNS:*.example.com"
    assert "mTLS candidate" not in out  # csv must stay machine-readable


def test_analyse_csv_includes_expiry_warning(write_cert, capsys):
    import csv, io
    cert, _ = make_cert(not_after=datetime.now(timezone.utc) + timedelta(days=3, hours=1))
    code, out = run_cli(["analyse", write_cert(cert), "--format", "csv"], capsys)
    row = next(csv.DictReader(io.StringIO(out)))
    assert row["warning"].startswith("certificate expires in 3 days")


def test_invalid_format_is_rejected(capsys):
    with pytest.raises(SystemExit) as exc:
        main.main(["search", EXAMPLE_CFG, "--format", "json"])
    assert exc.value.code == 2


# --- csr ------------------------------------------------------------------------

def test_csr_writes_csr_and_key(tmp_path, capsys):
    csr_path = tmp_path / "out.csr"
    key_path = tmp_path / "out-key.pem"
    code, out = run_cli([
        "csr", str(TEST_CERTS / "full.pem"),
        "--output", str(csr_path), "--key-output", str(key_path),
    ], capsys)
    assert code == 0
    assert csr_path.read_bytes().startswith(b"-----BEGIN CERTIFICATE REQUEST-----")
    assert b"PRIVATE KEY" in key_path.read_bytes()


# --- optional dependencies --------------------------------------------------------

def run_without_modules(blocked, argv):
    """Run main.py in a fresh interpreter where the given modules cannot be imported."""
    code = (
        "import runpy, sys\n"
        f"for name in {blocked!r}:\n"
        "    sys.modules[name] = None\n"
        f"sys.argv = ['main.py'] + {argv!r}\n"
        "runpy.run_path('main.py', run_name='__main__')\n"
    )
    return subprocess.run(
        [sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True,
    )


@pytest.mark.parametrize("argv", [
    ["validate", "example-cfg.yaml"],
    ["search", "example-cfg.yaml", "--cn", "energia"],
    ["analyse", "test_certs/full.pem"],
    ["analyse", "test_certs/full.der"],
    ["analyse", "test_certs/withpass.p12", "--password", "secret"],
    ["csr", "test_certs/full.pem", "--output", "{tmp}/out.csr", "--key-output", "{tmp}/out-key.pem"],
])
def test_offline_commands_need_neither_kubernetes_nor_pyjks(argv, tmp_path):
    argv = [a.replace("{tmp}", str(tmp_path)) for a in argv]
    result = run_without_modules(["kubernetes", "jks"], argv)
    assert result.returncode == 0, result.stdout + result.stderr


def test_jks_without_pyjks_is_a_clean_error(tmp_path):
    path = tmp_path / "store.jks"
    path.write_bytes(b"\xfe\xed\xfe\xed" + b"\x00" * 16)
    result = run_without_modules(["jks"], ["analyse", str(path), "--password", "x"])
    assert result.returncode == 1
    assert "pip install pyjks" in result.stdout
