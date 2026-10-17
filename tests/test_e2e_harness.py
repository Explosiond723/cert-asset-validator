"""Tests for the scenario harness of e2e/kind.sh (no cluster needed).

The kind job in CI is only as good as the harness deciding [OK] / [UNEXPECTED]: a scenario
expecting exit 1 must not pass on a crash, and a missing expected message must fail it.
"""
import shutil
import subprocess

import pytest

from conftest import REPO_ROOT

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")

PY_FAIL = "import sys; print('error: something expected'); sys.exit(1)"
PY_CRASH = "raise ValueError('boom')"
PY_OK = "print('all good: 42')"


def run_harness(body: str, tmp_path) -> tuple[str, int, int]:
    """Source kind.sh, run `body`, return (output, PASS, FAIL)."""
    script = f"""
source "{REPO_ROOT / 'e2e' / 'kind.sh'}"
OUT="{tmp_path}"
{body}
echo "COUNTERS $PASS $FAIL"
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    counters = result.stdout.strip().splitlines()[-1].split()
    return result.stdout, int(counters[1]), int(counters[2])


def test_exit_code_and_expected_text_pass(tmp_path):
    out, ok, ko = run_harness(f'''
expect "all good" "42"
scenario 0 "ok" python3 -c "{PY_OK}"
''', tmp_path)
    assert (ok, ko) == (1, 0)
    assert "+ output contains: all good" in out
    assert "[OK]" in out


def test_expected_failure_with_the_right_message_passes(tmp_path):
    _, ok, ko = run_harness(f'''
expect "error: something expected"
scenario 1 "fails as expected" python3 -c "{PY_FAIL}"
''', tmp_path)
    assert (ok, ko) == (1, 0)


def test_traceback_fails_even_with_the_expected_exit_code(tmp_path):
    out, ok, ko = run_harness(f'''
scenario 1 "a crash also exits 1" python3 -c "{PY_CRASH}"
''', tmp_path)
    assert (ok, ko) == (0, 1)
    assert "* Python traceback in the output" in out


def test_missing_expected_text_fails(tmp_path):
    out, ok, ko = run_harness(f'''
expect "error: a different message"
scenario 1 "right exit code, wrong error" python3 -c "{PY_FAIL}"
''', tmp_path)
    assert (ok, ko) == (0, 1)
    assert "* missing from output: error: a different message" in out


def test_rejected_text_fails(tmp_path):
    out, ok, ko = run_harness(f'''
reject "42"
scenario 0 "must not mention 42" python3 -c "{PY_OK}"
''', tmp_path)
    assert (ok, ko) == (0, 1)
    assert "* unexpected in output: 42" in out


def test_wrong_exit_code_fails(tmp_path):
    out, ok, ko = run_harness(f'''
scenario 0 "should succeed" python3 -c "{PY_FAIL}"
''', tmp_path)
    assert (ok, ko) == (0, 1)
    assert "* exit 1, wanted 0" in out


def test_expectations_are_reset_after_each_scenario(tmp_path):
    _, ok, ko = run_harness(f'''
expect "error: a different message"
scenario 1 "first fails" python3 -c "{PY_FAIL}"
scenario 1 "second has no expectations left" python3 -c "{PY_FAIL}"
''', tmp_path)
    assert (ok, ko) == (1, 1)


def test_script_runs_commands_inside_out(tmp_path):
    (tmp_path / "marker.txt").write_text("inside OUT")
    _, ok, ko = run_harness('''
expect "inside OUT"
scenario 0 "cwd is OUT" cat marker.txt
''', tmp_path)
    assert (ok, ko) == (1, 0)


def test_sourcing_does_not_run_a_subcommand(tmp_path):
    # without the BASH_SOURCE guard, sourcing would print the usage and exit 2
    out, ok, ko = run_harness("", tmp_path)
    assert "usage:" not in out
    assert (ok, ko) == (0, 0)
