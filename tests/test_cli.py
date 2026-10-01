import subprocess
import sys


def test_cli_help_runs_successfully():
    result = subprocess.run(
        ["tracenox", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "TraceNox" in result.stdout
    assert "--verify-hash" in result.stdout


def test_module_cli_help_runs_successfully():
    result = subprocess.run(
        [sys.executable, "-m", "tracenox.cli.main", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "TraceNox" in result.stdout
