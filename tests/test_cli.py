import hashlib
import json
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
    assert "--fim-create-baseline" in result.stdout
    assert "--fim-scan" in result.stdout


def test_module_cli_help_runs_successfully():
    result = subprocess.run(
        [sys.executable, "-m", "tracenox.cli.main", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "TraceNox" in result.stdout


def test_cli_can_create_fim_baseline(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()
    (monitored / "test.conf").write_text(
        "enabled=true\n",
        encoding="utf-8",
    )

    baseline = tmp_path / "baseline.json"

    result = subprocess.run(
        [
            "tracenox",
            "--fim-create-baseline",
            str(monitored),
            "--fim-output",
            str(baseline),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "FIM baseline created" in result.stdout
    assert baseline.exists()

    data = json.loads(baseline.read_text(encoding="utf-8"))
    assert data["file_count"] == 1
    assert data["files"]["test.conf"]["sha256"] == hashlib.sha256(
        b"enabled=true\n"
    ).hexdigest()


def test_cli_detects_fim_changes(tmp_path):
    monitored = tmp_path / "monitored"
    monitored.mkdir()

    sample = monitored / "important.conf"
    sample.write_text("secure=true\n", encoding="utf-8")

    baseline = tmp_path / "baseline.json"

    create = subprocess.run(
        [
            "tracenox",
            "--fim-create-baseline",
            str(monitored),
            "--fim-output",
            str(baseline),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert create.returncode == 0

    sample.write_text("secure=false\n", encoding="utf-8")

    scan = subprocess.run(
        [
            "tracenox",
            "--fim-scan",
            str(monitored),
            "--fim-baseline",
            str(baseline),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert scan.returncode == 1
    assert "CHANGES_DETECTED" in scan.stdout
    assert "important.conf" in scan.stdout
    assert "Modified       : 1" in scan.stdout


def test_existing_verify_hash_cli_still_works(tmp_path):
    sample = tmp_path / "sample.txt"
    content = b"TraceNox integrity test\n"
    sample.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()

    result = subprocess.run(
        [
            "tracenox",
            "--verify-hash",
            str(sample),
            "--expected-sha256",
            expected,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Verification      : MATCH" in result.stdout


def test_cli_hardening_help():
    import subprocess

    result = subprocess.run(
        ["tracenox", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--hardening" in result.stdout


def test_cli_hardening_runs():
    import subprocess

    result = subprocess.run(
        ["tracenox", "--hardening"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "TraceNox Linux Security Hardening Audit" in result.stdout
    assert "Security score" in result.stdout


def test_cli_security_score_help():
    import subprocess

    result = subprocess.run(
        ["tracenox", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--security-score" in result.stdout


def test_cli_security_score_runs():
    import subprocess

    result = subprocess.run(
        ["tracenox", "--security-score"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "TraceNox Unified Security Score" in result.stdout
    assert "Overall score" in result.stdout
