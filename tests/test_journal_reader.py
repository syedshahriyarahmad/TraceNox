import subprocess

import pytest

from tracenox.analyzer.log_reader import read_journal_lines


def test_read_journal_lines_returns_entries(monkeypatch):
    expected = [
        "Sep 28 09:56:05 kali sshd[646]: Server listening on port 22."
    ]

    def fake_run(command, **kwargs):
        assert command[:3] == ["sudo", "journalctl", "-u"]
        assert "ssh" in command
        assert "--no-pager" in command
        return subprocess.CompletedProcess(
            command, 0, stdout="\n".join(expected) + "\n", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert read_journal_lines() == expected


def test_read_journal_lines_reports_failure(monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            command, 1, stdout="", stderr="permission denied"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(ValueError, match="permission denied"):
        read_journal_lines()


def test_read_journal_lines_rejects_invalid_unit():
    with pytest.raises(ValueError, match="Invalid systemd unit"):
        read_journal_lines(unit="-bad")
