from pathlib import Path

from tracenox.analyzer.pipeline import analyze_log_file


def test_pipeline_calculates_separate_ip_risks(tmp_path: Path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Sep 21 03:20:10 kali sshd[1234]: "
        "Failed password for testuser from 192.168.1.50 port 22 ssh2\n"
        "Sep 21 03:20:20 kali sshd[1235]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n"
        "Sep 21 03:20:30 kali sshd[1236]: "
        "Failed password for root from 192.168.1.50 port 22 ssh2\n"
        "Sep 21 03:20:40 kali sshd[1237]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n"
        "Sep 21 03:21:02 kali sshd[1238]: "
        "Accepted password for admin from 192.168.1.50 port 22 ssh2\n"
        "Sep 21 03:22:10 kali sshd[1239]: "
        "Failed password for testuser from 10.0.0.25 port 22 ssh2\n"
    )

    result = analyze_log_file(str(log_file))

    assert result["parsed_events"] == 6

    ip_risks = result["ip_risk_assessment"]

    assert "192.168.1.50" in ip_risks
    assert "10.0.0.25" in ip_risks

    assert ip_risks["192.168.1.50"]["score"] == 80
    assert ip_risks["192.168.1.50"]["level"] == "high"

    assert ip_risks["10.0.0.25"]["score"] == 0
    assert ip_risks["10.0.0.25"]["level"] == "low"


def test_pipeline_handles_empty_log(tmp_path: Path):
    log_file = tmp_path / "empty.log"
    log_file.write_text("")

    result = analyze_log_file(str(log_file))

    assert result["total_lines"] == 0
    assert result["parsed_events"] == 0
    assert result["findings"] == []
    assert result["ip_summary"] == {}
    assert result["ip_risk_assessment"] == {}
    assert result["risk_assessment"]["score"] == 0
    assert result["risk_assessment"]["level"] == "low"
