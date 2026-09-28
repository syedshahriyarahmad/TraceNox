import json

from tracenox.analyzer.pipeline import analyze_log_file
from tracenox.reporting.json_report import (
    generate_json_report,
    save_json_report,
)


def test_generate_json_report(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Sep 21 03:20:10 kali sshd[1234]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n"
        "Sep 21 03:20:20 kali sshd[1235]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n"
        "Sep 21 03:20:30 kali sshd[1236]: "
        "Failed password for root from 192.168.1.50 port 22 ssh2\n"
        "Sep 21 03:20:40 kali sshd[1237]: "
        "Failed password for admin from 192.168.1.50 port 22 ssh2\n"
        "Sep 21 03:21:02 kali sshd[1238]: "
        "Accepted password for admin from 192.168.1.50 port 22 ssh2\n"
    )

    result = analyze_log_file(str(log_file))
    report = generate_json_report(result)
    parsed = json.loads(report)

    assert parsed["parsed_events"] == 5
    assert parsed["risk_assessment"]["level"] == "high"
    assert parsed["ip_risk_assessment"]["192.168.1.50"]["level"] == "high"
    assert len(parsed["timeline"]) == 5
    assert parsed["findings"]


def test_save_json_report(tmp_path):
    output_file = tmp_path / "reports" / "investigation.json"

    result = {
        "source_file": "auth.log",
        "total_lines": 0,
        "parsed_events": 0,
        "timeline": [],
        "findings": [],
        "ip_summary": {},
        "risk_assessment": {
            "score": 0,
            "level": "low",
            "reasons": [],
        },
        "ip_risk_assessment": {},
    }

    save_json_report(result, str(output_file))

    assert output_file.exists()

    saved_data = json.loads(output_file.read_text(encoding="utf-8"))

    assert saved_data["source_file"] == "auth.log"
    assert saved_data["risk_assessment"]["score"] == 0
    assert saved_data["timeline"] == []
