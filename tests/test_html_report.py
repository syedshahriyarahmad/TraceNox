from html.parser import HTMLParser
from pathlib import Path

from tracenox.analyzer.pipeline import analyze_log_file
from tracenox.reporting.html_report import (
    generate_html_report,
    save_html_report,
)


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


def test_generate_html_report(tmp_path: Path):
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
    report = generate_html_report(result)

    parser = ReportParser()
    parser.feed(report)

    assert "TraceNox Security Report" in report
    assert "192.168.1.50" in report
    assert "HIGH" in report
    assert "Investigation Timeline" in report
    assert "table" in parser.tags
    assert "html" in parser.tags


def test_save_html_report(tmp_path: Path):
    output_file = tmp_path / "reports" / "report.html"
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

    save_html_report(result, str(output_file))

    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "No source IP activity found." in content


def test_html_report_displays_integrity_metadata():
    from tracenox.reporting.html_report import generate_html_report

    report = generate_html_report({
        "source_file": "sample.log",
        "total_lines": 2,
        "parsed_events": 1,
        "timeline": [],
        "findings": [],
        "ip_summary": {},
        "risk_assessment": {"score": 0, "level": "low", "reasons": []},
        "ip_risk_assessment": {},
        "integrity": {
            "generated_at_utc": "2026-09-29T12:00:00+00:00",
            "source": "sample.log",
            "source_sha256": "abc123",
            "hash_algorithm": "SHA-256",
            "parsed_events": 1,
            "findings_count": 0,
            "supporting_evidence_count": 0,
        },
    })

    assert "Integrity &amp; Reproducibility" in report
    assert "2026-09-29T12:00:00+00:00" in report
    assert "abc123" in report
    assert "Copy SHA-256" in report
