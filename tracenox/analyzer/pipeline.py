from tracenox.analyzer.ip_summary import build_ip_summary
from tracenox.analyzer.log_reader import read_journal_lines, read_log_file
from tracenox.analyzer.ssh_parser import parse_ssh_line
from tracenox.analyzer.timeline import build_timeline
from tracenox.detection.risk_scoring import calculate_risk_score
from tracenox.detection.ssh_detection import (
    detect_failed_login_burst,
    detect_failed_then_success,
)


def _analyze_lines(lines: list[str], source_file: str) -> dict:
    """Analyze supplied log lines and correlate security evidence."""
    events = []

    for line in lines:
        event = parse_ssh_line(line)
        if event:
            events.append(event)

    timeline = build_timeline(events)

    findings = []
    findings.extend(detect_failed_login_burst(timeline))
    findings.extend(detect_failed_then_success(timeline))

    ip_summary = build_ip_summary(timeline)
    risk_assessment = calculate_risk_score(timeline, findings)

    ip_risk_assessment = {}
    source_ips = {
        event.source_ip
        for event in timeline
        if event.source_ip
    }

    for source_ip in sorted(source_ips):
        ip_events = [
            event for event in timeline
            if event.source_ip == source_ip
        ]
        ip_findings = [
            finding for finding in findings
            if finding.get("source_ip") == source_ip
        ]

        ip_risk_assessment[source_ip] = calculate_risk_score(
            ip_events,
            ip_findings,
        )

    return {
        "source_file": source_file,
        "total_lines": len(lines),
        "parsed_events": len(timeline),
        "timeline": timeline,
        "findings": findings,
        "ip_summary": ip_summary,
        "risk_assessment": risk_assessment,
        "ip_risk_assessment": ip_risk_assessment,
    }


def analyze_log_file(file_path: str) -> dict:
    """Analyze a log file."""
    lines = read_log_file(file_path)
    return _analyze_lines(lines, file_path)


def analyze_journal(unit: str = "ssh", since: str = "today") -> dict:
    """Analyze real systemd journal entries for a systemd unit."""
    lines = read_journal_lines(unit=unit, since=since)
    source = f"systemd journal: unit={unit}, since={since}"
    return _analyze_lines(lines, source)
