from tracenox.analyzer.ip_summary import build_ip_summary
from tracenox.analyzer.log_reader import read_log_file
from tracenox.analyzer.ssh_parser import parse_ssh_line
from tracenox.analyzer.timeline import build_timeline
from tracenox.detection.risk_scoring import calculate_risk_score
from tracenox.detection.ssh_detection import (
    detect_failed_login_burst,
    detect_failed_then_success,
)


def analyze_log_file(file_path: str) -> dict:
    """Read, parse, order, and analyze an SSH log."""

    lines = read_log_file(file_path)
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

    risk_assessment = calculate_risk_score(
        timeline,
        findings,
    )

    # Calculate a separate risk score for each source IP.
    ip_risk_assessment = {}

    source_ips = {
        event.source_ip
        for event in timeline
        if event.source_ip
    }

    for source_ip in sorted(source_ips):
        ip_events = [
            event
            for event in timeline
            if event.source_ip == source_ip
        ]

        ip_findings = [
            finding
            for finding in findings
            if finding.get("source_ip") == source_ip
        ]

        ip_risk_assessment[source_ip] = calculate_risk_score(
            ip_events,
            ip_findings,
        )

    return {
        "source_file": file_path,
        "total_lines": len(lines),
        "parsed_events": len(timeline),
        "timeline": timeline,
        "findings": findings,
        "ip_summary": ip_summary,
        "risk_assessment": risk_assessment,
        "ip_risk_assessment": ip_risk_assessment,
    }
