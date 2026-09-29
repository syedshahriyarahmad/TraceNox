"""TraceNox analysis pipeline."""

from pathlib import Path

from tracenox.analyzer.evidence import attach_evidence_to_findings
from tracenox.analyzer.integrity import build_integrity_metadata
from tracenox.analyzer.ip_summary import build_ip_summary
from tracenox.analyzer.log_reader import read_journal_lines, read_log_file
from tracenox.analyzer.ssh_parser import parse_ssh_line
from tracenox.analyzer.timeline import build_timeline
from tracenox.detection.risk_scoring import calculate_risk_score
from tracenox.detection.ssh_detection import (
    detect_failed_login_burst,
    detect_failed_then_success,
)


def _analyze_lines(
    lines: list[str],
    source_file: str,
    source_bytes: bytes | None = None,
) -> dict:
    """Analyze log lines and attach integrity metadata."""
    events = []

    for line in lines:
        event = parse_ssh_line(line)
        if event:
            events.append(event)

    timeline = build_timeline(events)

    findings = []
    findings.extend(detect_failed_login_burst(timeline))
    findings.extend(detect_failed_then_success(timeline))
    findings = attach_evidence_to_findings(findings, timeline)

    ip_summary = build_ip_summary(timeline)
    risk_assessment = calculate_risk_score(timeline, findings)

    ip_risk_assessment = {}
    source_ips = {
        event.source_ip for event in timeline if event.source_ip
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
            ip_events, ip_findings
        )

    if source_bytes is None:
        source_bytes = "\n".join(lines).encode("utf-8")

    integrity = build_integrity_metadata(
        source_file=source_file,
        source_bytes=source_bytes,
        parsed_events=len(timeline),
        findings=findings,
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
        "integrity": integrity,
    }


def analyze_log_file(file_path: str) -> dict:
    """Analyze a log file and hash its original bytes."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {file_path}")

    source_bytes = path.read_bytes()
    lines = read_log_file(file_path)

    return _analyze_lines(
        lines=lines,
        source_file=file_path,
        source_bytes=source_bytes,
    )


def analyze_journal(unit: str = "ssh", since: str = "today") -> dict:
    """Analyze systemd journal output and hash the captured text."""
    lines = read_journal_lines(unit=unit, since=since)
    source = f"systemd journal: unit={unit}, since={since}"

    return _analyze_lines(
        lines=lines,
        source_file=source,
        source_bytes="\n".join(lines).encode("utf-8"),
    )
