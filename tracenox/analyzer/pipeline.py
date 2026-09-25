from tracenox.analyzer.log_reader import read_log_file
from tracenox.analyzer.ssh_parser import parse_ssh_line
from tracenox.analyzer.timeline import build_timeline
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

    findings.extend(
        detect_failed_login_burst(timeline)
    )

    findings.extend(
        detect_failed_then_success(timeline)
    )

    return {
        "source_file": file_path,
        "total_lines": len(lines),
        "parsed_events": len(timeline),
        "timeline": timeline,
        "findings": findings,
    }
