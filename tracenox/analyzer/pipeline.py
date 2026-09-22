from tracenox.analyzer.log_reader import read_log_file
from tracenox.analyzer.ssh_parser import parse_ssh_line
from tracenox.detection.ssh_detection import detect_failed_login_burst


def analyze_log_file(file_path: str) -> dict:
    """Read, parse, and analyze an SSH log file."""

    lines = read_log_file(file_path)

    events = []

    for line in lines:
        event = parse_ssh_line(line)

        if event:
            events.append(event)

    findings = detect_failed_login_burst(events)

    return {
        "source_file": file_path,
        "total_lines": len(lines),
        "parsed_events": len(events),
        "findings": findings,
    }
