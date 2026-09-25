def generate_text_report(result: dict) -> str:
    """Generate a human-readable TraceNox security report."""

    lines = [
        "",
        "========================================",
        "          TRACENOX SECURITY REPORT",
        "========================================",
        f"Source file    : {result['source_file']}",
        f"Total lines    : {result['total_lines']}",
        f"Parsed events  : {result['parsed_events']}",
        "",
        "INVESTIGATION TIMELINE",
        "----------------------------------------",
    ]

    timeline = result.get("timeline", [])

    if not timeline:
        lines.append("No security events found.")

    else:
        for event in timeline:
            lines.append(
                f"{event.timestamp or 'unknown'}  "
                f"{event.event:<24} "
                f"{event.username or 'unknown':<12} "
                f"{event.source_ip or 'unknown'}"
            )

    lines.extend(
        [
            "",
            "FINDINGS",
            "----------------------------------------",
        ]
    )

    findings = result.get("findings", [])

    if not findings:
        lines.append("No suspicious activity detected.")

    else:
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"[{index}] Detection     : {finding['detection']}",
                    f"    Source IP      : {finding['source_ip']}",
                    f"    Failed attempts: {finding['failed_attempts']}",
                    f"    Threshold      : {finding['threshold']}",
                ]
            )

            if finding["detection"] == "ssh_failed_then_success":
                lines.extend(
                    [
                        f"    Username       : {finding.get('username', 'unknown')}",
                        f"    First failed at: {finding.get('first_failed_at', 'unknown')}",
                        f"    Successful at  : {finding.get('successful_login_at', 'unknown')}",
                    ]
                )

            lines.extend(
                [
                    f"    Severity       : {finding['severity'].upper()}",
                    "",
                ]
            )

    lines.append("========================================")

    return "\n".join(lines)
