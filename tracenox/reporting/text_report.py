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
        "FINDINGS",
        "----------------------------------------",
    ]

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
                    f"    Severity       : {finding['severity'].upper()}",
                    "",
                ]
            )

    lines.append("========================================")

    return "\n".join(lines)
