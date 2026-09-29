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
        "OVERALL RISK ASSESSMENT",
        "----------------------------------------",
    ]

    risk = result.get("risk_assessment", {})
    if risk:
        lines.extend([
            f"Risk score     : {risk.get('score', 0)}/100",
            f"Risk level     : {risk.get('level', 'unknown').upper()}",
            "",
            "Evidence:",
        ])
        reasons = risk.get("reasons", [])
        lines.extend(
            [f"- {reason}" for reason in reasons]
            if reasons else ["- No significant risk evidence found."]
        )
    else:
        lines.append("Risk assessment unavailable.")

    lines.extend(["", "IP INVESTIGATION SUMMARY", "----------------------------------------"])
    ip_summary = result.get("ip_summary", {})
    ip_risks = result.get("ip_risk_assessment", {})

    if not ip_summary:
        lines.append("No source IP activity found.")
    else:
        for source_ip, summary in ip_summary.items():
            ip_risk = ip_risks.get(source_ip, {})
            lines.extend([
                "",
                f"Source IP       : {source_ip}",
                f"Total events    : {summary['total_events']}",
                f"Failed logins   : {summary['failed_logins']}",
                f"Successful      : {summary['successful_logins']}",
                f"Usernames       : {', '.join(summary['usernames']) or 'none'}",
                f"First seen      : {summary['first_seen'] or 'unknown'}",
                f"Last seen       : {summary['last_seen'] or 'unknown'}",
                f"IP risk score   : {ip_risk.get('score', 'N/A')}/100",
                f"IP risk level   : {str(ip_risk.get('level', 'unknown')).upper()}",
                "IP risk evidence:",
            ])
            reasons = ip_risk.get("reasons", [])
            lines.extend(
                [f"  - {reason}" for reason in reasons]
                if reasons else ["  - No significant risk evidence found."]
            )

    lines.extend(["", "INVESTIGATION TIMELINE", "----------------------------------------"])
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
            lines.append(f"    Raw evidence: {event.raw_log}")

    lines.extend(["", "FINDINGS", "----------------------------------------"])
    findings = result.get("findings", [])

    if not findings:
        lines.append("No suspicious activity detected.")
    else:
        for index, finding in enumerate(findings, start=1):
            lines.extend([
                f"[{index}] Detection     : {finding.get('detection', 'unknown')}",
                f"    Source IP      : {finding.get('source_ip', 'unknown')}",
                f"    Failed attempts: {finding.get('failed_attempts', 'N/A')}",
                f"    Severity       : {str(finding.get('severity', 'unknown')).upper()}",
                f"    Evidence count : {finding.get('evidence_count', 0)}",
            ])

            if finding.get("window_minutes") is not None:
                lines.append(
                    f"    Window         : {finding['window_minutes']} minutes"
                )
            if finding.get("username"):
                lines.append(f"    Username       : {finding['username']}")

            evidence = finding.get("evidence", [])
            if evidence:
                lines.append("    Supporting log evidence:")
                for item in evidence:
                    lines.append(
                        f"      [{item.get('timestamp') or 'unknown'}] "
                        f"{item.get('raw_log', '')}"
                    )
            else:
                lines.append("    Supporting log evidence: none available")
            lines.append("")

    lines.append("========================================")
    return "\n".join(lines)
