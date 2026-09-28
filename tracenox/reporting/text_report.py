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
        "RISK ASSESSMENT",
        "----------------------------------------",
    ]

    risk_assessment = result.get("risk_assessment", {})

    if risk_assessment:
        lines.extend(
            [
                f"Risk score     : {risk_assessment.get('score', 0)}/100",
                f"Risk level     : {risk_assessment.get('level', 'unknown').upper()}",
                "",
                "Evidence:",
            ]
        )

        reasons = risk_assessment.get("reasons", [])
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

    risk_assessment = result.get("risk_assessment", {})

    if risk_assessment:
        lines.extend(
            [
                f"Risk score     : {risk_assessment.get('score', 0)}/100",
                f"Risk level     : {risk_assessment.get('level', 'unknown').upper()}",
                "",
                "Evidence:",
            ]
        )

        reasons = risk_assessment.get("reasons", [])

        if reasons:
            for reason in reasons:
                lines.append(f"- {reason}")
        else:
            lines.append("- No significant risk evidence found.")
    else:
        lines.append("Risk assessment unavailable.")

    lines.extend(
        [
            "",
            "IP INVESTIGATION SUMMARY",
            "----------------------------------------",
        ]
    )

    ip_summary = result.get("ip_summary", {})
    ip_risks = result.get("ip_risk_assessment", {})

    if not ip_summary:
        lines.append("No source IP activity found.")
    else:
        for source_ip, summary in ip_summary.items():
            ip_risk = ip_risks.get(source_ip, {})

            lines.extend(
                [
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
                ]
            )

            ip_reasons = ip_risk.get("reasons", [])

            if ip_reasons:
                for reason in ip_reasons:
                    lines.append(f"  - {reason}")
            else:
                lines.append("  - No significant risk evidence found.")

    lines.extend(
        [
            "",
            "INVESTIGATION TIMELINE",
            "----------------------------------------",
        ]
    )

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

            if finding["detection"] == "ssh_failed_login_burst":
                lines.extend(
                    [
                        f"    Window         : {finding.get('window_minutes', 'unknown')} minutes",
                        f"    First failed at: {finding.get('first_failed_at', 'unknown')}",
                        f"    Last failed at : {finding.get('last_failed_at', 'unknown')}",
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
