import html
import json
from pathlib import Path


def generate_html_report(result: dict) -> str:
    """Generate a standalone HTML investigation report."""

    escape = html.escape
    risk = result.get("risk_assessment", {})
    ip_summary = result.get("ip_summary", {})
    ip_risks = result.get("ip_risk_assessment", {})
    findings = result.get("findings", [])
    timeline = result.get("timeline", [])

    risk_level = str(risk.get("level", "unknown")).upper()
    risk_score = risk.get("score", 0)

    rows = []

    for source_ip, summary in sorted(ip_summary.items()):
        ip_risk = ip_risks.get(source_ip, {})
        level = str(ip_risk.get("level", "unknown")).upper()

        rows.append(
            "<tr>"
            f"<td>{escape(source_ip)}</td>"
            f"<td>{summary.get('total_events', 0)}</td>"
            f"<td>{summary.get('failed_logins', 0)}</td>"
            f"<td>{summary.get('successful_logins', 0)}</td>"
            f"<td>{ip_risk.get('score', 'N/A')}/100</td>"
            f"<td><span class='badge'>{escape(level)}</span></td>"
            "</tr>"
        )

    if not rows:
        rows.append("<tr><td colspan='6'>No source IP activity found.</td></tr>")

    finding_rows = []

    for finding in findings:
        finding_rows.append(
            "<tr>"
            f"<td>{escape(finding.get('detection', 'unknown'))}</td>"
            f"<td>{escape(finding.get('source_ip', 'unknown'))}</td>"
            f"<td>{escape(finding.get('severity', 'unknown').upper())}</td>"
            f"<td>{escape(str(finding.get('failed_attempts', 'N/A')))}</td>"
            "</tr>"
        )

    if not finding_rows:
        finding_rows.append("<tr><td colspan='4'>No findings detected.</td></tr>")

    timeline_rows = []

    for event in timeline:
        timeline_rows.append(
            "<tr>"
            f"<td>{escape(event.timestamp or 'unknown')}</td>"
            f"<td>{escape(event.event)}</td>"
            f"<td>{escape(event.username or 'unknown')}</td>"
            f"<td>{escape(event.source_ip or 'unknown')}</td>"
            "</tr>"
        )

    if not timeline_rows:
        timeline_rows.append("<tr><td colspan='4'>No security events found.</td></tr>")

    reason_items = "".join(
        f"<li>{escape(reason)}</li>"
        for reason in risk.get("reasons", [])
    ) or "<li>No significant risk evidence found.</li>"

    safe_source = escape(str(result.get("source_file", "unknown")))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TraceNox Security Report</title>
<style>
body {{
    font-family: system-ui, sans-serif;
    margin: 0;
    background: #f3f5f9;
    color: #182230;
}}
header {{
    background: #111827;
    color: white;
    padding: 28px max(20px, calc((100% - 1100px) / 2));
}}
main {{ max-width: 1100px; margin: 24px auto; padding: 0 18px; }}
.card {{
    background: white;
    padding: 20px;
    margin-bottom: 20px;
    border-radius: 12px;
    box-shadow: 0 2px 8px #0000000c;
    overflow-x: auto;
}}
.metrics {{ display: flex; gap: 16px; flex-wrap: wrap; }}
.metric {{ flex: 1; min-width: 150px; }}
.score {{ font-size: 30px; font-weight: 700; }}
.badge {{ font-weight: 700; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 11px; border-bottom: 1px solid #e5e7eb; text-align: left; }}
th {{ background: #f8fafc; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
footer {{ text-align: center; padding: 20px; color: #64748b; }}
</style>
</head>
<body>
<header>
    <h1>TraceNox Security Report</h1>
    <div>Evidence-Driven Cybersecurity Investigation Toolkit</div>
</header>
<main>
<section class="card metrics">
    <div class="metric">
        <h3>Overall Risk</h3>
        <div class="score">{risk_score}/100</div>
        <div>{escape(risk_level)}</div>
    </div>
    <div class="metric">
        <h3>Parsed Events</h3>
        <div class="score">{result.get('parsed_events', 0)}</div>
    </div>
    <div class="metric">
        <h3>Source IPs</h3>
        <div class="score">{len(ip_summary)}</div>
    </div>
    <div class="metric">
        <h3>Findings</h3>
        <div class="score">{len(findings)}</div>
    </div>
</section>

<section class="card">
    <h2>Investigation Details</h2>
    <p><strong>Source file:</strong> {safe_source}</p>
    <p><strong>Total log lines:</strong> {result.get('total_lines', 0)}</p>
    <h3>Overall risk evidence</h3>
    <ul>{reason_items}</ul>
    <p><strong>Note:</strong> Rule-based risk scores indicate investigation priority;
    they do not independently prove malicious activity.</p>
</section>

<section class="card">
    <h2>IP Investigation Summary</h2>
    <table>
        <thead><tr>
            <th>Source IP</th><th>Events</th><th>Failed</th>
            <th>Successful</th><th>Risk Score</th><th>Risk Level</th>
        </tr></thead>
        <tbody>{''.join(rows)}</tbody>
    </table>
</section>

<section class="card">
    <h2>Findings</h2>
    <table>
        <thead><tr>
            <th>Detection</th><th>Source IP</th>
            <th>Severity</th><th>Failed Attempts</th>
        </tr></thead>
        <tbody>{''.join(finding_rows)}</tbody>
    </table>
</section>

<section class="card">
    <h2>Investigation Timeline</h2>
    <table>
        <thead><tr>
            <th>Timestamp</th><th>Event</th>
            <th>Username</th><th>Source IP</th>
        </tr></thead>
        <tbody>{''.join(timeline_rows)}</tbody>
    </table>
</section>
</main>
<footer>Generated by TraceNox</footer>
</body>
</html>
"""


def save_html_report(result: dict, output_path: str) -> None:
    """Save the standalone HTML report."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        generate_html_report(result),
        encoding="utf-8",
    )
