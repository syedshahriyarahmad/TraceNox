import html
from pathlib import Path


def generate_html_report(result: dict) -> str:
    """Generate a standalone HTML investigation report."""
    escape = html.escape
    risk = result.get("risk_assessment", {})
    ip_summary = result.get("ip_summary", {})
    ip_risks = result.get("ip_risk_assessment", {})
    correlated_ip_risk = result.get("correlated_ip_risk", {})
    ip_reputation = result.get("ip_reputation", {})
    findings = result.get("findings", [])
    timeline = result.get("timeline", [])
    integrity = result.get("integrity", {})

    ip_rows = []
    for source_ip, summary in sorted(ip_summary.items()):
        ip_risk = ip_risks.get(source_ip, {})
        correlation = correlated_ip_risk.get(source_ip, {})
        ip_rows.append(
            "<tr>"
            f"<td>{escape(str(source_ip))}</td>"
            f"<td>{summary.get('total_events', 0)}</td>"
            f"<td>{summary.get('failed_logins', 0)}</td>"
            f"<td>{summary.get('successful_logins', 0)}</td>"
            f"<td>{escape(str(ip_risk.get('score', 'N/A')))}/100</td>"
            f"<td>{escape(str(ip_risk.get('level', 'unknown')).upper())}</td>"
            f"<td>{escape(str(correlation.get('score', ip_risk.get('score', 'N/A'))))}/100</td>"
            f"<td>{escape(str(correlation.get('level', ip_risk.get('level', 'unknown'))).upper())}</td>"
            f"<td>{escape(str(correlation.get('status', 'local_only')).replace('_', ' ').title())}</td>"
            "</tr>"
        )

    if not ip_rows:
        ip_rows.append(
            "<tr><td colspan='9'>No source IP activity found.</td></tr>"
        )

    reputation_rows = []
    for source_ip, reputation in sorted(ip_reputation.items()):
        reputation = reputation if isinstance(reputation, dict) else {}
        reputation_rows.append(
            "<tr>"
            f"<td>{escape(str(reputation.get('ip_address', source_ip)))}</td>"
            f"<td>{escape(str(reputation.get('status', 'unknown')).replace('_', ' ').title())}</td>"
            f"<td>{escape(str(reputation.get('abuse_confidence_score', 'N/A')))}</td>"
            f"<td>{escape(str(reputation.get('total_reports', 'N/A')))}</td>"
            f"<td>{escape(str(reputation.get('country_code') or 'N/A'))}</td>"
            f"<td>{escape(str(reputation.get('isp') or 'N/A'))}</td>"
            f"<td>{escape(str(reputation.get('reason') or reputation.get('message') or 'N/A'))}</td>"
            "</tr>"
        )

    if not reputation_rows:
        reputation_rows.append(
            "<tr><td colspan='7'>"
            "No IP reputation data available. Use --ip-reputation to request "
            "lookups for eligible public IP addresses."
            "</td></tr>"
        )

    finding_rows = []
    for finding in findings:
        evidence = finding.get("evidence", [])
        evidence_html = "".join(
            "<div class='evidence'>"
            f"<strong>{escape(str(item.get('timestamp') or 'unknown'))}</strong> "
            f"{escape(str(item.get('event') or 'unknown'))}<br>"
            f"<code>{escape(str(item.get('raw_log') or ''))}</code>"
            "</div>"
            for item in evidence
        )
        if not evidence_html:
            evidence_html = "<em>No supporting log evidence available.</em>"

        finding_rows.append(
            "<tr>"
            f"<td>{escape(str(finding.get('detection', 'unknown')))}</td>"
            f"<td>{escape(str(finding.get('source_ip', 'unknown')))}</td>"
            f"<td>{escape(str(finding.get('severity', 'unknown')).upper())}</td>"
            f"<td>{escape(str(finding.get('failed_attempts', 'N/A')))}</td>"
            f"<td>{finding.get('evidence_count', len(evidence))}</td>"
            f"<td>{evidence_html}</td>"
            "</tr>"
        )

    if not finding_rows:
        finding_rows.append(
            "<tr><td colspan='6'>No findings detected.</td></tr>"
        )

    timeline_rows = []
    for event in timeline:
        timeline_rows.append(
            "<tr>"
            f"<td>{escape(str(event.timestamp or 'unknown'))}</td>"
            f"<td>{escape(str(event.event))}</td>"
            f"<td>{escape(str(event.username or 'unknown'))}</td>"
            f"<td>{escape(str(event.source_ip or 'unknown'))}</td>"
            f"<td><code>{escape(str(event.raw_log))}</code></td>"
            "</tr>"
        )

    if not timeline_rows:
        timeline_rows.append(
            "<tr><td colspan='5'>No security events found.</td></tr>"
        )

    reasons = "".join(
        f"<li>{escape(str(reason))}</li>"
        for reason in risk.get("reasons", [])
    ) or "<li>No significant risk evidence found.</li>"

    source_hash = integrity.get("source_sha256")
    if source_hash:
        hash_display = (
            f"<code class='hash' id='source-hash'>{escape(str(source_hash))}</code>"
            "<button type='button' class='copy-button' "
            "onclick=\"navigator.clipboard.writeText("
            "document.getElementById('source-hash').textContent)"
            ".then(()=>this.textContent='Copied')"
            ".catch(()=>this.textContent='Copy failed')\">"
            "Copy SHA-256</button>"
        )
    else:
        hash_display = "<em>Integrity metadata unavailable.</em>"

    integrity_rows = [
        ("Generated at (UTC)", integrity.get("generated_at_utc", "Unavailable")),
        ("Source", integrity.get("source", result.get("source_file", "unknown"))),
        ("Hash algorithm", integrity.get("hash_algorithm", "Unavailable")),
        ("Parsed events", integrity.get("parsed_events", result.get("parsed_events", 0))),
        ("Findings count", integrity.get("findings_count", len(findings))),
        (
            "Supporting evidence count",
            integrity.get(
                "supporting_evidence_count",
                sum(len(f.get("evidence", [])) for f in findings),
            ),
        ),
    ]

    integrity_table_rows = "".join(
        "<tr>"
        f"<th>{escape(str(label))}</th>"
        f"<td>{escape(str(value))}</td>"
        "</tr>"
        for label, value in integrity_rows
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TraceNox Security Report</title>
<style>
body {{font-family:system-ui,sans-serif;margin:0;background:#f3f5f9;color:#182230}}
header {{background:#111827;color:white;padding:28px max(20px,calc((100% - 1150px)/2))}}
main {{max-width:1150px;margin:24px auto;padding:0 18px}}
.card {{background:white;padding:20px;margin-bottom:20px;border-radius:12px;box-shadow:0 2px 8px #0000000c;overflow-x:auto}}
.metrics {{display:flex;gap:16px;flex-wrap:wrap}}
.metric {{flex:1;min-width:140px}}
.score {{font-size:30px;font-weight:700}}
table {{width:100%;border-collapse:collapse}}
th,td {{padding:11px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}}
th {{background:#f8fafc}}
code {{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}}
.hash {{display:block;word-break:break-all;padding:12px;background:#f1f5f9;border-radius:6px}}
.evidence {{padding:8px;margin:4px 0;background:#f8fafc;border-radius:6px;min-width:240px}}
.copy-button {{margin-top:8px;padding:8px 12px;border:0;border-radius:6px;background:#1d4ed8;color:white;cursor:pointer}}
footer {{text-align:center;padding:20px;color:#64748b}}
.note {{color:#475569;font-size:14px}}
</style>
</head>
<body>
<header>
<h1>TraceNox Security Report</h1>
<div>Evidence-Driven Cybersecurity Investigation Toolkit</div>
</header>
<main>
<section class="card metrics">
<div class="metric"><h3>Overall Risk</h3><div class="score">{risk.get('score', 0)}/100</div><div>{escape(str(risk.get('level', 'unknown')).upper())}</div></div>
<div class="metric"><h3>Parsed Events</h3><div class="score">{result.get('parsed_events', 0)}</div></div>
<div class="metric"><h3>Source IPs</h3><div class="score">{len(ip_summary)}</div></div>
<div class="metric"><h3>Findings</h3><div class="score">{len(findings)}</div></div>
</section>

<section class="card">
<h2>Investigation Details</h2>
<p><strong>Source:</strong> {escape(str(result.get('source_file', 'unknown')))}</p>
<p><strong>Total log lines:</strong> {result.get('total_lines', 0)}</p>
<h3>Overall risk evidence</h3><ul>{reasons}</ul>
<p>Rule-based risk scores indicate investigation priority; they do not independently prove malicious activity.</p>
</section>

<section class="card">
<h2>Integrity &amp; Reproducibility</h2>
<p>Metadata recorded during analysis. The hash identifies the analyzed input bytes; it does not by itself prove that the input is authentic or unchanged since collection.</p>
<h3>Source SHA-256</h3>
{hash_display}
<table>
<thead><tr><th>Metadata</th><th>Value</th></tr></thead>
<tbody>{integrity_table_rows}</tbody>
</table>
</section>

<section class="card">
<h2>IP Investigation Summary</h2>
<table>
<thead><tr><th>Source IP</th><th>Events</th><th>Failed</th><th>Successful</th><th>Local Risk Score</th><th>Local Risk Level</th><th>Correlated Score</th><th>Correlated Level</th><th>Correlation Status</th></tr></thead>
<tbody>{''.join(ip_rows)}</tbody>
</table>
</section>

<section class="card">
<h2>IP Risk Correlation</h2>
<p class="note">When provider data is available, the correlated score uses 60% local behavior and 40% AbuseIPDB confidence, with up to 10 additional corroboration points when both signals are elevated. Without usable provider data, the local score is retained. This is a triage heuristic, not proof of malicious activity.</p>
<h2>IP Reputation Intelligence</h2>
<p class="note">External reputation results are contextual intelligence, not proof that an address is malicious. Results depend on provider data, lookup status, and availability.</p>
<table>
<thead><tr><th>IP Address</th><th>Status</th><th>Abuse Score</th><th>Total Reports</th><th>Country</th><th>ISP</th><th>Details</th></tr></thead>
<tbody>{''.join(reputation_rows)}</tbody>
</table>
</section>

<section class="card">
<h2>Findings and Supporting Evidence</h2>
<table>
<thead><tr><th>Detection</th><th>Source IP</th><th>Severity</th><th>Failed Attempts</th><th>Evidence Count</th><th>Original Log Evidence</th></tr></thead>
<tbody>{''.join(finding_rows)}</tbody>
</table>
</section>

<section class="card">
<h2>Investigation Timeline</h2>
<table>
<thead><tr><th>Timestamp</th><th>Event</th><th>Username</th><th>Source IP</th><th>Original Log Line</th></tr></thead>
<tbody>{''.join(timeline_rows)}</tbody>
</table>
</section>
</main>
<footer>Generated by TraceNox</footer>
</body>
</html>
"""


def save_html_report(result: dict, output_path: str) -> None:
    """Save the standalone HTML investigation report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(generate_html_report(result), encoding="utf-8")
