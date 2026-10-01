"""PDF report generation for TraceNox website assessments."""
from io import BytesIO
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
)

AUTHOR = "Project by Syed Shahriyar Ahmad"

def create_pdf_report(result):
    """Return a PDF byte string for a TraceNox scan result."""
    output = BytesIO()
    doc = SimpleDocTemplate(
        output, pagesize=A4,
        rightMargin=18*mm, leftMargin=18*mm,
        topMargin=18*mm, bottomMargin=22*mm,
        title="TraceNox Website Assessment",
        author="Syed Shahriyar Ahmad",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="TNTitle", parent=styles["Title"],
        alignment=TA_CENTER, textColor=colors.HexColor("#15365c"),
        spaceAfter=5*mm,
    ))
    styles.add(ParagraphStyle(
        name="TNSection", parent=styles["Heading2"],
        textColor=colors.HexColor("#15365c"), spaceBefore=4*mm,
        spaceAfter=2*mm,
    ))
    styles.add(ParagraphStyle(
        name="TNBody", parent=styles["BodyText"], leading=14,
        wordWrap="CJK",
    ))
    story = [
        Paragraph("TraceNox", styles["TNTitle"]),
        Paragraph("Website Security Assessment Report", styles["Heading2"]),
        Spacer(1, 4*mm),
    ]

    def safe(value):
        return escape(str(value if value is not None else "Not available"))

    def add(label, value):
        story.append(Paragraph(
            f"<b>{safe(label)}:</b> {safe(value)}", styles["TNBody"]
        ))
        story.append(Spacer(1, 1.5*mm))

    add("Target", result.get("target", result.get("url", "Not available")))
    add("Final URL", result.get("final_url", "Not available"))
    add("Scan time", result.get("scan_time", result.get("timestamp", "Not available")))
    add("Duration (seconds)", result.get("duration_seconds", "Not available"))
    add("HTTP status", result.get("status_code", result.get("http_status", "Not available")))
    add("Resolved addresses", ", ".join(map(str, result.get("resolved_addresses", []))) or "Not available")

    summary = result.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    findings = result.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    story.append(Paragraph("Severity Summary", styles["TNSection"]))
    severities = ["critical", "high", "medium", "low", "info"]
    counts = {s: summary.get(s, 0) for s in severities}
    if not any(counts.values()):
        for finding in findings:
            sev = str(finding.get("severity", "info")).lower()
            if sev in counts:
                counts[sev] += 1

    data = [["Severity", "Findings"]] + [
        [s.title(), str(counts[s])] for s in severities
    ]
    table = Table(data, colWidths=[70*mm, 35*mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#15365c")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.extend([table, Spacer(1, 4*mm)])

    story.append(Paragraph("Findings and Recommendations", styles["TNSection"]))
    if not findings:
        story.append(Paragraph("No findings were provided in the scan result.", styles["TNBody"]))
    for index, finding in enumerate(findings, 1):
        if not isinstance(finding, dict):
            continue
        block = [
            Paragraph(
                f"{index}. {safe(finding.get('title', 'Untitled finding'))}",
                styles["Heading3"],
            ),
            Paragraph(
                f"<b>Severity:</b> {safe(finding.get('severity', 'info'))}",
                styles["TNBody"],
            ),
            Paragraph(
                f"<b>Evidence:</b> {safe(finding.get('evidence', 'Not provided'))}",
                styles["TNBody"],
            ),
            Paragraph(
                f"<b>Recommendation:</b> {safe(finding.get('recommendation', 'Review manually'))}",
                styles["TNBody"],
            ),
            Spacer(1, 3*mm),
        ]
        story.append(KeepTogether(block))

    for section_key, title in [
        ("tls", "TLS Details"),
        ("redirect_chain", "Redirect Chain"),
        ("limitations", "Assessment Limitations"),
    ]:
        value = result.get(section_key)
        if value:
            story.append(Paragraph(title, styles["TNSection"]))
            if isinstance(value, dict):
                for k, v in value.items():
                    add(k.replace("_", " ").title(), v)
            elif isinstance(value, list):
                for item in value:
                    story.append(Paragraph(f"• {safe(item)}", styles["TNBody"]))
            else:
                story.append(Paragraph(safe(value), styles["TNBody"]))

    def footer(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.lightgrey)
        canvas.line(18*mm, 15*mm, A4[0]-18*mm, 15*mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#555555"))
        canvas.drawString(18*mm, 10*mm, AUTHOR)
        canvas.drawRightString(A4[0]-18*mm, 10*mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()
