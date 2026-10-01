"""Professional PDF report generator for TraceNox website assessments."""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
import json
import re
from collections.abc import Mapping

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)


NAVY = colors.HexColor("#14243A")
BLUE = colors.HexColor("#2563EB")
PALE_BLUE = colors.HexColor("#EFF6FF")
LIGHT = colors.HexColor("#F3F6FA")
DARK = colors.HexColor("#243247")
MUTED = colors.HexColor("#667085")
GREEN = colors.HexColor("#15803D")
AMBER = colors.HexColor("#B45309")
RED = colors.HexColor("#B91C1C")
BORDER = colors.HexColor("#D9E1EC")


def _plain(value):
    """Convert common scan result objects into printable Python data."""
    if value is None:
        return "Not provided"
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(v) for v in value]
    if hasattr(value, "__dict__"):
        return _plain(vars(value))
    return str(value)


def _safe_text(value, limit=1500):
    """Keep report text bounded and safe for ReportLab paragraphs."""
    from xml.sax.saxutils import escape

    text = str(value if value is not None else "Not provided")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    return escape(text[:limit]).replace("\n", "<br/>")


def _lookup(data, *names, default=None):
    if not isinstance(data, Mapping):
        return default
    lower = {str(k).lower().replace("-", "_"): v for k, v in data.items()}
    for name in names:
        key = name.lower().replace("-", "_")
        if key in lower and lower[key] is not None:
            return lower[key]
    return default


def _risk_label(result):
    explicit = _lookup(
        result, "risk_level", "overall_risk", "risk", "severity",
        "security_rating", default=""
    )
    if isinstance(explicit, Mapping):
        explicit = _lookup(explicit, "level", "label", "name", default="")
    if explicit:
        label = str(explicit).strip().upper()
        if any(x in label for x in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL")):
            return label
    findings = _lookup(result, "findings", "issues", "vulnerabilities", default=[])
    if not isinstance(findings, list):
        findings = []
    levels = []
    for item in findings:
        if isinstance(item, Mapping):
            level = str(_lookup(item, "severity", "risk", "level", default="")).upper()
            levels.append(level)
    if any("CRITICAL" in x for x in levels):
        return "CRITICAL"
    if any("HIGH" in x for x in levels):
        return "HIGH"
    if any("MEDIUM" in x for x in levels):
        return "MEDIUM"
    if any("LOW" in x for x in levels):
        return "LOW"
    if findings:
        return "REVIEW REQUIRED"
    return "NO FINDINGS REPORTED"


def _severity_color(label):
    label = str(label).upper()
    if "CRITICAL" in label or "HIGH" in label:
        return RED
    if "MEDIUM" in label:
        return AMBER
    if "LOW" in label:
        return GREEN
    if "PASS" in label or "SECURE" in label:
        return GREEN
    return BLUE


def _flatten(data, prefix="", depth=0, max_items=80):
    """Create readable key/value rows from nested scan results."""
    rows = []
    if depth > 4 or len(rows) >= max_items:
        return rows
    if isinstance(data, Mapping):
        for key, value in data.items():
            if len(rows) >= max_items:
                break
            label = f"{prefix} / {key}" if prefix else str(key)
            if isinstance(value, Mapping):
                rows.extend(_flatten(value, label, depth + 1, max_items - len(rows)))
            elif isinstance(value, list):
                if value and all(isinstance(x, Mapping) for x in value):
                    rows.append((label, f"{len(value)} item(s)"))
                else:
                    rows.append((label, ", ".join(map(str, value[:10]))[:500] or "None"))
            else:
                rows.append((label, str(value)[:1000]))
    elif isinstance(data, list):
        for index, value in enumerate(data[:max_items]):
            label = f"{prefix or 'Item'} {index + 1}"
            if isinstance(value, Mapping):
                rows.extend(_flatten(value, label, depth + 1, max_items - len(rows)))
            else:
                rows.append((label, str(value)[:1000]))
    else:
        rows.append((prefix or "Result", str(data)[:1000]))
    return rows[:max_items]


def _footer(canvas, doc):
    canvas.saveState()
    width, _ = A4
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, 15 * mm, width - 18 * mm, 15 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, "TraceNox | Website Security Assessment")
    canvas.drawRightString(width - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def create_pdf_report(result):
    """
    Generate a professional PDF from a TraceNox scan result.

    Returns PDF bytes, suitable for Flask send_file(BytesIO(...)).
    """
    data = _plain(result)
    if not isinstance(data, Mapping):
        data = {"scan_result": data}

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=22 * mm,
        title="TraceNox Website Security Assessment",
        author="Syed Shahriyar Ahmad",
        subject="Website security assessment report",
    )

    base = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TraceNoxTitle", parent=base["Title"], fontName="Helvetica-Bold",
        fontSize=23, leading=28, textColor=colors.white,
        alignment=TA_LEFT, spaceAfter=5,
    )
    subtitle_style = ParagraphStyle(
        "TraceNoxSubtitle", parent=base["Normal"], fontSize=10,
        leading=14, textColor=colors.HexColor("#DCE8F8"),
    )
    heading_style = ParagraphStyle(
        "TraceNoxHeading", parent=base["Heading2"], fontName="Helvetica-Bold",
        fontSize=13, leading=17, textColor=NAVY,
        spaceBefore=12, spaceAfter=7, keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "TraceNoxBody", parent=base["BodyText"], fontSize=9,
        leading=13, textColor=DARK, spaceAfter=5,
    )
    small_style = ParagraphStyle(
        "TraceNoxSmall", parent=base["BodyText"], fontSize=8,
        leading=11, textColor=MUTED,
    )
    cell_style = ParagraphStyle(
        "TraceNoxCell", parent=base["BodyText"], fontSize=8,
        leading=10, textColor=DARK, wordWrap="CJK",
    )
    label_style = ParagraphStyle(
        "TraceNoxLabel", parent=base["BodyText"], fontSize=8,
        leading=10, textColor=MUTED,
    )
    risk = _risk_label(data)
    target = _lookup(data, "target", "url", "domain", "website", "host", default="Not provided")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    findings = _lookup(data, "findings", "issues", "vulnerabilities", default=[])
    if not isinstance(findings, list):
        findings = []

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for item in findings:
        if isinstance(item, Mapping):
            severity = str(_lookup(item, "severity", "risk", "level", default="INFO")).upper()
            if "CRITICAL" in severity:
                counts["CRITICAL"] += 1
            elif "HIGH" in severity:
                counts["HIGH"] += 1
            elif "MEDIUM" in severity:
                counts["MEDIUM"] += 1
            elif "LOW" in severity:
                counts["LOW"] += 1
            else:
                counts["INFO"] += 1
        else:
            counts["INFO"] += 1

    story = []

    banner = Table(
        [[
            Paragraph("TraceNox", title_style),
            Paragraph("WEBSITE SECURITY<br/>ASSESSMENT", ParagraphStyle(
                "BannerRight", parent=subtitle_style, alignment=TA_LEFT,
                fontName="Helvetica-Bold", fontSize=10, leading=14
            )),
        ]],
        colWidths=[doc.width * 0.56, doc.width * 0.44],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 13),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 13),
    ]))
    story.extend([banner, Spacer(1, 8 * mm)])

    story.append(Paragraph("Assessment overview", heading_style))
    overview = [
        [Paragraph("<b>Target</b>", label_style), Paragraph(_safe_text(target, 400), body_style)],
        [Paragraph("<b>Generated</b>", label_style), Paragraph(_safe_text(timestamp), body_style)],
        [Paragraph("<b>Overall risk</b>", label_style),
         Paragraph(f'<font color="{_severity_color(risk).hexval()}"><b>{_safe_text(risk)}</b></font>', body_style)],
        [Paragraph("<b>Findings listed</b>", label_style), Paragraph(str(len(findings)), body_style)],
    ]
    overview_table = Table(overview, colWidths=[35 * mm, doc.width - 35 * mm])
    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(overview_table)

    story.append(Paragraph("Findings summary", heading_style))
    summary_cells = []
    for label, color in [
        ("CRITICAL", RED), ("HIGH", RED), ("MEDIUM", AMBER),
        ("LOW", GREEN), ("INFO", BLUE)
    ]:
        summary_cells.append(Paragraph(
            f'<font color="{color.hexval()}"><b>{label}</b></font><br/><font size="16"><b>{counts[label]}</b></font>',
            ParagraphStyle(f"Count{label}", parent=body_style, alignment=TA_CENTER, leading=20)
        ))
    summary = Table([summary_cells], colWidths=[doc.width / 5] * 5)
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE_BLUE),
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    story.append(summary)

    story.append(Paragraph("Detailed findings", heading_style))
    if findings:
        finding_rows = [[
            Paragraph("<b>Severity</b>", cell_style),
            Paragraph("<b>Finding</b>", cell_style),
            Paragraph("<b>Details</b>", cell_style),
        ]]
        for index, item in enumerate(findings[:100], 1):
            if isinstance(item, Mapping):
                severity = _lookup(item, "severity", "risk", "level", default="INFO")
                name = _lookup(item, "title", "name", "check", "finding", "issue", default=f"Finding {index}")
                details = _lookup(item, "description", "details", "message", "evidence", "recommendation", default="No additional details provided.")
                if isinstance(details, (Mapping, list)):
                    details = json.dumps(details, ensure_ascii=False, default=str)
            else:
                severity, name, details = "INFO", f"Finding {index}", item
            finding_rows.append([
                Paragraph(f'<font color="{_severity_color(severity).hexval()}"><b>{_safe_text(severity, 80)}</b></font>', cell_style),
                Paragraph(_safe_text(name, 300), cell_style),
                Paragraph(_safe_text(details, 1200), cell_style),
            ])
        finding_table = Table(
            finding_rows,
            colWidths=[24 * mm, 48 * mm, doc.width - 72 * mm],
            repeatRows=1,
        )
        finding_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(finding_table)
        if len(findings) > 100:
            story.append(Paragraph(
                f"Note: {len(findings) - 100} additional findings were omitted from this PDF for readability.",
                small_style
            ))
    else:
        story.append(Paragraph(
            "No structured findings list was provided by the scanner. "
            "Review the technical details below; absence of listed findings does not guarantee a website is secure.",
            body_style
        ))

    story.append(Paragraph("Technical scan details", heading_style))
    excluded = {"findings", "issues", "vulnerabilities"}
    technical = {k: v for k, v in data.items() if str(k).lower() not in excluded}
    technical_rows = _flatten(technical, max_items=60)
    if technical_rows:
        detail_data = [[
            Paragraph("<b>Property</b>", cell_style),
            Paragraph("<b>Value</b>", cell_style),
        ]]
        for key, value in technical_rows:
            detail_data.append([
                Paragraph(_safe_text(key, 200), cell_style),
                Paragraph(_safe_text(value, 1000), cell_style),
            ])
        detail_table = Table(detail_data, colWidths=[48 * mm, doc.width - 48 * mm], repeatRows=1)
        detail_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(detail_table)
    else:
        story.append(Paragraph("No additional technical details were supplied.", body_style))

    story.extend([
        Spacer(1, 8 * mm),
        HRFlowable(width="100%", thickness=0.8, color=BORDER),
        Spacer(1, 3 * mm),
        Paragraph("<b>Recommendations and responsible use</b>", heading_style),
        Paragraph(
            "Review every finding manually, validate evidence, and prioritize remediation based on "
            "business impact and exposure. A scan is a point-in-time assessment and cannot guarantee "
            "that a website is free of vulnerabilities. Only assess systems for which you have explicit authorization.",
            body_style,
        ),
        Spacer(1, 4 * mm),
        Paragraph("Project by Syed Shahriyar Ahmad", small_style),
        Paragraph("Generated by TraceNox | Evidence-driven security assessment", small_style),
    ])

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()
