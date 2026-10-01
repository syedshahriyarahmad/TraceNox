"""Loopback-only local browser interface for TraceNox."""
from __future__ import annotations

import secrets
from flask import Flask, request, render_template_string, send_file, abort
from io import BytesIO

from tracenox.webscan import normalize_url, scan_website
from tracenox.pdf_report import create_pdf_report

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096
_reports = {}

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TraceNox | Website Assessment</title>
<style>
body{font-family:system-ui,Arial,sans-serif;max-width:1000px;margin:35px auto;padding:0 18px;background:#f4f7fb;color:#17243a}
header,.panel{background:white;border-radius:12px;padding:22px;margin-bottom:18px;box-shadow:0 3px 14px #152b4810}
h1{margin:0;color:#15365c} .muted{color:#596579}
input[type=url]{box-sizing:border-box;width:100%;padding:13px;border:1px solid #b8c5d5;border-radius:8px;margin:10px 0}
button,.download{display:inline-block;background:#15365c;color:white;padding:11px 17px;border:0;border-radius:8px;text-decoration:none;cursor:pointer}
.warning{background:#fff5dc;padding:12px;border-radius:8px}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:9px;border-bottom:1px solid #dce3eb}
.error{color:#a21d28;background:#fff0f0;padding:12px;border-radius:8px}
</style></head>
<body>
<header><h1>TraceNox</h1><p class="muted">Website Security Assessment · Local interface</p>
<p class="warning">Only scan domains you own or have explicit permission to assess. This is a low-impact assessment, not a full penetration test.</p>
<form method="post" action="/scan">
<label for="url"><b>Public website URL or domain</b></label>
<input id="url" name="url" type="url" placeholder="https://your-domain.example" required>
<button type="submit">Generate Report</button>
</form></header>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
{% if result %}
<section class="panel"><h2>Assessment Summary</h2>
<p><b>Target:</b> {{ target }}</p>
{% if summary %}
<table><tr><th>Severity</th><th>Count</th></tr>
{% for severity,count in summary.items() %}<tr><td>{{ severity|title }}</td><td>{{ count }}</td></tr>{% endfor %}
</table>{% endif %}
<h3>Findings</h3>
{% if findings %}
<table><tr><th>Severity</th><th>Finding</th><th>Evidence</th></tr>
{% for f in findings %}<tr><td>{{ f.get('severity','info')|title }}</td><td>{{ f.get('title','Untitled') }}</td><td>{{ f.get('evidence','') }}</td></tr>{% endfor %}
</table>
{% else %}<p>No findings were returned by the scanner.</p>{% endif %}
<p><a class="download" href="/download/{{ token }}">Download PDF Report</a></p>
</section>
{% endif %}
<footer class="muted">Project by Syed Shahriyar Ahmad</footer>
</body></html>"""

@app.get("/")
def home():
    return render_template_string(PAGE, result=None, error=None)

@app.post("/scan")
def scan():
    raw_url = request.form.get("url", "")
    try:
        target = normalize_url(raw_url)
        # Scanner resolves and validates public addresses before connecting.
        result = scan_website(target)
        if not isinstance(result, dict):
            raise ValueError("Scanner returned an unexpected result.")
        result.setdefault("target", target)
        findings = result.get("findings", [])
        summary = result.get("summary", {})
        token = secrets.token_urlsafe(24)
        _reports[token] = result
        # Keep the local in-memory store bounded.
        while len(_reports) > 10:
            _reports.pop(next(iter(_reports)))
        return render_template_string(
            PAGE, result=result, target=target, findings=findings,
            summary=summary, token=token, error=None
        )
    except (ValueError, OSError, TimeoutError) as exc:
        return render_template_string(PAGE, result=None, error=str(exc)), 400
    except Exception:
        app.logger.exception("Website assessment failed")
        return render_template_string(
            PAGE, result=None,
            error="Assessment failed. Check the terminal for diagnostic details."
        ), 500

@app.get("/download/<token>")
def download(token):
    result = _reports.get(token)
    if result is None:
        abort(404)
    pdf = create_pdf_report(result)
    return send_file(
        BytesIO(pdf), mimetype="application/pdf",
        as_attachment=True, download_name="tracenox-assessment.pdf",
        max_age=0,
    )

def main():
    # Intentionally bind only to loopback; do not expose this UI to a network.
    app.run(host="127.0.0.1", port=5050, debug=False)

if __name__ == "__main__":
    main()
