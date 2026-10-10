"""Loopback-only local browser interface for TraceNox."""
from __future__ import annotations

import secrets
from flask import Flask, request, render_template_string, send_file, abort
from io import BytesIO
from pathlib import Path

from tracenox.webscan import normalize_url, scan_website
from tracenox.pdf_report import create_pdf_report
from tracenox.history import compare_snapshot_files, save_comparison, format_comparison

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
<p><a href="/history">Historical Score Comparison</a></p>
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


HISTORY_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TraceNox | Historical Comparison</title>
<style>
body{font-family:system-ui,Arial,sans-serif;max-width:1000px;margin:35px auto;padding:0 18px;background:#f4f7fb;color:#17243a}
header,.panel{background:white;border-radius:12px;padding:22px;margin-bottom:18px;box-shadow:0 3px 14px #152b4810}
h1{margin:0;color:#15365c}.muted{color:#596579}
input{box-sizing:border-box;width:100%;padding:12px;border:1px solid #b8c5d5;border-radius:8px;margin:8px 0 14px}
button,.link{display:inline-block;background:#15365c;color:white;padding:11px 17px;border:0;border-radius:8px;text-decoration:none;cursor:pointer}
.error{color:#a21d28;background:#fff0f0;padding:12px;border-radius:8px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f7fb;padding:15px;border-radius:8px}
</style></head>
<body>
<header>
<h1>Historical Score Comparison</h1>
<p class="muted">Compare two saved TraceNox score snapshots.</p>
<p><a href="/">← Back to Website Assessment</a></p>
</header>
<section class="panel">
<h2>Choose snapshots</h2>
<p class="muted">Enter JSON paths relative to the reports/ directory. For safety, files outside reports/ are rejected.</p>
<form method="post" action="/history">
<label for="previous"><b>Previous snapshot</b></label>
<input id="previous" name="previous" required
 value="{{ previous }}" placeholder="history-demo/previous.json">
<label for="current"><b>Current snapshot</b></label>
<input id="current" name="current" required
 value="{{ current }}" placeholder="history-demo/current.json">
<button type="submit">Compare Scores</button>
</form>
</section>
{% if error %}<section class="panel error">{{ error }}</section>{% endif %}
{% if formatted %}
<section class="panel">
<h2>Comparison Results</h2>
<pre>{{ formatted }}</pre>
{% if saved_path %}<p><b>Saved JSON:</b> {{ saved_path }}</p>{% endif %}
</section>
{% endif %}
<footer class="muted">TraceNox · Local interface</footer>
</body></html>"""

@app.route("/history", methods=["GET", "POST"])
def history_comparison():
    reports_root = (Path(__file__).resolve().parents[1] / "reports").resolve()
    default_previous = "history-demo/previous.json"
    default_current = "history-demo/current.json"

    previous = default_previous
    current = default_current
    error = None
    formatted = None
    saved_path = None

    if request.method == "POST":
        previous = request.form.get("previous", "").strip()
        current = request.form.get("current", "").strip()

        def resolve_snapshot(relative_name):
            candidate_name = Path(relative_name)
            if candidate_name.is_absolute() or not relative_name:
                raise ValueError("Use a relative JSON path inside reports/.")
            if candidate_name.suffix.lower() != ".json":
                raise ValueError("Snapshot files must have a .json extension.")
            candidate = (reports_root / candidate_name).resolve()
            if not candidate.is_relative_to(reports_root):
                raise ValueError("Snapshot paths must stay inside reports/.")
            if not candidate.is_file():
                raise ValueError(f"Snapshot file not found: {relative_name}")
            return candidate

        try:
            previous_path = resolve_snapshot(previous)
            current_path = resolve_snapshot(current)

            comparison = compare_snapshot_files(previous_path, current_path)

            output_dir = (reports_root / "history-demo").resolve()
            if not output_dir.is_relative_to(reports_root):
                raise ValueError("Invalid comparison output directory.")
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / "comparison.json"

            save_comparison(comparison, output_path)
            formatted = format_comparison(comparison)
            saved_path = str(output_path.relative_to(reports_root))
        except (ValueError, OSError, TypeError, KeyError) as exc:
            error = str(exc)
        except Exception:
            app.logger.exception("Historical comparison failed")
            error = "Comparison failed. Check the terminal for diagnostic details."

    return render_template_string(
        HISTORY_PAGE,
        previous=previous,
        current=current,
        error=error,
        formatted=formatted,
        saved_path=saved_path,
    )


def main():
    # Intentionally bind only to loopback; do not expose this UI to a network.
    app.run(host="127.0.0.1", port=5050, debug=False)

if __name__ == "__main__":
    main()
