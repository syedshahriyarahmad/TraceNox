from tracenox.pdf_report import create_pdf_report
from tracenox import webapp

def sample_result():
    return {
        "target": "https://example.com",
        "final_url": "https://example.com/",
        "duration_seconds": 1.2,
        "resolved_addresses": ["93.184.216.34"],
        "summary": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 1},
        "findings": [{
            "severity": "medium",
            "title": "Example finding",
            "evidence": "Example evidence",
            "recommendation": "Review the configuration",
        }],
        "limitations": ["Low-impact assessment only."],
    }

def test_pdf_is_generated():
    pdf = create_pdf_report(sample_result())
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 500

def test_home_page():
    client = webapp.app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"TraceNox" in response.data

def test_scan_and_download(monkeypatch):
    monkeypatch.setattr(webapp, "scan_website", lambda url: sample_result())
    client = webapp.app.test_client()
    response = client.post("/scan", data={"url": "https://example.com"})
    assert response.status_code == 200
    assert b"Download PDF Report" in response.data
    import re
    match = re.search(rb'href="/download/([^"]+)"', response.data)
    assert match
    pdf_response = client.get("/download/" + match.group(1).decode())
    assert pdf_response.status_code == 200
    assert pdf_response.data.startswith(b"%PDF-")
    assert pdf_response.mimetype == "application/pdf"

def test_unknown_download_token():
    response = webapp.app.test_client().get("/download/not-a-valid-token")
    assert response.status_code == 404
