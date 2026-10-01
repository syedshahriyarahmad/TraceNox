from tracenox.pdf_report import create_pdf_report


def test_pdf_starts_with_valid_pdf_header():
    result = {
        "target": "https://example.com",
        "risk_level": "LOW",
        "findings": [],
    }
    pdf = create_pdf_report(result)
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


def test_pdf_handles_findings_and_nested_data():
    result = {
        "target": "https://example.com",
        "findings": [
            {
                "severity": "HIGH",
                "title": "Security header missing",
                "description": "A security header was not observed.",
                "recommendation": "Review and configure the appropriate header.",
            },
            {
                "severity": "LOW",
                "title": "Cookie review",
                "details": {"secure": False, "httponly": True},
            },
        ],
        "headers": {
            "server": "Example",
            "checks": {"tls": "available", "redirects": ["https"]},
        },
    }
    pdf = create_pdf_report(result)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


def test_pdf_handles_empty_and_unexpected_result_shapes():
    for result in ({}, {"findings": []}, {"scan_result": ["item", 123, None]}):
        pdf = create_pdf_report(result)
        assert pdf.startswith(b"%PDF-")


def test_pdf_handles_special_characters_in_untrusted_text():
    result = {
        "target": 'https://example.com/?q=<script>alert("x")</script>&a=1',
        "findings": [
            {
                "severity": "INFO",
                "title": "<script>not executable</script>",
                "description": "Text with & ampersands, <tags>, and quotes.",
            }
        ],
    }
    pdf = create_pdf_report(result)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000
