from tracenox.pdf_report import create_pdf_report


def test_pdf_has_valid_header():
    pdf = create_pdf_report({
        "target": "https://example.com",
        "risk_level": "LOW",
        "findings": [],
    })
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


def test_pdf_handles_multiple_severities():
    result = {
        "target": "https://example.com",
        "findings": [
            {
                "severity": "HIGH",
                "title": "Security header review",
                "description": "A security header was not observed.",
                "recommendation": "Review the server configuration.",
            },
            {
                "severity": "LOW",
                "title": "Cookie review",
                "details": {"secure": False, "httponly": True},
            },
            {
                "severity": "INFO",
                "title": "Informational check",
                "description": "No additional details.",
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


def test_pdf_handles_empty_and_unexpected_results():
    for result in ({}, {"findings": []}, {"scan_result": ["item", 123, None]}):
        pdf = create_pdf_report(result)
        assert pdf.startswith(b"%PDF-")


def test_pdf_handles_special_characters():
    result = {
        "target": 'https://example.com/?q=<script>alert("x")</script>&a=1',
        "findings": [{
            "severity": "INFO",
            "title": "<script>not executable</script>",
            "description": "Text with & ampersands, <tags>, and quotes.",
        }],
    }
    pdf = create_pdf_report(result)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000
