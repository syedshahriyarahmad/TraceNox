import html
import ipaddress

import pytest

from tracenox.webscan import (
    generate_html_report,
    normalize_url,
    resolve_public_addresses,
)


def test_normalize_domain_to_https():
    assert normalize_url("example.com") == "https://example.com/"


def test_normalize_url_preserves_path_and_query():
    assert normalize_url("https://example.com/a?b=c") == (
        "https://example.com/a?b=c"
    )


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com",
        "http://127.0.0.1",
        "http://localhost",
        "http://192.168.1.1",
        "http://user:pass@example.com",
    ],
)
def test_reject_unsupported_or_unsafe_urls(value):
    with pytest.raises(ValueError):
        normalize_url(value)


def test_reject_non_public_dns_results(monkeypatch):
    import socket

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        ],
    )
    with pytest.raises(ValueError, match="non-public"):
        resolve_public_addresses("example.invalid", 443)


def test_public_ip_classification():
    assert ipaddress.ip_address("8.8.8.8").is_global
    assert not ipaddress.ip_address("10.0.0.1").is_global


def test_html_report_escapes_untrusted_evidence():
    report = generate_html_report(
        {
            "version": "0.3.0",
            "target": "https://example.com",
            "final_url": "https://example.com",
            "resolved_ips": ["8.8.8.8"],
            "summary": {"total_findings": 1, "by_severity": {"high": 1}},
            "http": {},
            "tls": {},
            "redirects": [],
            "findings": [
                {
                    "severity": "high",
                    "title": "<script>alert(1)</script>",
                    "evidence": "<img src=x>",
                    "recommendation": "Fix & review",
                }
            ],
            "limitations": [],
        }
    )
    assert "<script>alert(1)</script>" not in report
    assert "&lt;script&gt;" in report
    assert "&lt;img src=x&gt;" in report
    assert html.escape("Fix & review") in report
