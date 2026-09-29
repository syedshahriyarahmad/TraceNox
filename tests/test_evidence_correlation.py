from tracenox.analyzer.evidence import attach_evidence_to_findings
from tracenox.models.event import SecurityEvent


def test_burst_finding_includes_original_failed_log_lines():
    events = [
        SecurityEvent(
            "authentication_failed", "Sep 21 03:20:10",
            "admin", "192.168.1.50",
            "Failed password for admin from 192.168.1.50",
        ),
        SecurityEvent(
            "authentication_failed", "Sep 21 03:20:20",
            "root", "192.168.1.50",
            "Failed password for root from 192.168.1.50",
        ),
        SecurityEvent(
            "authentication_failed", "Sep 21 03:21:10",
            "guest", "10.0.0.5",
            "Failed password for guest from 10.0.0.5",
        ),
    ]
    findings = [{
        "detection": "ssh_failed_login_burst",
        "source_ip": "192.168.1.50",
        "first_failed_at": "Sep 21 03:20:10",
        "last_failed_at": "Sep 21 03:20:20",
        "failed_attempts": 2,
        "severity": "high",
    }]

    result = attach_evidence_to_findings(findings, events)

    assert result[0]["evidence_count"] == 2
    assert all(
        item["source_ip"] == "192.168.1.50"
        for item in result[0]["evidence"]
    )
    assert "Failed password for admin" in result[0]["evidence"][0]["raw_log"]


def test_finding_without_matching_events_has_empty_evidence():
    finding = {
        "detection": "ssh_failed_login_burst",
        "source_ip": "192.168.1.99",
        "first_failed_at": "Sep 21 03:20:10",
        "last_failed_at": "Sep 21 03:20:20",
    }

    result = attach_evidence_to_findings([finding], [])

    assert result[0]["evidence"] == []
    assert result[0]["evidence_count"] == 0
