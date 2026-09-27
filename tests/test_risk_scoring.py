from tracenox.detection.risk_scoring import calculate_risk_score
from tracenox.models.event import SecurityEvent


def test_high_risk_score():
    events = [
        SecurityEvent(
            event="authentication_failed",
            timestamp="Sep 21 03:20:10",
            username="admin",
            source_ip="192.168.1.50",
            raw_log="test",
        ),
        SecurityEvent(
            event="authentication_failed",
            timestamp="Sep 21 03:20:20",
            username="root",
            source_ip="192.168.1.50",
            raw_log="test",
        ),
        SecurityEvent(
            event="authentication_failed",
            timestamp="Sep 21 03:20:30",
            username="testuser",
            source_ip="192.168.1.50",
            raw_log="test",
        ),
        SecurityEvent(
            event="authentication_failed",
            timestamp="Sep 21 03:20:40",
            username="admin",
            source_ip="192.168.1.50",
            raw_log="test",
        ),
        SecurityEvent(
            event="authentication_success",
            timestamp="Sep 21 03:21:02",
            username="admin",
            source_ip="192.168.1.50",
            raw_log="test",
        ),
    ]

    findings = [
        {
            "detection": "ssh_failed_then_success",
            "source_ip": "192.168.1.50",
            "failed_attempts": 4,
            "threshold": 3,
            "username": "admin",
            "severity": "high",
        }
    ]

    result = calculate_risk_score(events, findings)

    assert result["score"] == 80
    assert result["level"] == "high"
    assert len(result["reasons"]) == 4


def test_low_risk_score():
    events = [
        SecurityEvent(
            event="authentication_failed",
            timestamp="Sep 21 03:20:10",
            username="testuser",
            source_ip="10.0.0.25",
            raw_log="test",
        )
    ]

    result = calculate_risk_score(events, [])

    assert result["score"] == 0
    assert result["level"] == "low"
    assert result["reasons"] == []
