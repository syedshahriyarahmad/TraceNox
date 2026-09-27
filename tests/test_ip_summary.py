from tracenox.analyzer.ip_summary import build_ip_summary
from tracenox.models.event import SecurityEvent


def test_build_ip_summary():
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
            event="authentication_success",
            timestamp="Sep 21 03:21:02",
            username="admin",
            source_ip="192.168.1.50",
            raw_log="test",
        ),
        SecurityEvent(
            event="authentication_failed",
            timestamp="Sep 21 03:22:10",
            username="testuser",
            source_ip="10.0.0.25",
            raw_log="test",
        ),
    ]

    summary = build_ip_summary(events)

    assert "192.168.1.50" in summary
    assert "10.0.0.25" in summary

    attacker = summary["192.168.1.50"]

    assert attacker["total_events"] == 3
    assert attacker["failed_logins"] == 2
    assert attacker["successful_logins"] == 1
    assert attacker["usernames"] == ["admin", "root"]

    assert attacker["first_seen"] == "Sep 21 03:20:10"
    assert attacker["last_seen"] == "Sep 21 03:21:02"

    other_ip = summary["10.0.0.25"]

    assert other_ip["total_events"] == 1
    assert other_ip["failed_logins"] == 1
    assert other_ip["successful_logins"] == 0
    assert other_ip["usernames"] == ["testuser"]
