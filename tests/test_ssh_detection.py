from tracenox.detection.ssh_detection import (
    detect_failed_login_burst,
    detect_failed_then_success,
)
from tracenox.models.event import SecurityEvent


def test_failed_login_burst():
    events = [
        SecurityEvent(
            event="authentication_failed",
            timestamp=f"Sep 21 03:20:{10 + i * 2:02d}",
            username="testuser",
            source_ip="192.168.1.50",
            raw_log="test",
        )
        for i in range(5)
    ]

    findings = detect_failed_login_burst(
        events,
        threshold=5,
        window_minutes=5,
    )

    assert len(findings) == 1
    assert findings[0]["detection"] == "ssh_failed_login_burst"
    assert findings[0]["source_ip"] == "192.168.1.50"
    assert findings[0]["failed_attempts"] == 5
    assert findings[0]["window_minutes"] == 5
    assert findings[0]["severity"] == "high"


def test_failed_login_burst_within_time_window():
    events = [
        SecurityEvent(
            event="authentication_failed",
            timestamp=timestamp,
            username="testuser",
            source_ip="192.168.1.50",
            raw_log="test",
        )
        for timestamp in [
            "Sep 21 03:20:10",
            "Sep 21 03:20:40",
            "Sep 21 03:21:10",
            "Sep 21 03:21:40",
            "Sep 21 03:22:10",
        ]
    ]

    findings = detect_failed_login_burst(
        events,
        threshold=5,
        window_minutes=5,
    )

    assert len(findings) == 1
    assert findings[0]["detection"] == "ssh_failed_login_burst"
    assert findings[0]["failed_attempts"] == 5
    assert findings[0]["window_minutes"] == 5
    assert findings[0]["severity"] == "high"


def test_failed_login_burst_outside_time_window():
    events = [
        SecurityEvent(
            event="authentication_failed",
            timestamp=timestamp,
            username="testuser",
            source_ip="192.168.1.50",
            raw_log="test",
        )
        for timestamp in [
            "Sep 21 03:20:10",
            "Sep 21 03:22:10",
            "Sep 21 03:24:10",
            "Sep 21 03:26:10",
            "Sep 21 03:28:10",
        ]
    ]

    findings = detect_failed_login_burst(
        events,
        threshold=5,
        window_minutes=5,
    )

    assert len(findings) == 0


def test_failed_then_success():
    events = [
        SecurityEvent(
            event="authentication_failed",
            timestamp=f"Sep 21 03:20:{10 + i * 2:02d}",
            username="testuser",
            source_ip="192.168.1.50",
            raw_log="test",
        )
        for i in range(5)
    ]

    events.append(
        SecurityEvent(
            event="authentication_success",
            timestamp="Sep 21 03:21:02",
            username="testuser",
            source_ip="192.168.1.50",
            raw_log="test",
        )
    )

    findings = detect_failed_then_success(
        events,
        threshold=3,
    )

    assert len(findings) == 1
    assert findings[0]["detection"] == "ssh_failed_then_success"
    assert findings[0]["source_ip"] == "192.168.1.50"
    assert findings[0]["username"] == "testuser"
    assert findings[0]["failed_attempts"] == 5
    assert findings[0]["severity"] == "high"
