from collections import Counter
from datetime import datetime


def detect_failed_login_burst(
    events: list[dict],
    threshold: int = 5,
) -> list[dict]:
    """Detect repeated failed SSH logins from the same source IP."""

    failed_events = [
        event
        for event in events
        if event.get("event") == "authentication_failed"
    ]

    ip_counts = Counter(
        event.get("source_ip")
        for event in failed_events
        if event.get("source_ip")
    )

    findings = []

    for source_ip, count in ip_counts.items():
        if count >= threshold:
            findings.append(
                {
                    "detection": "ssh_failed_login_burst",
                    "source_ip": source_ip,
                    "failed_attempts": count,
                    "threshold": threshold,
                    "severity": "high",
                }
            )

    return findings


def _parse_timestamp(timestamp: str | None) -> datetime | None:
    """Convert SSH timestamp text into a comparable datetime."""

    if not timestamp:
        return None

    try:
        return datetime.strptime(timestamp, "%b %d %H:%M:%S")
    except ValueError:
        return None


def detect_failed_then_success(
    events: list[dict],
    threshold: int = 3,
) -> list[dict]:
    """Detect successful SSH login after multiple earlier failed attempts."""

    findings = []

    successful_events = [
        event
        for event in events
        if event.get("event") == "authentication_success"
    ]

    for success_event in successful_events:
        success_ip = success_event.get("source_ip")
        success_time = _parse_timestamp(success_event.get("timestamp"))

        if not success_ip or not success_time:
            continue

        failed_before_success = []

        for event in events:
            if event.get("event") != "authentication_failed":
                continue

            if event.get("source_ip") != success_ip:
                continue

            failed_time = _parse_timestamp(event.get("timestamp"))

            if failed_time and failed_time < success_time:
                failed_before_success.append(event)

        failed_attempts = len(failed_before_success)

        if failed_attempts >= threshold:
            findings.append(
                {
                    "detection": "ssh_failed_then_success",
                    "source_ip": success_ip,
                    "username": success_event.get("username"),
                    "failed_attempts": failed_attempts,
                    "threshold": threshold,
                    "first_failed_at": failed_before_success[0].get(
                        "timestamp"
                    ),
                    "successful_login_at": success_event.get(
                        "timestamp"
                    ),
                    "severity": "high",
                }
            )

    return findings
