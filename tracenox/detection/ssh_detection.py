from collections import Counter
from datetime import datetime, timedelta

from tracenox.models.event import SecurityEvent


def detect_failed_login_burst(
    events: list[SecurityEvent],
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[dict]:
    """Detect repeated failed SSH logins within a time window."""

    failed_events = [
        event
        for event in events
        if event.event == "authentication_failed"
        and event.source_ip
        and event.timestamp
    ]

    findings = []

    events_by_ip: dict[str, list[SecurityEvent]] = {}

    for event in failed_events:
        events_by_ip.setdefault(event.source_ip, []).append(event)

    for source_ip, ip_events in events_by_ip.items():
        parsed_events = []

        for event in ip_events:
            event_time = _parse_timestamp(event.timestamp)

            if event_time:
                parsed_events.append((event_time, event))

        parsed_events.sort(key=lambda item: item[0])

        for start_index, (start_time, _) in enumerate(parsed_events):
            window_events = [
                event
                for event_time, event in parsed_events[start_index:]
                if event_time - start_time
                <= timedelta(minutes=window_minutes)
            ]

            if len(window_events) >= threshold:
                findings.append(
                    {
                        "detection": "ssh_failed_login_burst",
                        "source_ip": source_ip,
                        "failed_attempts": len(window_events),
                        "threshold": threshold,
                        "window_minutes": window_minutes,
                        "first_failed_at": window_events[0].timestamp,
                        "last_failed_at": window_events[-1].timestamp,
                        "severity": "high",
                    }
                )

                break

    return findings


def _parse_timestamp(timestamp: str | None) -> datetime | None:
    """Convert SSH timestamp text into a comparable datetime."""

    if not timestamp:
        return None

    try:
        return datetime.strptime(
            f"2026 {timestamp}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None


def detect_failed_then_success(
    events: list[SecurityEvent],
    threshold: int = 3,
) -> list[dict]:
    """Detect successful SSH login after multiple earlier failed attempts."""

    findings = []

    successful_events = [
        event
        for event in events
        if event.event == "authentication_success"
    ]

    for success_event in successful_events:
        success_ip = success_event.source_ip
        success_time = _parse_timestamp(success_event.timestamp)

        if not success_ip or not success_time:
            continue

        failed_before_success = []

        for event in events:
            if event.event != "authentication_failed":
                continue

            if event.source_ip != success_ip:
                continue

            failed_time = _parse_timestamp(event.timestamp)

            if failed_time and failed_time < success_time:
                failed_before_success.append(event)

        failed_attempts = len(failed_before_success)

        if failed_attempts >= threshold:
            findings.append(
                {
                    "detection": "ssh_failed_then_success",
                    "source_ip": success_ip,
                    "username": success_event.username,
                    "failed_attempts": failed_attempts,
                    "threshold": threshold,
                    "first_failed_at": failed_before_success[0].timestamp,
                    "successful_login_at": success_event.timestamp,
                    "severity": "high",
                }
            )

    return findings
