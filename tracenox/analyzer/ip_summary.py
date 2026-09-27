from collections import Counter, defaultdict

from tracenox.models.event import SecurityEvent


def build_ip_summary(
    events: list[SecurityEvent],
) -> dict[str, dict]:
    """Build an investigation summary for each source IP."""

    summaries = defaultdict(
        lambda: {
            "total_events": 0,
            "failed_logins": 0,
            "successful_logins": 0,
            "usernames": set(),
            "first_seen": None,
            "last_seen": None,
        }
    )

    for event in events:
        if not event.source_ip:
            continue

        summary = summaries[event.source_ip]

        summary["total_events"] += 1

        if event.event == "authentication_failed":
            summary["failed_logins"] += 1

        elif event.event == "authentication_success":
            summary["successful_logins"] += 1

        if event.username:
            summary["usernames"].add(event.username)

        if event.timestamp:
            if summary["first_seen"] is None:
                summary["first_seen"] = event.timestamp

            summary["last_seen"] = event.timestamp

    result = {}

    for source_ip, summary in summaries.items():
        result[source_ip] = {
            "total_events": summary["total_events"],
            "failed_logins": summary["failed_logins"],
            "successful_logins": summary["successful_logins"],
            "usernames": sorted(summary["usernames"]),
            "first_seen": summary["first_seen"],
            "last_seen": summary["last_seen"],
        }

    return result
