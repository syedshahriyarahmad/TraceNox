from collections import Counter


def detect_failed_login_burst(events: list[dict], threshold: int = 5) -> list[dict]:
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
