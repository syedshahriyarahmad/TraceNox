from datetime import datetime

from tracenox.models.event import SecurityEvent


def _parse_timestamp(timestamp: str | None) -> datetime | None:
    if not timestamp:
        return None
    try:
        return datetime.strptime(
            f"2026 {timestamp}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None


def attach_evidence_to_findings(
    findings: list[dict],
    timeline: list[SecurityEvent],
) -> list[dict]:
    """Attach relevant original log records to each detection."""
    enriched = []

    for finding in findings:
        detection = finding.get("detection")
        source_ip = finding.get("source_ip")
        first_time = _parse_timestamp(finding.get("first_failed_at"))
        last_time = _parse_timestamp(
            finding.get("last_failed_at")
            or finding.get("successful_login_at")
        )

        evidence_events = []

        for event in timeline:
            if event.source_ip != source_ip:
                continue

            event_time = _parse_timestamp(event.timestamp)

            if detection == "ssh_failed_login_burst":
                if event.event != "authentication_failed":
                    continue
                if first_time and event_time and event_time < first_time:
                    continue
                if last_time and event_time and event_time > last_time:
                    continue

            elif detection == "ssh_failed_then_success":
                if event.event not in (
                    "authentication_failed",
                    "authentication_success",
                ):
                    continue
                if last_time and event_time and event_time > last_time:
                    continue

            else:
                continue

            evidence_events.append({
                "timestamp": event.timestamp,
                "event": event.event,
                "username": event.username,
                "source_ip": event.source_ip,
                "raw_log": event.raw_log,
            })

        item = dict(finding)
        item["evidence"] = evidence_events
        item["evidence_count"] = len(evidence_events)
        enriched.append(item)

    return enriched
