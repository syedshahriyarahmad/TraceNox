from datetime import datetime

from tracenox.models.event import SecurityEvent


def _parse_timestamp(timestamp: str | None) -> datetime | None:
    """Convert SSH timestamp text into a comparable datetime."""

    if not timestamp:
        return None

    try:
        return datetime.strptime(timestamp, "%b %d %H:%M:%S")
    except ValueError:
        return None


def build_timeline(events: list[SecurityEvent]) -> list[SecurityEvent]:
    """Return security events ordered chronologically."""

    return sorted(
        events,
        key=lambda event: (
            _parse_timestamp(event.timestamp)
            or datetime.max
        ),
    )
