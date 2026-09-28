from datetime import datetime

from tracenox.models.event import SecurityEvent


REFERENCE_YEAR = 2026


def _parse_timestamp(timestamp: str | None) -> datetime | None:
    """Parse a syslog timestamp using a reference year."""

    if not timestamp:
        return None

    try:
        return datetime.strptime(
            f"{timestamp} {REFERENCE_YEAR}",
            "%b %d %H:%M:%S %Y",
        )
    except ValueError:
        return None


def build_timeline(events: list[SecurityEvent]) -> list[SecurityEvent]:
    """Return security events ordered chronologically."""

    return sorted(
        events,
        key=lambda event: (
            _parse_timestamp(event.timestamp) or datetime.max
        ),
    )
