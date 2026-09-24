import re

from tracenox.models.event import SecurityEvent


TIMESTAMP_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)


SSH_FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<source_ip>\S+)"
)


SSH_ACCEPTED_PATTERN = re.compile(
    r"Accepted \S+ for (?P<username>\S+) from (?P<source_ip>\S+)"
)


def parse_ssh_line(line: str) -> SecurityEvent | None:
    """Parse a Linux SSH authentication log line."""

    timestamp_match = TIMESTAMP_PATTERN.search(line)

    timestamp = (
        timestamp_match.group("timestamp")
        if timestamp_match
        else None
    )

    failed_match = SSH_FAILED_PATTERN.search(line)

    if failed_match:
        return SecurityEvent(
            event="authentication_failed",
            timestamp=timestamp,
            username=failed_match.group("username"),
            source_ip=failed_match.group("source_ip"),
            raw_log=line,
        )

    accepted_match = SSH_ACCEPTED_PATTERN.search(line)

    if accepted_match:
        return SecurityEvent(
            event="authentication_success",
            timestamp=timestamp,
            username=accepted_match.group("username"),
            source_ip=accepted_match.group("source_ip"),
            raw_log=line,
        )

    return None
