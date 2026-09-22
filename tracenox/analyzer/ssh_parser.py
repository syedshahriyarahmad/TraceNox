import re


SSH_FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<source_ip>\S+)"
)

SSH_ACCEPTED_PATTERN = re.compile(
    r"Accepted \S+ for (?P<username>\S+) from (?P<source_ip>\S+)"
)


def parse_ssh_line(line: str) -> dict | None:
    """Parse a Linux SSH authentication log line."""

    failed_match = SSH_FAILED_PATTERN.search(line)

    if failed_match:
        return {
            "event": "authentication_failed",
            "username": failed_match.group("username"),
            "source_ip": failed_match.group("source_ip"),
            "raw_log": line,
        }

    accepted_match = SSH_ACCEPTED_PATTERN.search(line)

    if accepted_match:
        return {
            "event": "authentication_success",
            "username": accepted_match.group("username"),
            "source_ip": accepted_match.group("source_ip"),
            "raw_log": line,
        }

    return None
