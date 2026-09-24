from dataclasses import dataclass


@dataclass
class SecurityEvent:
    """Normalized security event used by TraceNox."""

    event: str
    timestamp: str | None
    username: str | None
    source_ip: str | None
    raw_log: str
