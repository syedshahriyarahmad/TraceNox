"""Integrity metadata for reproducible TraceNox investigations."""

import hashlib
from datetime import datetime, timezone


def build_integrity_metadata(
    source_file: str,
    source_bytes: bytes,
    parsed_events: int,
    findings: list[dict],
) -> dict:
    """Build integrity metadata for the exact bytes analyzed."""
    evidence_count = sum(
        len(finding.get("evidence", []))
        for finding in findings
    )

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": source_file,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "hash_algorithm": "SHA-256",
        "parsed_events": parsed_events,
        "findings_count": len(findings),
        "supporting_evidence_count": evidence_count,
    }
