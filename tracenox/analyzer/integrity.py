"""Integrity metadata and SHA-256 verification utilities."""

import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path


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


def calculate_file_sha256(file_path: str) -> str:
    """Calculate SHA-256 for the exact bytes of a file."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {file_path}")

    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def verify_file_sha256(
    file_path: str,
    expected_sha256: str,
) -> tuple[bool, str]:
    """Compare a file's current SHA-256 with an expected hash."""
    expected = expected_sha256.strip().lower()

    if len(expected) != 64 or any(
        character not in "0123456789abcdef"
        for character in expected
    ):
        raise ValueError("Expected SHA-256 must be exactly 64 hexadecimal characters.")

    actual = calculate_file_sha256(file_path)
    return hmac.compare_digest(actual, expected), actual
