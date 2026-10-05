"""Integrity metadata, SHA-256 verification, and file integrity monitoring."""

from __future__ import annotations

import hashlib
import hmac
import json
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
        raise ValueError(
            "Expected SHA-256 must be exactly 64 hexadecimal characters."
        )

    actual = calculate_file_sha256(file_path)
    return hmac.compare_digest(actual, expected), actual


def _scan_directory(directory: str) -> dict[str, dict]:
    """Return SHA-256 metadata for regular files below a directory."""
    root = Path(directory).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")
    if not root.is_dir():
        raise ValueError(f"Not a directory: {directory}")

    files: dict[str, dict] = {}

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue

        relative_path = path.relative_to(root).as_posix()

        files[relative_path] = {
            "sha256": calculate_file_sha256(str(path)),
            "size": path.stat().st_size,
        }

    return files


def create_file_integrity_baseline(
    directory: str,
    output_file: str,
) -> dict:
    """Create a JSON SHA-256 baseline for regular files in a directory."""
    root = Path(directory).expanduser().resolve()
    output = Path(output_file).expanduser().resolve()

    files = _scan_directory(directory)

    # If the baseline is stored inside the monitored directory and already
    # exists, do not make it part of its own baseline.
    try:
        relative_output = output.relative_to(root).as_posix()
    except ValueError:
        relative_output = None

    if relative_output:
        files.pop(relative_output, None)

    baseline = {
        "format_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "root_directory": str(root),
        "hash_algorithm": "SHA-256",
        "file_count": len(files),
        "files": files,
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    return baseline


def load_file_integrity_baseline(baseline_file: str) -> dict:
    """Load and validate a TraceNox FIM baseline JSON file."""
    path = Path(baseline_file).expanduser()

    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {baseline_file}")
    if not path.is_file():
        raise ValueError(f"Baseline path is not a file: {baseline_file}")

    try:
        baseline = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid FIM baseline JSON: {baseline_file}"
        ) from error

    if not isinstance(baseline, dict):
        raise ValueError("FIM baseline must contain a JSON object.")

    if baseline.get("format_version") != 1:
        raise ValueError("Unsupported FIM baseline format version.")

    if baseline.get("hash_algorithm") != "SHA-256":
        raise ValueError("FIM baseline must use SHA-256.")

    files = baseline.get("files")
    if not isinstance(files, dict):
        raise ValueError("FIM baseline contains an invalid files section.")

    for relative_path, metadata in files.items():
        if not isinstance(relative_path, str) or not isinstance(metadata, dict):
            raise ValueError("FIM baseline contains invalid file metadata.")

        digest = metadata.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError(
                f"Invalid SHA-256 value in baseline for: {relative_path}"
            )

    return baseline


def scan_file_integrity(
    directory: str,
    baseline_file: str,
) -> dict:
    """Compare a directory against a previously generated FIM baseline."""
    root = Path(directory).expanduser().resolve()
    baseline_path = Path(baseline_file).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")
    if not root.is_dir():
        raise ValueError(f"Not a directory: {directory}")

    baseline = load_file_integrity_baseline(str(baseline_path))
    current_files = _scan_directory(directory)

    # Prevent a baseline stored inside the monitored directory from appearing
    # as an unexpected added file.
    try:
        relative_baseline = baseline_path.relative_to(root).as_posix()
    except ValueError:
        relative_baseline = None

    if relative_baseline:
        current_files.pop(relative_baseline, None)

    baseline_files = baseline["files"]

    added = sorted(set(current_files) - set(baseline_files))
    deleted = sorted(set(baseline_files) - set(current_files))

    modified = []
    unchanged = []

    for relative_path in sorted(set(current_files) & set(baseline_files)):
        baseline_hash = baseline_files[relative_path]["sha256"]
        current_hash = current_files[relative_path]["sha256"]

        if not hmac.compare_digest(current_hash, baseline_hash):
            modified.append(relative_path)
        else:
            unchanged.append(relative_path)

    result = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "root_directory": str(root),
        "baseline_file": str(baseline_path),
        "hash_algorithm": "SHA-256",
        "summary": {
            "baseline_files": len(baseline_files),
            "current_files": len(current_files),
            "unchanged": len(unchanged),
            "modified": len(modified),
            "added": len(added),
            "deleted": len(deleted),
        },
        "findings": {
            "modified": modified,
            "added": added,
            "deleted": deleted,
            "unchanged": unchanged,
        },
        "status": (
            "CLEAN"
            if not modified and not added and not deleted
            else "CHANGES_DETECTED"
        ),
    }

    return result
