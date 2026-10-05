import hashlib
import json

import pytest

from tracenox.analyzer.integrity import (
    build_integrity_metadata,
    calculate_file_sha256,
    create_file_integrity_baseline,
    scan_file_integrity,
    verify_file_sha256,
)


def test_integrity_records_correct_sha256():
    content = b"sample security log\n"
    result = build_integrity_metadata(
        source_file="sample.log",
        source_bytes=content,
        parsed_events=2,
        findings=[],
    )

    assert result["source_sha256"] == hashlib.sha256(content).hexdigest()
    assert result["hash_algorithm"] == "SHA-256"
    assert result["source"] == "sample.log"
    assert result["parsed_events"] == 2
    assert result["findings_count"] == 0
    assert result["supporting_evidence_count"] == 0
    assert result["generated_at_utc"]


def test_integrity_counts_supporting_evidence():
    findings = [
        {"evidence": [{"raw_log": "event 1"}, {"raw_log": "event 2"}]},
        {"evidence": [{"raw_log": "event 3"}]},
    ]

    result = build_integrity_metadata(
        source_file="sample.log",
        source_bytes=b"sample",
        parsed_events=3,
        findings=findings,
    )

    assert result["findings_count"] == 2
    assert result["supporting_evidence_count"] == 3


def test_file_sha256_verification_matches(tmp_path):
    sample = tmp_path / "sample.log"
    sample.write_bytes(b"original evidence\n")

    expected = calculate_file_sha256(str(sample))
    matches, actual = verify_file_sha256(str(sample), expected)

    assert matches is True
    assert actual == expected


def test_file_sha256_verification_detects_changes(tmp_path):
    sample = tmp_path / "sample.log"
    sample.write_bytes(b"original evidence\n")
    original_hash = calculate_file_sha256(str(sample))

    sample.write_bytes(b"modified evidence\n")
    matches, actual = verify_file_sha256(str(sample), original_hash)

    assert matches is False
    assert actual != original_hash


def test_file_sha256_rejects_invalid_expected_hash(tmp_path):
    sample = tmp_path / "sample.log"
    sample.write_bytes(b"sample")

    with pytest.raises(ValueError, match="64 hexadecimal"):
        verify_file_sha256(str(sample), "not-a-valid-hash")


def test_fim_creates_recursive_baseline(tmp_path):
    root = tmp_path / "monitored"
    root.mkdir()
    (root / "auth.log").write_text("login event\n", encoding="utf-8")
    nested = root / "config"
    nested.mkdir()
    (nested / "settings.conf").write_text(
        "enabled=true\n",
        encoding="utf-8",
    )

    baseline_path = tmp_path / "baseline.json"
    baseline = create_file_integrity_baseline(
        str(root),
        str(baseline_path),
    )

    assert baseline["format_version"] == 1
    assert baseline["hash_algorithm"] == "SHA-256"
    assert baseline["file_count"] == 2
    assert "auth.log" in baseline["files"]
    assert "config/settings.conf" in baseline["files"]

    saved = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert saved["file_count"] == 2


def test_fim_detects_modified_added_and_deleted_files(tmp_path):
    root = tmp_path / "monitored"
    root.mkdir()

    original = root / "original.txt"
    removed = root / "removed.txt"
    original.write_text("original\n", encoding="utf-8")
    removed.write_text("remove me\n", encoding="utf-8")

    baseline_path = tmp_path / "baseline.json"
    create_file_integrity_baseline(str(root), str(baseline_path))

    original.write_text("changed\n", encoding="utf-8")
    removed.unlink()
    (root / "new.txt").write_text("new file\n", encoding="utf-8")

    result = scan_file_integrity(str(root), str(baseline_path))

    assert result["status"] == "CHANGES_DETECTED"
    assert result["findings"]["modified"] == ["original.txt"]
    assert result["findings"]["added"] == ["new.txt"]
    assert result["findings"]["deleted"] == ["removed.txt"]
    assert result["summary"]["modified"] == 1
    assert result["summary"]["added"] == 1
    assert result["summary"]["deleted"] == 1


def test_fim_reports_clean_directory(tmp_path):
    root = tmp_path / "monitored"
    root.mkdir()
    (root / "important.conf").write_text(
        "secure=true\n",
        encoding="utf-8",
    )

    baseline_path = tmp_path / "baseline.json"
    create_file_integrity_baseline(str(root), str(baseline_path))

    result = scan_file_integrity(str(root), str(baseline_path))

    assert result["status"] == "CLEAN"
    assert result["summary"]["unchanged"] == 1
    assert result["summary"]["modified"] == 0
    assert result["summary"]["added"] == 0
    assert result["summary"]["deleted"] == 0


def test_fim_ignores_baseline_inside_monitored_directory(tmp_path):
    root = tmp_path / "monitored"
    root.mkdir()
    (root / "important.conf").write_text(
        "secure=true\n",
        encoding="utf-8",
    )

    baseline_path = root / "tracenox-baseline.json"
    create_file_integrity_baseline(str(root), str(baseline_path))

    result = scan_file_integrity(str(root), str(baseline_path))

    assert result["status"] == "CLEAN"
    assert "tracenox-baseline.json" not in result["findings"]["added"]
