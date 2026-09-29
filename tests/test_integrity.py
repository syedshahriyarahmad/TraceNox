import hashlib

from tracenox.analyzer.integrity import build_integrity_metadata


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
    from tracenox.analyzer.integrity import (
        calculate_file_sha256,
        verify_file_sha256,
    )

    sample = tmp_path / "sample.log"
    sample.write_bytes(b"original evidence\n")

    expected = calculate_file_sha256(str(sample))
    matches, actual = verify_file_sha256(str(sample), expected)

    assert matches is True
    assert actual == expected


def test_file_sha256_verification_detects_changes(tmp_path):
    from tracenox.analyzer.integrity import (
        calculate_file_sha256,
        verify_file_sha256,
    )

    sample = tmp_path / "sample.log"
    sample.write_bytes(b"original evidence\n")
    original_hash = calculate_file_sha256(str(sample))

    sample.write_bytes(b"modified evidence\n")
    matches, actual = verify_file_sha256(str(sample), original_hash)

    assert matches is False
    assert actual != original_hash


def test_file_sha256_rejects_invalid_expected_hash(tmp_path):
    import pytest
    from tracenox.analyzer.integrity import verify_file_sha256

    sample = tmp_path / "sample.log"
    sample.write_bytes(b"sample")

    with pytest.raises(ValueError, match="64 hexadecimal"):
        verify_file_sha256(str(sample), "not-a-valid-hash")
