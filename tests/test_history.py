import json

import pytest

from tracenox.history import (
    compare_snapshots,
    format_comparison,
    load_score_snapshot,
    normalize_score_report,
    save_comparison,
    save_score_snapshot,
)


def test_normalize():
    result = normalize_score_report(
        {
            "overall_score": 72,
            "rating": "MODERATE",
            "modules": {
                "hardening": 65,
                "fim": {"score": 100},
            },
        }
    )

    assert result["overall_score"] == 72
    assert result["modules"]["hardening"] == 65
    assert result["modules"]["fim"] == 100


def test_improved():
    result = compare_snapshots(
        {
            "overall_score": 56,
            "modules": {
                "hardening": 20,
                "fim": 100,
                "logs": 15,
                "ip_reputation": 20,
            },
        },
        {
            "overall_score": 72,
            "modules": {
                "hardening": 65,
                "fim": 100,
                "logs": 40,
                "ip_reputation": 35,
            },
        },
    )

    assert result["delta"] == 16
    assert result["status"] == "IMPROVED"
    assert result["module_changes"]["hardening"]["delta"] == 45
    assert result["module_changes"]["logs"]["delta"] == 25


def test_degraded():
    result = compare_snapshots(
        {
            "overall_score": 80,
            "modules": {"hardening": 80},
        },
        {
            "overall_score": 60,
            "modules": {"hardening": 40},
        },
    )

    assert result["delta"] == -20
    assert result["status"] == "DEGRADED"


def test_unchanged():
    result = compare_snapshots(
        {
            "overall_score": 75,
            "modules": {"hardening": 70},
        },
        {
            "overall_score": 75,
            "modules": {"hardening": 70},
        },
    )

    assert result["delta"] == 0
    assert result["status"] == "UNCHANGED"


def test_new_and_resolved():
    result = compare_snapshots(
        {
            "overall_score": 50,
            "modules": {
                "hardening": 40,
                "logs": 60,
            },
        },
        {
            "overall_score": 70,
            "modules": {
                "hardening": 70,
                "fim": 100,
            },
        },
    )

    assert "fim" in result["new_modules"]
    assert "logs" in result["resolved_modules"]


def test_snapshot_roundtrip(tmp_path):
    path = tmp_path / "snapshot.json"

    save_score_snapshot(
        {
            "overall_score": 72,
            "rating": "MODERATE",
            "modules": {"hardening": 65},
        },
        path,
    )

    result = load_score_snapshot(path)

    assert result["overall_score"] == 72
    assert result["modules"]["hardening"] == 65


def test_missing_snapshot(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_score_snapshot(
            tmp_path / "missing.json"
        )


def test_bad_snapshot(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(
        "{invalid",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_score_snapshot(path)


def test_format():
    result = compare_snapshots(
        {
            "overall_score": 56,
            "modules": {"hardening": 20},
        },
        {
            "overall_score": 72,
            "modules": {"hardening": 65},
        },
    )

    text = format_comparison(result)

    assert "Previous score : 56/100" in text
    assert "Current score  : 72/100" in text
    assert "Change         : +16" in text
    assert "Status         : IMPROVED" in text


def test_save_comparison(tmp_path):
    path = tmp_path / "comparison.json"

    result = compare_snapshots(
        {
            "overall_score": 50,
            "modules": {"hardening": 40},
        },
        {
            "overall_score": 70,
            "modules": {"hardening": 70},
        },
    )

    save_comparison(result, path)

    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    assert data["delta"] == 20
    assert data["status"] == "IMPROVED"
