from tracenox.security_score import (
    calculate_security_score,
    format_security_score,
)


def test_unified_score_with_hardening():
    result = calculate_security_score(
        hardening={
            "security_score": 80,
            "status": "WARNING",
        }
    )

    assert result["tool"] == "TraceNox"
    assert result["overall_score"] == 80
    assert result["rating"] == "GOOD"
    assert "hardening" in result["modules"]


def test_unified_score_empty():
    result = calculate_security_score()

    assert result["overall_score"] == 0
    assert result["rating"] == "NO_DATA"
    assert result["summary"]["modules_evaluated"] == 0


def test_fim_clean_score():
    result = calculate_security_score(
        fim={
            "status": "UNCHANGED",
        }
    )

    assert result["overall_score"] == 100
    assert result["modules"]["fim"]["score"] == 100


def test_fim_changes_score():
    result = calculate_security_score(
        fim={
            "status": "CHANGES_DETECTED",
        }
    )

    assert result["overall_score"] == 50
    assert result["modules"]["fim"]["score"] == 50


def test_format_security_score():
    result = calculate_security_score(
        hardening={
            "security_score": 75,
            "status": "WARNING",
        }
    )

    output = format_security_score(result)

    assert "TraceNox Unified Security Score" in output
    assert "75/100" in output
    assert "hardening" in output
