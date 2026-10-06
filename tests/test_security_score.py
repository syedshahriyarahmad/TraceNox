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


def test_unified_score_empty():
    result = calculate_security_score()

    assert result["overall_score"] == 0
    assert result["rating"] == "NO_DATA"


def test_fim_clean_score():
    result = calculate_security_score(
        fim={"status": "CLEAN"}
    )

    assert result["modules"]["fim"]["score"] == 100


def test_fim_changes_score():
    result = calculate_security_score(
        fim={"status": "CHANGES_DETECTED"}
    )

    assert result["modules"]["fim"]["score"] == 50


def test_real_log_risk_score():
    result = calculate_security_score(
        logs={
            "risk_assessment": {
                "score": 30,
            }
        }
    )

    assert result["modules"]["logs"]["score"] == 70


def test_real_ip_risk_score():
    result = calculate_security_score(
        ip_reputation={
            "correlated_ip_risk": {
                "1.1.1.1": {"score": 20},
                "2.2.2.2": {"score": 65},
            }
        }
    )

    assert result["modules"]["ip_reputation"]["score"] == 35


def test_real_web_score():
    result = calculate_security_score(
        webscan={
            "summary": {
                "by_severity": {
                    "critical": 0,
                    "high": 1,
                    "medium": 2,
                    "low": 1,
                    "info": 1,
                }
            }
        }
    )

    assert result["modules"]["webscan"]["score"] == 40


def test_full_real_module_integration():
    result = calculate_security_score(
        hardening={
            "security_score": 80,
        },
        fim={
            "status": "CLEAN",
        },
        webscan={
            "summary": {
                "by_severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 1,
                    "low": 0,
                    "info": 1,
                }
            }
        },
        logs={
            "risk_assessment": {
                "score": 30,
            }
        },
        ip_reputation={
            "correlated_ip_risk": {
                "1.1.1.1": {
                    "score": 20,
                }
            }
        },
    )

    assert result["summary"]["modules_evaluated"] == 5
    assert result["summary"]["modules_missing"] == 0
    assert result["overall_score"] == 84
    assert result["rating"] == "GOOD"


def test_format_security_score():
    result = calculate_security_score(
        hardening={
            "security_score": 75,
        }
    )

    output = format_security_score(result)

    assert "TraceNox Unified Security Score" in output
    assert "75/100" in output
    assert "hardening" in output
