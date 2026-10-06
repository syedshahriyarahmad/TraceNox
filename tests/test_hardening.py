from tracenox.hardening import run_hardening_audit


def test_hardening_audit_returns_expected_structure():
    result = run_hardening_audit()

    assert result["tool"] == "TraceNox"
    assert result["module"] == "Linux Security Hardening Auditor"
    assert result["status"] in {
        "PASS",
        "WARNING",
        "FAIL",
        "PARTIAL",
    }
    assert 0 <= result["security_score"] <= 100
    assert result["checks"]


def test_hardening_checks_have_required_fields():
    result = run_hardening_audit()

    for check in result["checks"]:
        assert check["id"]
        assert check["title"]
        assert check["status"]
        assert check["severity"]
        assert check["detail"]
        assert check["recommendation"]


def test_hardening_summary_matches_checks():
    result = run_hardening_audit()
    checks = result["checks"]
    summary = result["summary"]

    assert summary["total"] == len(checks)

    for status in ("PASS", "WARNING", "FAIL", "UNKNOWN"):
        assert summary[status] == sum(
            check["status"] == status
            for check in checks
        )
