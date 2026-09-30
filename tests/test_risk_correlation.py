from tracenox.detection.risk_correlation import correlate_ip_risk


def test_successful_reputation_is_combined_with_local_risk():
    result = correlate_ip_risk(
        {"score": 80, "level": "high", "reasons": ["Repeated failures"]},
        {"status": "success", "abuse_confidence_score": 100},
    )
    assert result["status"] == "correlated"
    assert result["local_score"] == 80
    assert result["abuse_confidence_score"] == 100
    assert result["score"] == 98
    assert result["level"] == "high"
    assert any("corroboration" in reason for reason in result["reasons"])


def test_unavailable_reputation_preserves_local_score():
    result = correlate_ip_risk(
        {"score": 80, "level": "high", "reasons": []},
        {"status": "not_configured"},
    )
    assert result["score"] == 80
    assert result["level"] == "high"
    assert result["status"] == "local_only"


def test_zero_local_and_zero_external_score_is_low():
    result = correlate_ip_risk(
        {"score": 0, "level": "low", "reasons": []},
        {"status": "success", "abuse_confidence_score": 0},
    )
    assert result["score"] == 0
    assert result["level"] == "low"
    assert result["status"] == "correlated"


def test_invalid_external_score_falls_back_to_local():
    result = correlate_ip_risk(
        {"score": 45, "level": "medium", "reasons": []},
        {"status": "success", "abuse_confidence_score": "invalid"},
    )
    assert result["score"] == 45
    assert result["status"] == "local_only"


def test_scores_are_clamped_to_valid_range():
    result = correlate_ip_risk(
        {"score": 150, "level": "high", "reasons": []},
        {"status": "success", "abuse_confidence_score": 150},
    )
    assert result["score"] == 100
    assert result["level"] == "high"
