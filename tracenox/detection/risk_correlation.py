"""Correlate local SSH behavior with external IP reputation."""

def _level(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def correlate_ip_risk(local_risk: dict, reputation: dict) -> dict:
    """Return an explainable combined score without changing local risk."""
    local_score = max(0, min(100, int(local_risk.get("score", 0))))
    status = reputation.get("status", "unknown")
    abuse_score = reputation.get("abuse_confidence_score")

    reasons = [
        f"Local behavior risk: {local_score}/100 "
        f"({local_risk.get('level', _level(local_score))})"
    ]

    if status != "success" or abuse_score is None:
        reasons.append(
            f"External reputation unavailable for scoring (status: {status})"
        )
        return {
            "score": local_score,
            "level": _level(local_score),
            "status": "local_only",
            "local_score": local_score,
            "abuse_confidence_score": None,
            "reasons": reasons,
            "method": "Local score retained; no usable external reputation data.",
        }

    try:
        abuse_score = max(0, min(100, int(abuse_score)))
    except (TypeError, ValueError):
        reasons.append("External abuse score was invalid; local score retained.")
        return {
            "score": local_score,
            "level": _level(local_score),
            "status": "local_only",
            "local_score": local_score,
            "abuse_confidence_score": None,
            "reasons": reasons,
            "method": "Local score retained; external score was invalid.",
        }

    # 60% observed local behavior + 40% provider confidence score.
    combined = round(local_score * 0.60 + abuse_score * 0.40)

    if local_score >= 40 and abuse_score >= 50:
        combined = min(100, combined + 10)
        reasons.append("Local behavior and external reputation both indicate risk (+10 corroboration).")

    reasons.append(f"AbuseIPDB confidence score: {abuse_score}/100 (40% weight)")
    reasons.append(f"Combined score uses 60% local behavior and 40% external reputation.")

    return {
        "score": combined,
        "level": _level(combined),
        "status": "correlated",
        "local_score": local_score,
        "abuse_confidence_score": abuse_score,
        "reasons": reasons,
        "method": "60% local behavior + 40% external reputation, with up to 10 corroboration points.",
    }
