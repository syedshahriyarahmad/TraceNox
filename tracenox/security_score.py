"""Unified TraceNox security scoring engine."""

from __future__ import annotations


MODULE_WEIGHTS = {
    "hardening": 25,
    "fim": 20,
    "webscan": 25,
    "logs": 15,
    "ip_reputation": 15,
}


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, float(value)))


def _fim_score(result: dict) -> float:
    status = str(result.get("status", "")).upper()

    if status in {"UNCHANGED", "PASS", "CLEAN"}:
        return 100.0

    if status in {"CHANGES_DETECTED", "WARNING"}:
        return 50.0

    if status in {"FAIL", "COMPROMISED"}:
        return 0.0

    return 50.0


def _hardening_score(result: dict) -> float:
    try:
        return _clamp(result.get("security_score", 0))
    except (TypeError, ValueError):
        return 0.0


def _log_score(result: dict) -> float:
    """Convert observed authentication risk into security posture."""
    if result.get("analysis_warning"):
        return 50.0

    risk = result.get("risk_assessment", {})

    if isinstance(risk, dict):
        value = risk.get("score")

        if isinstance(value, (int, float)):
            return round(100.0 - _clamp(value), 2)

    return 50.0


def _ip_reputation_score(result: dict) -> float:
    """Use the worst observed correlated IP risk as module risk."""
    correlated = result.get("correlated_ip_risk", {})

    if not isinstance(correlated, dict) or not correlated:
        return 50.0

    scores = []

    for data in correlated.values():
        if isinstance(data, dict):
            value = data.get("score")

            if isinstance(value, (int, float)):
                scores.append(_clamp(value))

    if not scores:
        return 50.0

    return round(100.0 - max(scores), 2)


def _webscan_score(result: dict) -> float:
    """Convert website finding severity into security posture."""
    summary = result.get("summary", {})
    severity_counts = summary.get("by_severity", {})

    if not isinstance(severity_counts, dict):
        return 50.0

    penalties = {
        "critical": 35,
        "high": 25,
        "medium": 15,
        "low": 5,
    }

    penalty = sum(
        int(severity_counts.get(severity, 0) or 0) * points
        for severity, points in penalties.items()
    )

    return round(_clamp(100.0 - penalty), 2)


def calculate_security_score(
    *,
    hardening: dict | None = None,
    fim: dict | None = None,
    webscan: dict | None = None,
    logs: dict | None = None,
    ip_reputation: dict | None = None,
) -> dict:
    """Calculate weighted overall TraceNox security score."""

    results = {
        "hardening": hardening,
        "fim": fim,
        "webscan": webscan,
        "logs": logs,
        "ip_reputation": ip_reputation,
    }

    scores = {}
    weights = {}

    for module, result in results.items():
        if result is None:
            continue

        if module == "hardening":
            score = _hardening_score(result)
        elif module == "fim":
            score = _fim_score(result)
        elif module == "webscan":
            score = _webscan_score(result)
        elif module == "logs":
            score = _log_score(result)
        else:
            score = _ip_reputation_score(result)

        scores[module] = round(score, 2)
        weights[module] = MODULE_WEIGHTS[module]

    if not scores:
        return {
            "tool": "TraceNox",
            "overall_score": 0,
            "rating": "NO_DATA",
            "modules": {},
            "summary": {
                "modules_evaluated": 0,
                "modules_missing": len(MODULE_WEIGHTS),
            },
        }

    total_weight = sum(weights.values())

    weighted_score = sum(
        scores[module] * weights[module]
        for module in scores
    )

    overall = round(weighted_score / total_weight)

    if overall >= 90:
        rating = "EXCELLENT"
    elif overall >= 75:
        rating = "GOOD"
    elif overall >= 60:
        rating = "MODERATE"
    elif overall >= 40:
        rating = "WEAK"
    else:
        rating = "CRITICAL"

    return {
        "tool": "TraceNox",
        "overall_score": overall,
        "rating": rating,
        "modules": {
            module: {
                "score": scores[module],
                "weight": weights[module],
            }
            for module in scores
        },
        "summary": {
            "modules_evaluated": len(scores),
            "modules_missing": len(MODULE_WEIGHTS) - len(scores),
        },
    }


def format_security_score(result: dict) -> str:
    """Format unified security score for terminal output."""

    lines = [
        "",
        "TraceNox Unified Security Score",
        "================================",
        f"Overall score : {result['overall_score']}/100",
        f"Rating        : {result['rating']}",
        "",
        "Module scores:",
    ]

    for module, data in result.get("modules", {}).items():
        lines.append(
            f"  {module:<18} "
            f"{data['score']:>6.1f}/100 "
            f"(weight {data['weight']}%)"
        )

    summary = result.get("summary", {})

    lines.extend(
        [
            "",
            f"Modules evaluated : {summary.get('modules_evaluated', 0)}",
            f"Modules missing   : {summary.get('modules_missing', 0)}",
        ]
    )

    return "\n".join(lines)
