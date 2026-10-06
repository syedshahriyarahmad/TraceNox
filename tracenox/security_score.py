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


def _generic_score(result: dict) -> float:
    if not isinstance(result, dict):
        return 50.0

    for key in (
        "security_score",
        "score",
        "risk_score",
        "health_score",
    ):
        value = result.get(key)

        if isinstance(value, (int, float)):
            return _clamp(value)

    status = str(result.get("status", "")).upper()

    if status in {"PASS", "CLEAN", "SAFE", "LOW"}:
        return 100.0

    if status in {"WARNING", "MEDIUM", "CHANGES_DETECTED"}:
        return 50.0

    if status in {"FAIL", "HIGH", "CRITICAL", "COMPROMISED"}:
        return 0.0

    return 50.0


def calculate_security_score(
    *,
    hardening: dict | None = None,
    fim: dict | None = None,
    webscan: dict | None = None,
    logs: dict | None = None,
    ip_reputation: dict | None = None,
) -> dict:
    """Calculate a weighted overall TraceNox security score."""

    results = {
        "hardening": hardening,
        "fim": fim,
        "webscan": webscan,
        "logs": logs,
        "ip_reputation": ip_reputation,
    }

    scores: dict[str, float] = {}
    weights: dict[str, int] = {}

    for module, result in results.items():
        if result is None:
            continue

        if module == "hardening":
            score = _hardening_score(result)
        elif module == "fim":
            score = _fim_score(result)
        else:
            score = _generic_score(result)

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

    modules = result.get("modules", {})

    for module, data in modules.items():
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
