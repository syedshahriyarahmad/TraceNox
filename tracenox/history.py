from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HISTORY_SCHEMA_VERSION = 1


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_score(value: Any) -> float | None:
    if value is None:
        return None

    try:
        score = float(value)
    except (TypeError, ValueError):
        return None

    return max(0.0, min(100.0, score))


def normalize_score_report(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ValueError("Security score report must be a JSON object.")

    overall = report.get(
        "overall_score",
        report.get("score", report.get("overall")),
    )

    overall_score = _safe_score(overall)

    raw_modules = report.get(
        "modules",
        report.get("module_scores", {}),
    )

    modules: dict[str, float] = {}

    if isinstance(raw_modules, dict):
        for name, value in raw_modules.items():
            if isinstance(value, dict):
                value = value.get("score")

            score = _safe_score(value)

            if score is not None:
                modules[str(name)] = score

    return {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "timestamp": report.get("timestamp") or _utc_now(),
        "overall_score": overall_score,
        "rating": report.get("rating"),
        "modules": modules,
    }


def save_score_snapshot(
    report: dict[str, Any],
    path: str | Path,
) -> dict[str, Any]:

    normalized = normalize_score_report(report)

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    destination.write_text(
        json.dumps(normalized, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    return normalized


def load_score_snapshot(path: str | Path) -> dict[str, Any]:

    source = Path(path)

    if not source.exists():
        raise FileNotFoundError(
            f"Historical snapshot not found: {source}"
        )

    try:
        data = json.loads(
            source.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid historical snapshot JSON: {source}"
        ) from exc

    return normalize_score_report(data)


def compare_snapshots(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:

    previous = normalize_score_report(previous)
    current = normalize_score_report(current)

    previous_score = previous["overall_score"]
    current_score = current["overall_score"]

    delta = None

    if previous_score is not None and current_score is not None:
        delta = round(current_score - previous_score, 2)

    if delta is None or abs(delta) < 0.000001:
        status = "UNCHANGED"
    elif delta > 0:
        status = "IMPROVED"
    else:
        status = "DEGRADED"

    previous_modules = previous["modules"]
    current_modules = current["modules"]

    module_changes: dict[str, dict[str, Any]] = {}

    for name in sorted(
        set(previous_modules) | set(current_modules)
    ):
        old = previous_modules.get(name)
        new = current_modules.get(name)

        if old is None and new is not None:
            module_changes[name] = {
                "previous": None,
                "current": new,
                "delta": None,
                "status": "NEW",
            }
            continue

        if old is not None and new is None:
            module_changes[name] = {
                "previous": old,
                "current": None,
                "delta": None,
                "status": "RESOLVED",
            }
            continue

        module_delta = round(new - old, 2)

        if module_delta > 0:
            module_status = "IMPROVED"
        elif module_delta < 0:
            module_status = "DEGRADED"
        else:
            module_status = "UNCHANGED"

        module_changes[name] = {
            "previous": old,
            "current": new,
            "delta": module_delta,
            "status": module_status,
        }

    return {
        "schema_version": HISTORY_SCHEMA_VERSION,
        "previous": previous,
        "current": current,
        "previous_score": previous_score,
        "current_score": current_score,
        "delta": delta,
        "status": status,
        "module_changes": module_changes,
        "improved_modules": [
            name
            for name, data in module_changes.items()
            if data["status"] == "IMPROVED"
        ],
        "degraded_modules": [
            name
            for name, data in module_changes.items()
            if data["status"] == "DEGRADED"
        ],
        "new_modules": [
            name
            for name, data in module_changes.items()
            if data["status"] == "NEW"
        ],
        "resolved_modules": [
            name
            for name, data in module_changes.items()
            if data["status"] == "RESOLVED"
        ],
    }


def compare_snapshot_files(
    previous_path: str | Path,
    current_path: str | Path,
) -> dict[str, Any]:

    return compare_snapshots(
        load_score_snapshot(previous_path),
        load_score_snapshot(current_path),
    )


def save_comparison(
    comparison: dict[str, Any],
    path: str | Path,
) -> None:

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    destination.write_text(
        json.dumps(comparison, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _score(value: Any) -> str:
    if value is None:
        return "N/A"

    number = float(value)

    if number.is_integer():
        return str(int(number))

    return f"{number:.1f}"


def _delta(value: Any) -> str:
    if value is None:
        return "N/A"

    number = float(value)

    if number > 0:
        prefix = "+"
    else:
        prefix = ""

    if number.is_integer():
        return f"{prefix}{int(number)}"

    return f"{prefix}{number:.1f}"


def format_comparison(
    comparison: dict[str, Any],
) -> str:

    lines = [
        "",
        "TraceNox Historical Security Comparison",
        "=======================================",
        f"Previous score : {_score(comparison['previous_score'])}/100",
        f"Current score  : {_score(comparison['current_score'])}/100",
        f"Change         : {_delta(comparison['delta'])}",
        f"Status         : {comparison['status']}",
        "",
        "Module changes:",
    ]

    changes = comparison["module_changes"]

    if not changes:
        lines.append("  No module data available.")
    else:
        for name, data in changes.items():
            old = _score(data["previous"])
            new = _score(data["current"])
            change = _delta(data["delta"])
            status = data["status"]

            if status in {"NEW", "RESOLVED"}:
                lines.append(
                    f"  {name:<18} {old:>5} → {new:<5}    {status}"
                )
            else:
                lines.append(
                    f"  {name:<18} {old:>5} → {new:<5}  "
                    f"{change:>6}  {status}"
                )

    lines.extend(
        [
            "",
            "Improved modules : "
            + (
                ", ".join(comparison["improved_modules"])
                if comparison["improved_modules"]
                else "None"
            ),
            "Degraded modules : "
            + (
                ", ".join(comparison["degraded_modules"])
                if comparison["degraded_modules"]
                else "None"
            ),
            "New modules      : "
            + (
                ", ".join(comparison["new_modules"])
                if comparison["new_modules"]
                else "None"
            ),
            "Resolved modules : "
            + (
                ", ".join(comparison["resolved_modules"])
                if comparison["resolved_modules"]
                else "None"
            ),
        ]
    )

    return "\n".join(lines)


__all__ = [
    "HISTORY_SCHEMA_VERSION",
    "compare_snapshot_files",
    "compare_snapshots",
    "format_comparison",
    "load_score_snapshot",
    "normalize_score_report",
    "save_comparison",
    "save_score_snapshot",
]
