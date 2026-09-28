import json
from dataclasses import asdict
from pathlib import Path


def generate_json_report(result: dict) -> str:
    """Convert investigation results into JSON-safe data."""

    serializable_result = dict(result)

    serializable_result["timeline"] = [
        asdict(event)
        for event in result.get("timeline", [])
    ]

    return json.dumps(
        serializable_result,
        indent=2,
        ensure_ascii=False,
    )


def save_json_report(result: dict, output_path: str) -> None:
    """Save investigation results as a JSON file."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    report = generate_json_report(result)
    path.write_text(report + "\n", encoding="utf-8")
