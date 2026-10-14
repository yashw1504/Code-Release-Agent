
import json
from pathlib import Path

from engine.normalizer import normalize_finding
from engine.risk_engine import evaluate
from engine.report import save_report


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = PROJECT_ROOT / "reports" / "sample-findings.json"


def run_agent(input_file: str) -> dict:
    path = Path(input_file)

    # Resolve relative paths from the project root, not the terminal's
    # current directory.
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    with path.open("r", encoding="utf-8") as file:
        raw = json.load(file)

    if not isinstance(raw, list):
        raise ValueError("Input must be a JSON list of findings")

    findings = []

    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("Each finding must be a JSON object")

        tool = str(item.get("tool", "manual"))
        findings.append(normalize_finding(item, tool))

    result = evaluate(findings)
    result["agent"] = "Secure Code Release Agent"
    result["source_file"] = path.name

    return result


if __name__ == "__main__":
    result = run_agent(str(DEFAULT_INPUT))
    report_path = save_report(result)

    print(json.dumps(result, indent=2))
    print(f"\nReport saved to: {report_path}")
