
import json
from pathlib import Path

from engine.normalizer import normalize_finding
from engine.risk_engine import evaluate
from engine.report import save_report
from engine.html_report import generate_html_report
from engine.normalizer import (
    normalize_finding,
    normalize_semgrep_report,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = PROJECT_ROOT / "reports" / "sample-findings.json"


def run_agent(input_file: str) -> dict:
    path = Path(input_file)

    # Resolve relative paths from the project root.
    if not path.is_absolute():
        path = PROJECT_ROOT / path

    with path.open("r", encoding="utf-8") as file:
        raw = json.load(file)

    if isinstance(raw, dict) and "results" in raw:
        findings = normalize_semgrep_report(raw)

    elif isinstance(raw, list):
        findings = []

        for item in raw:
            if not isinstance(item, dict):
                raise ValueError("Each finding must be a JSON object")

            tool = str(item.get("tool", "manual"))
            findings.append(normalize_finding(item, tool))

    else:
        raise ValueError(
            "Input must be a findings list or a Semgrep JSON report"
        )

    result = evaluate(findings)
    result["agent"] = "Secure Code Release Agent"
    result["source_file"] = path.name

    return result


if __name__ == "__main__":
    import sys

    input_file = sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_INPUT)

    result = run_agent(input_file)
    report_path = save_report(result)
    html_path = generate_html_report(result)

    print(json.dumps(result, indent=2))
    print(f"\nJSON report saved to: {report_path}")
    print(f"HTML report saved to: {html_path}")