import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = ROOT / "reports" / "release-report.json"


def load_report():
    if not REPORT_PATH.exists():
        print(f"ERROR: Report not found: {REPORT_PATH}")
        return None

    try:
        with REPORT_PATH.open("r", encoding="utf-8") as file:
            report = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: Cannot read report: {exc}")
        return None

    if not isinstance(report, dict):
        print("ERROR: Report must contain a JSON object.")
        return None

    return report


def get_decision(report):
    # Adapt these fields if your existing report uses another schema.
    decision = (
        report.get("decision")
        or report.get("release_decision")
        or report.get("status")
    )

    if not isinstance(decision, str):
        return None

    decision = decision.strip().upper()

    if decision not in {"PASS", "BLOCK", "REVIEW"}:
        return None

    return decision


def main():
    report = load_report()

    if report is None:
        return 2

    decision = get_decision(report)

    if decision is None:
        print("ERROR: Missing or invalid release decision.")
        return 2

    print(f"Release decision: {decision}")

    if decision == "PASS":
        print("Release gate passed.")
        return 0

    if decision == "REVIEW":
        print("Manual review required. Release is not authorized.")
        return 1

    print("Release blocked by security policy.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
