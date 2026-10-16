
import json
from pathlib import Path

from engine.normalizer import normalize_finding, normalize_semgrep_report
from engine.risk_engine import evaluate
from engine.report import save_report
from engine.html_report import generate_html_report
from engine.gate import evaluate_policy, load_policy
from engine.orchestrator import run_scans


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = PROJECT_ROOT / "reports" / "sample-findings.json"


def run_agent(input_file: str, policy_file=None, scans=None) -> dict:
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

    risk = evaluate(findings)
    scans = scans or [{"scanner": "semgrep", "status": "SUCCESS", "raw_output": str(path)}]
    policy_result = evaluate_policy(risk, scans, load_policy(policy_file) if policy_file else load_policy())
    result = {"schema_version": "1.0", "risk": risk, "scans": scans, **policy_result, **risk}
    result["agent"] = "Secure Code Release Agent"
    result["source_file"] = path.name

    return result


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate security findings or run enabled scanners.")
    parser.add_argument("input", nargs="?", help="Semgrep JSON or a list of normalized findings")
    parser.add_argument("--scan", action="store_true", help="Run Semgrep, Trivy, and Gitleaks against --target")
    parser.add_argument("--target", default=".")
    arguments = parser.parse_args()
    if arguments.scan:
        scan_results = run_scans(PROJECT_ROOT / arguments.target, PROJECT_ROOT / "reports")
        scans = [item.to_dict() for item in scan_results]
        findings = [finding for item in scan_results for finding in item.findings]
        risk = evaluate(findings)
        result = {"schema_version": "1.0", "agent": "Secure Code Release Agent", "scans": scans, "risk": risk, **risk, **evaluate_policy(risk, scans, load_policy())}
    else:
        input_file = arguments.input or str(DEFAULT_INPUT)
        result = run_agent(input_file)
    report_path = save_report(result)
    html_path = generate_html_report(result)

    print(json.dumps(result, indent=2))
    print(f"\nJSON report saved to: {report_path}")
    print(f"HTML report saved to: {html_path}")
