import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = ROOT / "reports" / "release-report.json"
DEFAULT_POLICY_PATH = ROOT / "policies" / "release-policy.json"


def load_policy(path=DEFAULT_POLICY_PATH):
    """Load and minimally validate the single source of release policy."""
    try:
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot load policy: {exc}") from exc
    required = {"block_severities", "review_severities", "required_scanners", "fail_on_missing_required_scan"}
    if not isinstance(policy, dict) or not required.issubset(policy):
        raise ValueError("Policy is missing required fields")
    if not all(isinstance(policy[key], list) for key in ("block_severities", "review_severities", "required_scanners")):
        raise ValueError("Policy scanner and severity fields must be lists")
    if not isinstance(policy["fail_on_missing_required_scan"], bool):
        raise ValueError("Policy fail_on_missing_required_scan must be boolean")
    return policy


def evaluate_policy(risk, scans, policy):
    """Return PASS/REVIEW/BLOCK and the policy rules that determined it."""
    violations = []
    statuses = {str(item.get("scanner")): str(item.get("status")) for item in scans if isinstance(item, dict)}
    if policy["fail_on_missing_required_scan"]:
        for scanner in policy["required_scanners"]:
            if statuses.get(scanner) != "SUCCESS":
                violations.append({"rule": "required_scanner", "message": f"Required scanner {scanner} did not succeed"})
    counts = risk.get("severity_counts", {})
    for severity in policy["block_severities"]:
        if counts.get(str(severity).upper(), 0):
            violations.append({"rule": "block_severity", "message": f"{severity} findings are blocked"})
    maximum = policy.get("max_risk_score")
    if isinstance(maximum, (int, float)) and risk.get("risk_score", 0) > maximum:
        violations.append({"rule": "max_risk_score", "message": f"Risk score exceeds {maximum}"})
    if violations:
        decision = "BLOCK"
    elif any(counts.get(str(severity).upper(), 0) for severity in policy["review_severities"]) or counts.get("UNKNOWN", 0):
        decision = "REVIEW"
        violations.append({"rule": "review_severity", "message": "Findings require manual review"})
    else:
        decision = "PASS"
    return {"decision": decision, "policy_name": policy.get("name"), "policy_version": policy.get("version"), "violations": violations}


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
