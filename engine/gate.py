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
    boolean_rules = ("block_on_secrets", "block_fix_available_vulnerabilities", "block_iac_misconfigurations", "allow_partial_scans", "require_raw_output")
    for rule in boolean_rules:
        if rule in policy and not isinstance(policy[rule], bool):
            raise ValueError(f"Policy {rule} must be boolean")
    for rule in ("max_total_findings", "max_high_findings", "max_medium_findings", "max_low_findings"):
        if rule in policy and (not isinstance(policy[rule], int) or policy[rule] < 0):
            raise ValueError(f"Policy {rule} must be a non-negative integer")
    for rule in ("block_rule_ids", "block_vulnerability_ids"):
        if rule in policy and (not isinstance(policy[rule], list) or not all(isinstance(item, str) for item in policy[rule])):
            raise ValueError(f"Policy {rule} must be a list of strings")
    return policy


def evaluate_policy(risk, scans, policy):
    """Return PASS/REVIEW/BLOCK and the policy rules that determined it."""
    violations = []
    statuses = {str(item.get("scanner")): str(item.get("status")) for item in scans if isinstance(item, dict)}
    if policy["fail_on_missing_required_scan"]:
        for scanner in policy["required_scanners"]:
            if statuses.get(scanner) != "SUCCESS":
                violations.append({"rule": "required_scanner", "message": f"Required scanner {scanner} did not succeed"})
    if not policy.get("allow_partial_scans", False):
        for scanner, status in statuses.items():
            if status not in {"SUCCESS", "NOT_RUN"}:
                violations.append({"rule": "partial_scan", "message": f"Scanner {scanner} completed with {status}"})
    if policy.get("require_raw_output", False):
        for scan in scans:
            if isinstance(scan, dict) and scan.get("status") == "SUCCESS" and not scan.get("raw_output"):
                violations.append({"rule": "require_raw_output", "message": f"Successful scanner {scan.get('scanner')} has no raw report artifact"})
    counts = risk.get("severity_counts", {})
    for severity in policy["block_severities"]:
        if counts.get(str(severity).upper(), 0):
            violations.append({"rule": "block_severity", "message": f"{severity} findings are blocked"})
    maximum = policy.get("max_risk_score")
    if isinstance(maximum, (int, float)) and risk.get("risk_score", 0) > maximum:
        violations.append({"rule": "max_risk_score", "message": f"Risk score exceeds {maximum}"})
    total_limit = policy.get("max_total_findings")
    if isinstance(total_limit, int) and risk.get("finding_count", 0) > total_limit:
        violations.append({"rule": "max_total_findings", "message": f"Total finding count exceeds {total_limit}"})
    for severity, rule in (("HIGH", "max_high_findings"), ("MEDIUM", "max_medium_findings"), ("LOW", "max_low_findings")):
        limit = policy.get(rule)
        if isinstance(limit, int) and counts.get(severity, 0) > limit:
            violations.append({"rule": rule, "message": f"{severity.title()} finding count exceeds {limit}"})
    findings = risk.get("findings", [])
    if policy.get("block_on_secrets", False) and any(item.get("scanner") == "gitleaks" for item in findings if isinstance(item, dict)):
        violations.append({"rule": "block_on_secrets", "message": "Potential secret findings are blocked"})
    if policy.get("block_fix_available_vulnerabilities", False) and any(item.get("scanner") == "trivy" and item.get("fixed_version") for item in findings if isinstance(item, dict)):
        violations.append({"rule": "block_fix_available_vulnerabilities", "message": "A vulnerability with an available fix was found"})
    if policy.get("block_iac_misconfigurations", False) and any(item.get("metadata", {}).get("finding_type") == "iac_misconfiguration" for item in findings if isinstance(item, dict)):
        violations.append({"rule": "block_iac_misconfigurations", "message": "IaC misconfiguration findings are blocked"})
    blocked_rules = set(policy.get("block_rule_ids", []))
    blocked_vulnerabilities = set(policy.get("block_vulnerability_ids", []))
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        identifiers = set(str(value) for value in finding.get("identifiers", []))
        if finding.get("rule_id") in blocked_rules:
            violations.append({"rule": "block_rule_ids", "message": f"Blocked rule ID: {finding.get('rule_id')}"})
        if finding.get("rule_id") in blocked_vulnerabilities or identifiers & blocked_vulnerabilities:
            violations.append({"rule": "block_vulnerability_ids", "message": f"Blocked vulnerability: {finding.get('rule_id')}"})
    if violations:
        decision = "BLOCK"
    elif any(counts.get(str(severity).upper(), 0) for severity in policy["review_severities"]):
        decision = "REVIEW"
        violations.append({"rule": "review_severity", "message": "Findings require manual review"})
    elif counts.get("UNKNOWN", 0):
        action = str(policy.get("unknown_severity_action", "REVIEW")).upper()
        decision = action if action in {"PASS", "REVIEW", "BLOCK"} else "REVIEW"
        if decision != "PASS":
            violations.append({"rule": "unknown_severity_action", "message": "Unknown-severity findings require manual handling"})
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
