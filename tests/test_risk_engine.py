
import unittest

from engine.risk_engine import Finding, evaluate
from engine.gate import evaluate_policy


class RiskEngineTests(unittest.TestCase):

    def policy(self, **overrides):
        base = {"block_severities": ["CRITICAL"], "review_severities": ["HIGH"], "required_scanners": [], "fail_on_missing_required_scan": False}
        base.update(overrides)
        return base

    def test_critical_finding_blocks(self):
        findings = [
            Finding("TEST-001", "CRITICAL", "Critical test finding")
        ]

        result = evaluate(findings)

        self.assertEqual(result["risk_score"], 10)
        outcome = evaluate_policy(result, [], self.policy())
        self.assertEqual(outcome["decision"], "BLOCK")

    def test_high_finding_requires_review(self):
        findings = [
            Finding("TEST-002", "HIGH", "High test finding")
        ]

        result = evaluate(findings)

        outcome = evaluate_policy(result, [], self.policy())
        self.assertEqual(outcome["decision"], "REVIEW")

    def test_no_findings_passes(self):
        result = evaluate([])

        self.assertEqual(result["risk_score"], 0)

    def test_unknown_severity_requires_review(self):
        findings = [
            Finding("TEST-004", "UNKNOWN", "Unclassified finding")
        ]

        result = evaluate(findings)

        outcome = evaluate_policy(result, [], self.policy())
        self.assertEqual(outcome["decision"], "REVIEW")

    def test_secret_finding_blocks_when_enabled(self):
        result = evaluate([Finding("secret", "HIGH", "Potential secret", scanner="gitleaks")])
        outcome = evaluate_policy(result, [], self.policy(block_on_secrets=True))
        self.assertEqual(outcome["decision"], "BLOCK")
        self.assertEqual(outcome["violations"][0]["rule"], "block_on_secrets")

    def test_fixed_vulnerability_blocks_when_enabled(self):
        result = evaluate([Finding("CVE-1", "LOW", "Dependency issue", scanner="trivy", fixed_version="2.0")])
        outcome = evaluate_policy(result, [], self.policy(block_fix_available_vulnerabilities=True))
        self.assertEqual(outcome["decision"], "BLOCK")

    def test_medium_limit_blocks(self):
        result = evaluate([Finding("rule", "MEDIUM", "Medium issue")])
        outcome = evaluate_policy(result, [], self.policy(max_medium_findings=0))
        self.assertEqual(outcome["decision"], "BLOCK")

    def test_partial_scan_blocks_when_not_allowed(self):
        result = evaluate([])
        outcome = evaluate_policy(result, [{"scanner": "trivy", "status": "FAILED"}], self.policy(allow_partial_scans=False))
        self.assertEqual(outcome["decision"], "BLOCK")

    def test_total_limit_and_rule_blocklist_block(self):
        result = evaluate([Finding("unsafe-rule", "LOW", "Unsafe pattern")])
        outcome = evaluate_policy(result, [], self.policy(max_total_findings=0, block_rule_ids=["unsafe-rule"]))
        self.assertEqual(outcome["decision"], "BLOCK")
        self.assertEqual(len(outcome["violations"]), 2)

    def test_success_without_raw_artifact_blocks_when_required(self):
        result = evaluate([])
        outcome = evaluate_policy(result, [{"scanner": "semgrep", "status": "SUCCESS"}], self.policy(require_raw_output=True))
        self.assertEqual(outcome["decision"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
