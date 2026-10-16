
import unittest

from engine.risk_engine import Finding, evaluate
from engine.gate import evaluate_policy


class RiskEngineTests(unittest.TestCase):

    def test_critical_finding_blocks(self):
        findings = [
            Finding("TEST-001", "CRITICAL", "Critical test finding")
        ]

        result = evaluate(findings)

        self.assertEqual(result["risk_score"], 10)
        outcome = evaluate_policy(result, [], {"block_severities": ["CRITICAL"], "review_severities": ["HIGH"], "required_scanners": [], "fail_on_missing_required_scan": False})
        self.assertEqual(outcome["decision"], "BLOCK")

    def test_high_finding_requires_review(self):
        findings = [
            Finding("TEST-002", "HIGH", "High test finding")
        ]

        result = evaluate(findings)

        outcome = evaluate_policy(result, [], {"block_severities": ["CRITICAL"], "review_severities": ["HIGH"], "required_scanners": [], "fail_on_missing_required_scan": False})
        self.assertEqual(outcome["decision"], "REVIEW")

    def test_no_findings_passes(self):
        result = evaluate([])

        self.assertEqual(result["risk_score"], 0)

    def test_unknown_severity_requires_review(self):
        findings = [
            Finding("TEST-004", "UNKNOWN", "Unclassified finding")
        ]

        result = evaluate(findings)

        outcome = evaluate_policy(result, [], {"block_severities": ["CRITICAL"], "review_severities": ["HIGH"], "required_scanners": [], "fail_on_missing_required_scan": False})
        self.assertEqual(outcome["decision"], "REVIEW")


if __name__ == "__main__":
    unittest.main()
