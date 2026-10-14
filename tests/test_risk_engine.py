
import unittest

from engine.risk_engine import Finding, evaluate


class RiskEngineTests(unittest.TestCase):

    def test_critical_finding_blocks(self):
        findings = [
            Finding("TEST-001", "CRITICAL", "Critical test finding")
        ]

        result = evaluate(findings)

        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(result["risk_score"], 10)

    def test_high_finding_requires_review(self):
        findings = [
            Finding("TEST-002", "HIGH", "High test finding")
        ]

        result = evaluate(findings)

        self.assertEqual(result["decision"], "REVIEW")

    def test_no_findings_passes(self):
        result = evaluate([])

        self.assertEqual(result["decision"], "PASS")
        self.assertEqual(result["risk_score"], 0)

    def test_unknown_severity_requires_review(self):
        findings = [
            Finding("TEST-004", "UNKNOWN", "Unclassified finding")
        ]

        result = evaluate(findings)

        self.assertEqual(result["decision"], "REVIEW")


if __name__ == "__main__":
    unittest.main()
