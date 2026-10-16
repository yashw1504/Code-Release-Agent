import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from engine.scanners import GitleaksAdapter, SemgrepAdapter, TrivyAdapter
from engine import orchestrator


class AdapterParsingTests(unittest.TestCase):
    def test_semgrep_normalizes_actual_result_shape(self):
        raw = {"version": "1", "errors": [], "results": [{"check_id": "rule", "path": "a.py", "start": {"line": 3}, "end": {"line": 3}, "extra": {"severity": "ERROR", "message": "issue", "metadata": {}}}]}
        result = SemgrepAdapter().parse(raw, Path("out.json"), 1, 0.1, ".", "")
        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.findings[0].severity, "HIGH")

    def test_trivy_normalizes_vulnerability(self):
        raw = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "Severity": "CRITICAL", "PkgName": "demo", "InstalledVersion": "1", "FixedVersion": "2"}]}]}
        result = TrivyAdapter().parse(raw, Path("out.json"), 0, 0.1, ".", "")
        self.assertEqual(result.findings[0].fixed_version, "2")

    def test_trivy_empty_report_is_successful(self):
        raw = {"SchemaVersion": 2, "ArtifactName": ".", "ArtifactType": "filesystem"}
        result = TrivyAdapter().parse(raw, Path("out.json"), 0, 0.1, ".", "")
        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.findings, [])

    def test_gitleaks_redacts_evidence(self):
        raw = [{"RuleID": "generic-api-key", "Description": "secret", "File": "x.env", "StartLine": 1}]
        result = GitleaksAdapter().parse(raw, Path("out.json"), 1, 0.1, ".", "")
        self.assertEqual(result.findings[0].evidence, "[REDACTED]")

    def test_orchestrator_records_adapter_exception(self):
        with TemporaryDirectory() as directory:
            original = SemgrepAdapter.scan
            SemgrepAdapter.scan = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("broken parser"))
            try:
                results = orchestrator.run_scans(directory, Path(directory) / "reports", enabled=("semgrep",))
            finally:
                SemgrepAdapter.scan = original
        self.assertEqual(results[0].status, "FAILED")
        self.assertIn("Adapter error", results[0].error)


if __name__ == "__main__":
    unittest.main()
