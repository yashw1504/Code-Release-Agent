"""Safe subprocess adapters for Semgrep, Trivy, and Gitleaks."""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .models import Finding, ScanResult, canonical_severity


class ScannerError(RuntimeError):
    pass


class BaseAdapter:
    name = "scanner"

    def __init__(self, executable: str | None = None, timeout: int = 600):
        self.executable = executable or self.name
        self.timeout = timeout

    def _run_json(self, args: list[str], output: Path, scope: str) -> ScanResult:
        started = time.monotonic()
        if not shutil.which(self.executable):
            return ScanResult(self.name, "FAILED", duration_seconds=0, error=f"Executable not found: {self.executable}", scope=scope)
        try:
            completed = subprocess.run(args, capture_output=True, text=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired:
            return ScanResult(self.name, "FAILED", duration_seconds=time.monotonic()-started, error=f"Timed out after {self.timeout} seconds", scope=scope)
        except OSError as exc:
            return ScanResult(self.name, "FAILED", duration_seconds=time.monotonic()-started, error=str(exc), scope=scope)
        if not output.is_file() or not output.stat().st_size:
            return ScanResult(self.name, "FAILED", duration_seconds=time.monotonic()-started, error=f"No JSON report produced (exit {completed.returncode}): {completed.stderr[-1000:]}", scope=scope)
        try:
            raw = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return ScanResult(self.name, "FAILED", raw_output=str(output), duration_seconds=time.monotonic()-started, error=f"Invalid JSON output: {exc}", scope=scope)
        return self.parse(raw, output, completed.returncode, time.monotonic()-started, scope, completed.stderr)

    def parse(self, raw: Any, output: Path, exit_code: int, duration: float, scope: str, stderr: str) -> ScanResult:
        raise NotImplementedError


class SemgrepAdapter(BaseAdapter):
    name = "semgrep"

    def scan(self, target: Path, output: Path, config: str = "p/security-audit") -> ScanResult:
        return self._run_json([self.executable, "scan", "--config", config, "--json", "--output", str(output), str(target)], output, str(target))

    def parse(self, raw: Any, output: Path, exit_code: int, duration: float, scope: str, stderr: str) -> ScanResult:
        if not isinstance(raw, dict) or not isinstance(raw.get("results"), list) or not isinstance(raw.get("errors", []), list):
            return ScanResult(self.name, "FAILED", raw_output=str(output), duration_seconds=duration, error="Unexpected Semgrep JSON schema", scope=scope)
        if raw["errors"]:
            return ScanResult(self.name, "FAILED", raw_output=str(output), duration_seconds=duration, error="Semgrep reported errors", scope=scope)
        findings = []
        for item in raw["results"]:
            if not isinstance(item, dict):
                return ScanResult(self.name, "FAILED", raw_output=str(output), duration_seconds=duration, error="Malformed Semgrep result", scope=scope)
            extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
            metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
            start = item.get("start") if isinstance(item.get("start"), dict) else {}
            end = item.get("end") if isinstance(item.get("end"), dict) else {}
            findings.append(Finding(str(item.get("check_id", "UNSPECIFIED")), canonical_severity(extra.get("severity") or metadata.get("severity")), str(extra.get("message", "Untitled finding")), self.name, item.get("path"), start.get("line"), end.get("line"), extra.get("metavars", {}).get("$MESSAGE") or metadata.get("description") or extra.get("message"), metadata.get("fix") or item.get("fix"), identifiers=tuple(str(x) for x in metadata.get("cwe", []) if x), metadata=metadata))
        return ScanResult(self.name, "SUCCESS", findings, str(output), duration, raw.get("version"), scope=scope)


class TrivyAdapter(BaseAdapter):
    name = "trivy"

    def filesystem_scan(self, target: Path, output: Path, scan_type: str = "vuln") -> ScanResult:
        return self._run_json([self.executable, "fs", "--format", "json", "--output", str(output), "--scanners", scan_type, str(target)], output, str(target))

    def parse(self, raw: Any, output: Path, exit_code: int, duration: float, scope: str, stderr: str) -> ScanResult:
        if not isinstance(raw, dict):
            return ScanResult(self.name, "FAILED", raw_output=str(output), duration_seconds=duration, error="Unexpected Trivy JSON schema", scope=scope)
        results = raw.get("Results")
        # Trivy may omit Results entirely for a valid filesystem scan with no
        # supported targets/findings. Its report metadata still establishes the
        # format; never index the optional key directly.
        if results is None:
            if "Results" not in raw and ("SchemaVersion" in raw or "ArtifactName" in raw):
                return ScanResult(self.name, "SUCCESS", raw_output=str(output), duration_seconds=duration, version=raw.get("Metadata", {}).get("Version"), scope=scope)
            return ScanResult(self.name, "FAILED", raw_output=str(output), duration_seconds=duration, error="Trivy JSON is missing Results", scope=scope)
        if not isinstance(results, list):
            return ScanResult(self.name, "FAILED", raw_output=str(output), duration_seconds=duration, error="Trivy Results must be a list", scope=scope)
        findings = []
        for result in results:
            if not isinstance(result, dict): continue
            target = result.get("Target")
            for vuln in result.get("Vulnerabilities") or []:
                findings.append(Finding(str(vuln.get("VulnerabilityID", "UNSPECIFIED")), canonical_severity(vuln.get("Severity")), str(vuln.get("Title") or vuln.get("VulnerabilityID")), self.name, target, description=vuln.get("Description"), remediation=vuln.get("FixedVersion"), package_name=vuln.get("PkgName"), installed_version=vuln.get("InstalledVersion"), fixed_version=vuln.get("FixedVersion"), identifiers=(str(vuln.get("VulnerabilityID")),)))
            for misconfig in result.get("Misconfigurations") or []:
                findings.append(Finding(str(misconfig.get("ID", "UNSPECIFIED")), canonical_severity(misconfig.get("Severity")), str(misconfig.get("Title", "IaC misconfiguration")), self.name, target, description=misconfig.get("Description"), remediation=misconfig.get("Resolution"), identifiers=tuple(str(x) for x in misconfig.get("PrimaryURL", []) if x)))
        return ScanResult(self.name, "SUCCESS", findings, str(output), duration, raw.get("Metadata", {}).get("Version"), scope=scope)


class GitleaksAdapter(BaseAdapter):
    name = "gitleaks"

    def scan(self, target: Path, output: Path, history: bool = False) -> ScanResult:
        command = [self.executable, "git" if history else "dir", str(target), "--report-format", "json", "--report-path", str(output), "--no-banner"]
        return self._run_json(command, output, str(target))

    def parse(self, raw: Any, output: Path, exit_code: int, duration: float, scope: str, stderr: str) -> ScanResult:
        if not isinstance(raw, list):
            return ScanResult(self.name, "FAILED", raw_output=str(output), duration_seconds=duration, error="Unexpected Gitleaks JSON schema", scope=scope)
        findings = [Finding(str(i.get("RuleID", "UNSPECIFIED")), "HIGH", str(i.get("Description", "Potential secret")), self.name, i.get("File"), i.get("StartLine"), i.get("EndLine"), remediation="Revoke and rotate the exposed credential; then remove it from source and history.", evidence="[REDACTED]", metadata={"commit": i.get("Commit")}) for i in raw if isinstance(i, dict)]
        return ScanResult(self.name, "SUCCESS", findings, str(output), duration, scope=scope)
