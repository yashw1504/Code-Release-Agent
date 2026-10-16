"""Coordinates scanner adapters without hiding failures."""
from __future__ import annotations
from pathlib import Path
from .models import ScanResult
from .scanners import GitleaksAdapter, SemgrepAdapter, TrivyAdapter

def run_scans(target: str | Path, reports_dir: str | Path, enabled: tuple[str, ...] = ("semgrep", "trivy", "gitleaks")) -> list[ScanResult]:
    target, reports = Path(target).resolve(), Path(reports_dir).resolve()
    reports.mkdir(parents=True, exist_ok=True)
    results: list[ScanResult] = []

    def execute(scanner: str, operation):
        try:
            results.append(operation())
        except Exception as exc:  # A scanner bug must never hide as a clean scan.
            results.append(ScanResult(scanner=scanner, status="FAILED", error=f"Adapter error: {type(exc).__name__}: {exc}", scope=str(target)))

    if "semgrep" in enabled:
        execute("semgrep", lambda: SemgrepAdapter().scan(target, reports / "semgrep.json"))
    if "trivy" in enabled:
        execute("trivy", lambda: TrivyAdapter().filesystem_scan(target, reports / "trivy-filesystem.json"))
    if "gitleaks" in enabled:
        execute("gitleaks", lambda: GitleaksAdapter().scan(target, reports / "gitleaks.json"))
    return results
