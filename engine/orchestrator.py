"""Coordinates scanner adapters without hiding failures."""
from __future__ import annotations
from pathlib import Path
from .models import ScanResult
from .scanners import GitleaksAdapter, SemgrepAdapter, TrivyAdapter

def run_scans(target: str | Path, reports_dir: str | Path, enabled: tuple[str, ...] = ("semgrep", "trivy", "gitleaks")) -> list[ScanResult]:
    target, reports = Path(target).resolve(), Path(reports_dir).resolve()
    reports.mkdir(parents=True, exist_ok=True)
    results: list[ScanResult] = []
    if "semgrep" in enabled: results.append(SemgrepAdapter().scan(target, reports / "semgrep.json"))
    if "trivy" in enabled: results.append(TrivyAdapter().filesystem_scan(target, reports / "trivy-filesystem.json"))
    if "gitleaks" in enabled: results.append(GitleaksAdapter().scan(target, reports / "gitleaks.json"))
    return results
