
"""Deterministic risk scoring; policy decisions are intentionally separate."""
from collections import Counter
from typing import Iterable

from .models import Finding, canonical_severity

WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0, "UNKNOWN": 0}


def evaluate(findings: Iterable[Finding]) -> dict:
    """Score unique findings from 0--100; unknown severity is never invented."""
    unique = {finding.fingerprint: finding for finding in findings}
    ordered = list(unique.values())
    counts = Counter(canonical_severity(f.severity) for f in ordered)
    score = min(100, sum(WEIGHTS[canonical_severity(f.severity)] for f in ordered))
    return {
        "formula": "sum of severity weights over unique fingerprints, capped at 100 (critical=10, high=7, medium=4, low=1)",
        "risk_score": score,
        "finding_count": len(ordered),
        "severity_counts": {severity: counts[severity] for severity in WEIGHTS},
        "findings": [finding.to_dict() for finding in ordered],
    }
