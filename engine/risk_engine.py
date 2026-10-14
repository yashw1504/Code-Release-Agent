
from dataclasses import dataclass
from typing import Iterable


WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    tool: str = "manual"
    file: str = ""
    description: str = ""
    remediation: str = ""


def evaluate(findings: Iterable[Finding]) -> dict:
    findings = list(findings)

    score = min(
        100,
        sum(WEIGHTS.get(f.severity.upper(), 0) for f in findings),
    )

    severities = [f.severity.upper() for f in findings]

    # A finding with an unknown severity requires review.
    known = set(WEIGHTS)
    unknown = any(severity not in known for severity in severities)

    critical = "CRITICAL" in severities
    high = "HIGH" in severities

    if critical:
        decision = "BLOCK"
    elif unknown or high:
        decision = "REVIEW"
    else:
        decision = "PASS"

    return {
        "risk_score": score,
        "decision": decision,
        "finding_count": len(findings),
        "severity_counts": {
            severity: severities.count(severity)
            for severity in WEIGHTS
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.upper(),
                "title": f.title,
                "tool": f.tool,
                "file": f.file,
                "description": f.description,
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }
