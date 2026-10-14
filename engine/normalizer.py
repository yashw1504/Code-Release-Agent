
from engine.risk_engine import Finding


SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
}


def normalize_finding(item: dict, tool: str) -> Finding:
    raw_severity = str(
        item.get("severity", item.get("level", "UNKNOWN"))
    ).upper()

    severity = SEVERITY_MAP.get(raw_severity, "UNKNOWN")

    rule_id = (
        item.get("rule_id")
        or item.get("check_id")
        or item.get("id")
        or "UNSPECIFIED"
    )

    title = (
        item.get("title")
        or item.get("message")
        or item.get("description")
        or "Untitled finding"
    )

    return Finding(
        rule_id=str(rule_id),
        severity=severity,
        title=str(title),
        tool=tool,
        file=str(item.get("file", item.get("path", ""))),
        description=str(item.get("description", "")),
        remediation=str(item.get("remediation", "")),
    )
