
from engine.risk_engine import Finding


SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "ERROR": "HIGH",
    "HIGH": "HIGH",
    "WARNING": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
}


def normalize_finding(item: dict, tool: str = "manual") -> Finding:
    """Normalize synthetic, manual, or raw Semgrep findings."""

    # Semgrep places severity, message, and metadata under extra.
    extra = item.get("extra", {})
    if not isinstance(extra, dict):
        extra = {}

    metadata = extra.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    raw_severity = (
        item.get("severity")
        or item.get("level")
        or extra.get("severity")
        or metadata.get("severity")
        or "UNKNOWN"
    )

    severity = SEVERITY_MAP.get(str(raw_severity).upper(), "UNKNOWN")

    rule_id = (
        item.get("rule_id")
        or item.get("check_id")
        or item.get("id")
        or "UNSPECIFIED"
    )

    title = (
        item.get("title")
        or extra.get("message")
        or item.get("message")
        or item.get("description")
        or "Untitled finding"
    )

    file_path = (
        item.get("file")
        or item.get("path")
        or item.get("file_path")
        or ""
    )

    start = item.get("start", {})
    if not isinstance(start, dict):
        start = {}

    line = start.get("line") or item.get("line_number") or item.get("line")

    # Preserve the source line even if Finding has no dedicated line field.
    if line is not None:
        file_path = f"{file_path}:{line}" if file_path else f"line:{line}"

    description = (
        item.get("description")
        or metadata.get("description")
        or extra.get("message")
        or item.get("message")
        or ""
    )

    remediation = (
        item.get("remediation")
        or metadata.get("fix")
        or metadata.get("remediation")
        or ""
    )

    return Finding(
        rule_id=str(rule_id),
        severity=severity,
        title=str(title),
        scanner=tool,
        path=str(file_path) or None,
        description=str(description),
        remediation=str(remediation),
    )


def normalize_semgrep_report(report: dict) -> list:
    """Convert a Semgrep JSON report into normalized Finding objects."""

    if not isinstance(report, dict):
        raise ValueError("Semgrep report must be a JSON object")

    results = report.get("results")
    if not isinstance(results, list):
        raise ValueError("Semgrep report is missing its results list")

    findings = []

    for item in results:
        if not isinstance(item, dict):
            continue

        findings.append(normalize_finding(item, "semgrep"))

    return findings
