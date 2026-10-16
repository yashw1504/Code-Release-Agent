"""Stable data models for scanner output and release decisions."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Any


SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"}


def canonical_severity(value: Any) -> str:
    aliases = {"ERROR": "HIGH", "WARNING": "MEDIUM", "MODERATE": "MEDIUM", "INFORMATIONAL": "INFO", "NONE": "INFO"}
    result = str(value or "UNKNOWN").strip().upper()
    result = aliases.get(result, result)
    return result if result in SEVERITIES else "UNKNOWN"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    scanner: str = "manual"
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    description: str | None = None
    remediation: str | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    identifiers: tuple[str, ...] = ()
    confidence: str | None = None
    evidence: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        # Never include secret evidence in a fingerprint.
        key = "|".join((self.scanner, self.rule_id, self.path or "", str(self.start_line or ""), self.package_name or "", self.installed_version or ""))
        return sha256(key.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = canonical_severity(self.severity)
        data["identifiers"] = list(self.identifiers)
        data["fingerprint"] = self.fingerprint
        return data


@dataclass
class ScanResult:
    scanner: str
    status: str
    findings: list[Finding] = field(default_factory=list)
    raw_output: str | None = None
    duration_seconds: float | None = None
    version: str | None = None
    error: str | None = None
    scope: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [item.to_dict() for item in self.findings]
        return data
