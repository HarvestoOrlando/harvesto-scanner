"""Severity classification aligned with Immunefi bug bounty standards."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"  # filtered out by default


# Impact descriptions mapped to severity (Immunefi standard)
IMPACT_SEVERITY_MAP: dict[str, Severity] = {
    # Critical
    "Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield": Severity.CRITICAL,
    "Permanent freezing of funds": Severity.CRITICAL,
    "Protocol insolvency": Severity.CRITICAL,
    # High
    "Theft of unclaimed yield": Severity.HIGH,
    # Medium
    "Unbounded gas consumption": Severity.MEDIUM,
    "Permanent freezing of unclaimed yield": Severity.MEDIUM,
    "Temporary freezing of funds": Severity.MEDIUM,
    # Low
    "Contract fails to deliver promised returns, but doesn't lose value": Severity.LOW,
    "Block stuffing": Severity.LOW,
}


@dataclass
class Finding:
    """A single verified vulnerability finding."""
    id: str
    title: str
    severity: Severity
    impact: str
    confidence: int  # 0-100
    file: str
    lines: list[int]
    function: str
    description: str
    recommendation: str
    detector: str  # which detector found it
    exploitable_by: str  # "any_user", "privileged_role", "admin_only"
    raw_detector_id: str = ""  # original slither/custom detector name
    fp_filters_passed: list[str] = field(default_factory=list)
    duplicate_of: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "impact": self.impact,
            "confidence": self.confidence,
            "file": self.file,
            "lines": self.lines,
            "function": self.function,
            "description": self.description,
            "recommendation": self.recommendation,
            "detector": self.detector,
            "exploitable_by": self.exploitable_by,
        }


@dataclass
class ScanResult:
    """Complete scan result with metadata."""
    vulnerabilities: list[Finding]
    total_raw_findings: int = 0
    filtered_findings: int = 0
    scan_time_seconds: float = 0.0
    files_scanned: int = 0
    sloc_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def fp_reduction_rate(self) -> float:
        if self.total_raw_findings == 0:
            return 0.0
        return 1.0 - (self.filtered_findings / self.total_raw_findings)

    def to_dict(self) -> dict:
        return {
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "metadata": {
                "scanner_version": "0.1.0",
                "scan_time_seconds": round(self.scan_time_seconds, 2),
                "total_raw_findings": self.total_raw_findings,
                "filtered_findings": self.filtered_findings,
                "fp_reduction_rate": round(self.fp_reduction_rate, 4),
                "files_scanned": self.files_scanned,
                "sloc_scanned": self.sloc_scanned,
            },
        }
