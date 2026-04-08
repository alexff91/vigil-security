"""Data models for Vigil Security findings and configuration."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class Severity(enum.Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: "Severity") -> bool:
        order = [self.INFO, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    """A single security finding from any scanner."""

    scanner: str
    severity: Severity
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cve_id: Optional[str] = None
    recommendation: Optional[str] = None
    metadata: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "cve_id": self.cve_id,
            "recommendation": self.recommendation,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanResult:
    """Aggregated results from a scan session."""

    scanner_name: str
    findings: list[Finding] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    error: Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def total_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner_name,
            "total_findings": self.total_count,
            "critical": self.critical_count,
            "high": self.high_count,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }
