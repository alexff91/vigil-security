"""Security posture scoring.

Aggregates findings from all scanners into a single 0-100 health score with a
letter grade and a prioritized, deduplicated remediation list.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from vigil.models import ScanResult, Severity

# Penalty points deducted from a perfect score (100) for each finding of a
# given severity. INFO findings are informational and never affect the score.
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

# Letter grade thresholds, evaluated highest-first (inclusive lower bound).
GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]


def score_to_grade(score: int) -> str:
    """Map a 0-100 score to a letter grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


@dataclass
class RemediationItem:
    """A deduplicated, prioritized remediation action."""

    severity: Severity
    title: str
    recommendation: str
    count: int
    scanners: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "title": self.title,
            "recommendation": self.recommendation,
            "count": self.count,
            "scanners": self.scanners,
        }


@dataclass
class PostureScore:
    """The aggregated security posture for a scan session."""

    score: int
    grade: str
    total_findings: int
    severity_counts: dict[Severity, int]
    penalty: int
    remediation: list[RemediationItem]
    errors: list[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "total_findings": self.total_findings,
            "penalty": self.penalty,
            "severity_counts": {
                s.value: c for s, c in self.severity_counts.items()
            },
            "remediation": [r.to_dict() for r in self.remediation],
            "errors": self.errors,
            "generated_at": self.generated_at.isoformat(),
        }


def build_digest(posture: PostureScore, top_n: int = 5) -> str:
    """Build a concise, plain-text digest summary of a posture score.

    Designed for a single weekly message to Telegram/Slack rather than
    per-finding spam.
    """
    lines = [
        "Vigil weekly security digest",
        f"Score: {posture.score}/100 (Grade {posture.grade}) - "
        f"{posture.total_findings} finding(s)",
    ]

    counts = posture.severity_counts
    breakdown = ", ".join(
        f"{counts.get(s, 0)} {s.value}"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
        if counts.get(s, 0) > 0
    )
    if breakdown:
        lines.append(breakdown)

    top = posture.remediation[:top_n]
    if top:
        lines.append("")
        lines.append("Top fixes:")
        for i, item in enumerate(top, start=1):
            occ = f" (x{item.count})" if item.count > 1 else ""
            lines.append(
                f"{i}. [{item.severity.value.upper()}] {item.title}{occ}"
            )

    return "\n".join(lines)


def _dedup_key(scanner: str, title: str, recommendation: str | None) -> str:
    """Group equivalent findings together.

    A recommendation usually captures the shared remediation action; fall back
    to the scanner+title so distinct issues are not collapsed.
    """
    if recommendation:
        return recommendation.strip().lower()
    return f"{scanner}:{title}".strip().lower()


def compute_score(results: list[ScanResult]) -> PostureScore:
    """Aggregate scan results into a posture score and remediation list."""
    severity_counts: dict[Severity, int] = {s: 0 for s in Severity}
    penalty = 0
    errors: list[str] = []
    groups: dict[str, RemediationItem] = {}

    for result in results:
        if result.error:
            errors.append(f"{result.scanner_name}: {result.error}")
        for finding in result.findings:
            severity_counts[finding.severity] += 1
            penalty += SEVERITY_WEIGHTS.get(finding.severity, 0)

            key = _dedup_key(finding.scanner, finding.title, finding.recommendation)
            item = groups.get(key)
            if item is None:
                groups[key] = RemediationItem(
                    severity=finding.severity,
                    title=finding.title,
                    recommendation=finding.recommendation or finding.description,
                    count=1,
                    scanners=[finding.scanner],
                )
            else:
                item.count += 1
                # Track the most severe occurrence for prioritization.
                if finding.severity > item.severity:
                    item.severity = finding.severity
                if finding.scanner not in item.scanners:
                    item.scanners.append(finding.scanner)

    total_findings = sum(severity_counts.values())
    score = max(0, 100 - penalty)

    # Prioritize: highest severity first, then most frequent.
    remediation = sorted(
        groups.values(),
        key=lambda r: (r.severity, r.count),
        reverse=True,
    )

    return PostureScore(
        score=score,
        grade=score_to_grade(score),
        total_findings=total_findings,
        severity_counts=severity_counts,
        penalty=penalty,
        remediation=remediation,
        errors=errors,
    )
