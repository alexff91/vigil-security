"""Markdown report generator for security posture scores."""

from __future__ import annotations

from pathlib import Path

from vigil.models import Severity
from vigil.scoring import PostureScore

GRADE_EMOJI = {
    "A": "\U0001f7e2",  # green
    "B": "\U0001f7e2",
    "C": "\U0001f7e1",  # yellow
    "D": "\U0001f7e0",  # orange
    "F": "\U0001f534",  # red
}

SEVERITY_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


class MarkdownReporter:
    """Render a PostureScore as a clean Markdown report."""

    def generate(
        self, posture: PostureScore, output_path: str | None = None
    ) -> str:
        md = self._render(posture)
        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(md)
        return md

    def _render(self, posture: PostureScore) -> str:
        emoji = GRADE_EMOJI.get(posture.grade, "")
        lines: list[str] = []
        lines.append("# Vigil Security Posture Report")
        lines.append("")
        lines.append(f"_Generated: {posture.generated_at.isoformat()}Z_")
        lines.append("")
        lines.append(f"## {emoji} Score: {posture.score}/100 (Grade {posture.grade})")
        lines.append("")
        lines.append(f"**{posture.total_findings} finding(s)** across all scanners.")
        lines.append("")

        # Severity breakdown table
        lines.append("| Severity | Count |")
        lines.append("| --- | --- |")
        for sev in (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ):
            count = posture.severity_counts.get(sev, 0)
            lines.append(f"| {SEVERITY_LABEL[sev]} | {count} |")
        lines.append("")

        # Remediation list
        lines.append("## Prioritized Remediation")
        lines.append("")
        if not posture.remediation:
            lines.append("No remediation needed. Nice work!")
        else:
            for i, item in enumerate(posture.remediation, start=1):
                label = SEVERITY_LABEL[item.severity]
                scanners = ", ".join(item.scanners)
                occ = f" (x{item.count})" if item.count > 1 else ""
                lines.append(f"{i}. **[{label}]** {item.title}{occ}")
                lines.append(f"   - _{item.recommendation}_")
                lines.append(f"   - Source: {scanners}")
        lines.append("")

        if posture.errors:
            lines.append("## Scanner Errors")
            lines.append("")
            for err in posture.errors:
                lines.append(f"- {err}")
            lines.append("")

        return "\n".join(lines)
