"""HTML report generator."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from vigil.models import ScanResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#16a34a",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigil Security Report</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  h1 {{ font-size: 1.75rem; margin-bottom: 0.5rem; }}
  .meta {{ color: var(--muted); margin-bottom: 2rem; font-size: 0.875rem; }}
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
              gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border);
           border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat .value {{ font-size: 2rem; font-weight: bold; }}
  .stat .label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; }}
  .scanner {{ background: var(--surface); border: 1px solid var(--border);
              border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }}
  .scanner-header {{ padding: 1rem; font-weight: 600; border-bottom: 1px solid var(--border);
                     display: flex; justify-content: space-between; }}
  .finding {{ padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }}
  .finding:last-child {{ border-bottom: none; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
            font-size: 0.7rem; font-weight: 700; text-transform: uppercase; color: #fff; }}
  .finding-title {{ margin-left: 0.5rem; font-weight: 500; }}
  .finding-desc {{ margin-top: 0.25rem; color: var(--muted); font-size: 0.85rem; }}
  .finding-meta {{ margin-top: 0.25rem; color: var(--muted); font-size: 0.8rem; font-style: italic; }}
  .empty {{ text-align: center; padding: 2rem; color: var(--muted); }}
  footer {{ text-align: center; color: var(--muted); margin-top: 2rem; font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>Vigil Security Report</h1>
  <p class="meta">Generated {generated_at}</p>
  <div class="summary">
    <div class="stat"><div class="value">{total}</div><div class="label">Total Findings</div></div>
    <div class="stat"><div class="value" style="color:#dc2626">{critical}</div><div class="label">Critical</div></div>
    <div class="stat"><div class="value" style="color:#ea580c">{high}</div><div class="label">High</div></div>
    <div class="stat"><div class="value" style="color:#ca8a04">{medium}</div><div class="label">Medium</div></div>
    <div class="stat"><div class="value" style="color:#16a34a">{info_low}</div><div class="label">Low / Info</div></div>
  </div>
  {scanner_sections}
  <footer>Vigil Security v0.1.0 &mdash; github.com/alexff91/vigil-security</footer>
</div>
</body>
</html>"""


class HTMLReporter:
    """Generate styled HTML reports from scan results."""

    def generate(
        self, results: list[ScanResult], output_path: Optional[str] = None
    ) -> str:
        """Generate an HTML report and optionally write to file."""
        total = sum(r.total_count for r in results)
        critical = sum(r.critical_count for r in results)
        high = sum(r.high_count for r in results)
        medium = sum(
            1 for r in results for f in r.findings if f.severity == Severity.MEDIUM
        )
        info_low = total - critical - high - medium

        scanner_sections = []
        for r in results:
            scanner_sections.append(self._render_scanner(r))

        html = HTML_TEMPLATE.format(
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            total=total,
            critical=critical,
            high=high,
            medium=medium,
            info_low=info_low,
            scanner_sections="\n".join(scanner_sections),
        )

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(html)

        return html

    def _render_scanner(self, result: ScanResult) -> str:
        if result.total_count == 0:
            return (
                f'<div class="scanner">'
                f'<div class="scanner-header">{result.scanner_name}'
                f'<span>0 findings</span></div>'
                f'<div class="empty">No issues found.</div></div>'
            )

        findings_html = []
        for f in sorted(result.findings, key=lambda x: x.severity, reverse=True):
            color = SEVERITY_COLORS.get(f.severity, "#64748b")
            badge = f'<span class="badge" style="background:{color}">{f.severity.value}</span>'
            desc = f'<div class="finding-desc">{self._escape(f.description)}</div>' if f.description else ""
            meta_parts = []
            if f.file_path:
                loc = f.file_path
                if f.line_number:
                    loc += f":{f.line_number}"
                meta_parts.append(loc)
            if f.recommendation:
                meta_parts.append(f"Fix: {f.recommendation}")
            meta = f'<div class="finding-meta">{" | ".join(meta_parts)}</div>' if meta_parts else ""

            findings_html.append(
                f'<div class="finding">{badge}'
                f'<span class="finding-title">{self._escape(f.title)}</span>'
                f'{desc}{meta}</div>'
            )

        return (
            f'<div class="scanner">'
            f'<div class="scanner-header">{result.scanner_name}'
            f'<span>{result.total_count} finding(s)</span></div>'
            f'{"".join(findings_html)}</div>'
        )

    @staticmethod
    def _escape(text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
