"""Console/terminal alert output."""

from __future__ import annotations

import sys

from vigil.models import Finding, ScanResult, Severity

COLORS = {
    Severity.CRITICAL: "\033[1;31m",  # bold red
    Severity.HIGH: "\033[0;31m",      # red
    Severity.MEDIUM: "\033[0;33m",    # yellow
    Severity.LOW: "\033[0;36m",       # cyan
    Severity.INFO: "\033[0;32m",      # green
}
RESET = "\033[0m"
BOLD = "\033[1m"


class ConsoleAlerter:
    """Print findings to the terminal with color coding."""

    def __init__(self, use_color: bool = True, verbose: bool = False) -> None:
        self.use_color = use_color and sys.stdout.isatty()
        self.verbose = verbose

    def print_results(self, results: list[ScanResult]) -> None:
        """Print a formatted summary of all scan results."""
        total = sum(r.total_count for r in results)
        critical = sum(r.critical_count for r in results)
        high = sum(r.high_count for r in results)

        self._print("")
        self._print(f"{BOLD}=== Vigil Security Scan Report ==={RESET}")
        self._print("")

        for r in results:
            self._print_scanner_results(r)

        self._print(f"{BOLD}--- Summary ---{RESET}")
        self._print(f"Total findings: {total}")

        if critical > 0:
            self._print(f"{COLORS[Severity.CRITICAL]}Critical: {critical}{RESET}")
        if high > 0:
            self._print(f"{COLORS[Severity.HIGH]}High: {high}{RESET}")

        self._print("")

        if critical > 0:
            self._print(
                f"{COLORS[Severity.CRITICAL]}ACTION REQUIRED: "
                f"{critical} critical finding(s) need immediate attention.{RESET}"
            )

    def _print_scanner_results(self, result: ScanResult) -> None:
        """Print results from a single scanner."""
        if result.total_count == 0 and not self.verbose:
            return

        self._print(f"{BOLD}[{result.scanner_name}]{RESET} "
                     f"{result.total_count} finding(s)")

        if result.error:
            self._print(f"  Error: {result.error}")

        for finding in result.findings:
            self._print_finding(finding)

        self._print("")

    def _print_finding(self, finding: Finding) -> None:
        """Print a single finding."""
        color = COLORS.get(finding.severity, "") if self.use_color else ""
        reset = RESET if self.use_color else ""

        self._print(
            f"  {color}[{finding.severity.value.upper()}]{reset} {finding.title}"
        )

        if self.verbose or finding.severity in (Severity.CRITICAL, Severity.HIGH):
            self._print(f"    {finding.description}")
            if finding.file_path:
                loc = finding.file_path
                if finding.line_number:
                    loc += f":{finding.line_number}"
                self._print(f"    Location: {loc}")
            if finding.recommendation:
                self._print(f"    Fix: {finding.recommendation}")

    def _print(self, text: str) -> None:
        if not self.use_color:
            # Strip ANSI codes
            import re
            text = re.sub(r"\033\[[0-9;]*m", "", text)
        print(text)
