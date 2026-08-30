"""Command-line interface for Vigil Security."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from vigil import __version__
from vigil.alerts.console import ConsoleAlerter
from vigil.alerts.slack import SlackAlerter
from vigil.alerts.telegram import TelegramAlerter
from vigil.config import load_config
from vigil.engine import ScanEngine
from vigil.reporters.html_reporter import HTMLReporter
from vigil.reporters.json_reporter import JSONReporter
from vigil.reporters.markdown_reporter import MarkdownReporter
from vigil.scoring import compute_score


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigil",
        description="Vigil Security -- open-source personal security monitoring agent",
    )
    parser.add_argument(
        "--version", action="version", version=f"vigil {__version__}"
    )
    parser.add_argument(
        "-c", "--config", default=None,
        help="Path to vigil.yaml config file (default: auto-detect)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scans")
    scan_parser.add_argument(
        "--scanner", choices=["dependency", "secret", "port", "ssl_cert", "uptime"],
        help="Run only a specific scanner",
    )
    scan_parser.add_argument(
        "--path", nargs="*",
        help="Override scan paths (for dependency and secret scanners)",
    )
    scan_parser.add_argument(
        "--format", choices=["console", "json", "html"], default="console",
        help="Output format (default: console)",
    )
    scan_parser.add_argument(
        "-o", "--output",
        help="Output file path (for json/html formats)",
    )
    scan_parser.add_argument(
        "--telegram", action="store_true",
        help="Send results via Telegram",
    )

    # monitor command
    monitor_parser = subparsers.add_parser(
        "monitor", help="Run continuous monitoring"
    )
    monitor_parser.add_argument(
        "--interval", type=int, default=300,
        help="Check interval in seconds (default: 300)",
    )
    monitor_parser.add_argument(
        "--telegram", action="store_true",
        help="Send alerts via Telegram",
    )

    # report command
    report_parser = subparsers.add_parser(
        "report", help="Generate a report from a scan"
    )
    report_parser.add_argument(
        "--format", choices=["json", "html"], default="html",
        help="Report format (default: html)",
    )
    report_parser.add_argument(
        "-o", "--output", default=None,
        help="Output file path",
    )

    # score command
    score_parser = subparsers.add_parser(
        "score",
        help="Aggregate all scanners into a 0-100 security posture score",
    )
    score_parser.add_argument(
        "--format", choices=["console", "markdown"], default="console",
        help="Output format (default: console)",
    )
    score_parser.add_argument(
        "-o", "--output",
        help="Write the Markdown report to this file path",
    )
    score_parser.add_argument(
        "--digest", choices=["telegram", "slack"], action="append", default=[],
        help="Post a concise weekly digest (repeatable for multiple targets)",
    )
    score_parser.add_argument(
        "--fail-under", type=int, default=None,
        help="Exit non-zero if the score is below this threshold",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Load config
    config = load_config(args.config)

    # Override paths if specified
    if args.command == "scan" and args.path:
        config.dependencies.paths = args.path
        config.secrets.paths = args.path

    if args.command == "scan":
        asyncio.run(_cmd_scan(args, config))
    elif args.command == "monitor":
        asyncio.run(_cmd_monitor(args, config))
    elif args.command == "report":
        asyncio.run(_cmd_report(args, config))
    elif args.command == "score":
        asyncio.run(_cmd_score(args, config))


async def _cmd_scan(args: argparse.Namespace, config) -> None:
    """Execute scan command."""
    engine = ScanEngine(config)

    if args.scanner:
        result = await engine.run_scanner(args.scanner)
        results = [result] if result else []
    else:
        results = await engine.run_all()

    # Console output
    if args.format == "console":
        console = ConsoleAlerter(use_color=not args.no_color, verbose=args.verbose)
        console.print_results(results)
    elif args.format == "json":
        reporter = JSONReporter()
        output = args.output or _default_output_path(config, "json")
        json_str = reporter.generate(results, output)
        if not args.output:
            print(json_str)
        else:
            print(f"JSON report saved to {output}")
    elif args.format == "html":
        reporter = HTMLReporter()
        output = args.output or _default_output_path(config, "html")
        reporter.generate(results, output)
        print(f"HTML report saved to {output}")

    # Telegram alerts
    if args.telegram:
        await _send_telegram(config, results)

    # Exit with non-zero if critical findings
    critical = sum(r.critical_count for r in results)
    if critical > 0:
        sys.exit(1)


async def _cmd_monitor(args: argparse.Namespace, config) -> None:
    """Run continuous monitoring loop."""
    console = ConsoleAlerter(use_color=True, verbose=False)
    interval = args.interval

    print(f"Starting continuous monitoring (interval: {interval}s)")
    print("Press Ctrl+C to stop\n")

    try:
        while True:
            engine = ScanEngine(config)
            results = await engine.run_all()
            console.print_results(results)

            if args.telegram:
                # Only send alerts if there are critical/high findings
                has_issues = any(
                    r.critical_count > 0 or r.high_count > 0
                    for r in results
                )
                if has_issues:
                    await _send_telegram(config, results)

            await asyncio.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")


async def _cmd_report(args: argparse.Namespace, config) -> None:
    """Generate a report from a fresh scan."""
    engine = ScanEngine(config)
    results = await engine.run_all()

    if args.format == "json":
        reporter = JSONReporter()
        output = args.output or _default_output_path(config, "json")
        reporter.generate(results, output)
    else:
        reporter = HTMLReporter()
        output = args.output or _default_output_path(config, "html")
        reporter.generate(results, output)

    print(f"Report saved to {output}")


async def _cmd_score(args: argparse.Namespace, config) -> None:
    """Compute and present the aggregated security posture score."""
    engine = ScanEngine(config)
    results = await engine.run_all()
    posture = compute_score(results)

    if args.format == "markdown":
        reporter = MarkdownReporter()
        output = args.output or _default_output_path(config, "md")
        reporter.generate(posture, output)
        print(f"Markdown report saved to {output}")
    else:
        _print_score_console(posture, use_color=not args.no_color)
        if args.output:
            MarkdownReporter().generate(posture, args.output)
            print(f"\nMarkdown report saved to {args.output}")

    # Weekly digests (deduplicated, one message per target)
    for target in args.digest:
        if target == "telegram":
            if config.telegram.enabled and config.telegram.bot_token:
                tg = TelegramAlerter(config.telegram.bot_token, config.telegram.chat_id)
                await tg.send_digest(posture)
            else:
                logging.getLogger(__name__).warning("Telegram not configured.")
        elif target == "slack":
            if config.slack.enabled and config.slack.webhook_url:
                await SlackAlerter(config.slack.webhook_url).send_digest(posture)
            else:
                logging.getLogger(__name__).warning("Slack not configured.")

    if args.fail_under is not None and posture.score < args.fail_under:
        sys.exit(1)


def _print_score_console(posture, use_color: bool) -> None:
    """Print a compact posture summary to the console."""
    print("=" * 50)
    print(f"  Security Posture Score: {posture.score}/100  (Grade {posture.grade})")
    print(f"  {posture.total_findings} finding(s)")
    print("=" * 50)
    for sev, count in posture.severity_counts.items():
        if count:
            print(f"  {sev.value.upper():<9} {count}")
    if posture.remediation:
        print("\nPrioritized remediation:")
        for i, item in enumerate(posture.remediation, start=1):
            occ = f" (x{item.count})" if item.count > 1 else ""
            print(f"  {i}. [{item.severity.value.upper()}] {item.title}{occ}")
            print(f"     -> {item.recommendation}")
    if posture.errors:
        print("\nScanner errors:")
        for err in posture.errors:
            print(f"  - {err}")


async def _send_telegram(config, results) -> None:
    """Send results via Telegram if configured."""
    if config.telegram.enabled and config.telegram.bot_token:
        tg = TelegramAlerter(config.telegram.bot_token, config.telegram.chat_id)
        await tg.send_results(results)
    else:
        logging.getLogger(__name__).warning(
            "Telegram not configured. Set VIGIL_TELEGRAM_TOKEN and VIGIL_TELEGRAM_CHAT_ID."
        )


def _default_output_path(config, ext: str) -> str:
    from datetime import datetime
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    return str(out_dir / f"vigil_report_{ts}.{ext}")


if __name__ == "__main__":
    main()
