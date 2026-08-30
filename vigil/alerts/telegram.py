"""Telegram alert backend."""

from __future__ import annotations

import logging
from typing import Optional

import aiohttp

from vigil.models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    Severity.CRITICAL: "\u2622\ufe0f",  # radioactive
    Severity.HIGH: "\ud83d\udd34",       # red circle
    Severity.MEDIUM: "\ud83d\udfe0",     # orange circle
    Severity.LOW: "\ud83d\udfe1",        # yellow circle
    Severity.INFO: "\ud83d\udfe2",       # green circle
}


class TelegramAlerter:
    """Send security findings to a Telegram chat."""

    def __init__(self, bot_token: str, chat_id: str) -> None:
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_base = f"https://api.telegram.org/bot{bot_token}"

    async def send_results(self, results: list[ScanResult]) -> None:
        """Send a summary of scan results to Telegram."""
        if not self.bot_token or not self.chat_id:
            logger.warning("Telegram not configured, skipping alerts")
            return

        total_findings = sum(r.total_count for r in results)
        critical = sum(r.critical_count for r in results)
        high = sum(r.high_count for r in results)

        # Build summary message
        lines = ["\ud83d\udee1\ufe0f *Vigil Security Report*\n"]

        for r in results:
            if r.total_count > 0:
                lines.append(f"*{r.scanner_name}*: {r.total_count} finding(s)")

        lines.append(f"\n*Total*: {total_findings} findings")
        if critical > 0:
            lines.append(f"\u2622\ufe0f *{critical} CRITICAL*")
        if high > 0:
            lines.append(f"\ud83d\udd34 *{high} HIGH*")

        summary = "\n".join(lines)
        await self._send_message(summary)

        # Send critical and high findings individually
        for r in results:
            for finding in r.findings:
                if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                    await self._send_finding(finding)

    async def send_digest(self, posture) -> None:
        """Send a single concise weekly digest instead of per-finding spam."""
        if not self.bot_token or not self.chat_id:
            logger.warning("Telegram not configured, skipping digest")
            return
        from vigil.scoring import build_digest

        await self._send_message(self._escape_md(build_digest(posture)))

    async def send_finding(self, finding: Finding) -> None:
        """Send a single finding to Telegram."""
        await self._send_finding(finding)

    async def _send_finding(self, finding: Finding) -> None:
        emoji = SEVERITY_EMOJI.get(finding.severity, "")
        lines = [
            f"{emoji} *{finding.severity.value.upper()}*: {self._escape_md(finding.title)}",
            f"_{self._escape_md(finding.description)}_",
        ]
        if finding.file_path:
            lines.append(f"\ud83d\udcc1 `{finding.file_path}`")
            if finding.line_number:
                lines[-1] += f" (line {finding.line_number})"
        if finding.recommendation:
            lines.append(f"\ud83d\udca1 {self._escape_md(finding.recommendation)}")

        await self._send_message("\n".join(lines))

    async def _send_message(self, text: str) -> None:
        """Send a message via Telegram Bot API."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_base}/sendMessage",
                    json={
                        "chat_id": self.chat_id,
                        "text": text,
                        "parse_mode": "Markdown",
                        "disable_web_page_preview": True,
                    },
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        logger.error("Telegram API error %d: %s", resp.status, body)
        except aiohttp.ClientError as e:
            logger.error("Failed to send Telegram message: %s", e)

    @staticmethod
    def _escape_md(text: str) -> str:
        """Escape Markdown special characters for Telegram."""
        for char in ("_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"):
            text = text.replace(char, f"\\{char}")
        return text
