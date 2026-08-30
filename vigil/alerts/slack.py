"""Slack alert backend."""

from __future__ import annotations

import logging

import aiohttp

from vigil.scoring import PostureScore, build_digest

logger = logging.getLogger(__name__)


class SlackAlerter:
    """Send a concise security digest to a Slack incoming webhook."""

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    async def send_digest(self, posture: PostureScore) -> None:
        """Post a single weekly digest message to Slack."""
        if not self.webhook_url:
            logger.warning("Slack not configured, skipping digest")
            return
        await self._send_message(build_digest(posture))

    async def _send_message(self, text: str) -> None:
        try:
            async with aiohttp.ClientSession() as session, session.post(
                self.webhook_url,
                json={"text": text},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.error("Slack webhook error %d: %s", resp.status, body)
        except aiohttp.ClientError as e:
            logger.error("Failed to send Slack message: %s", e)
