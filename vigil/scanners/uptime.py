"""HTTP uptime and health check monitor."""

from __future__ import annotations

import logging
import time

import aiohttp

from vigil.config import UptimeConfig
from vigil.models import Finding, ScanResult, Severity
from vigil.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class UptimeMonitor(BaseScanner):
    """Monitor HTTP endpoints for availability."""

    name = "uptime"

    def __init__(self, config: UptimeConfig) -> None:
        self.config = config

    async def scan(self) -> ScanResult:
        result = self._make_result()

        if not self.config.enabled or not self.config.endpoints:
            return self._finish_result(result)

        async with aiohttp.ClientSession() as session:
            for endpoint in self.config.endpoints:
                await self._check_endpoint(session, endpoint, result)

        return self._finish_result(result)

    async def _check_endpoint(
        self, session: aiohttp.ClientSession, endpoint: dict, result: ScanResult
    ) -> None:
        """Check a single HTTP endpoint."""
        url = endpoint.get("url", "")
        name = endpoint.get("name", url)
        method = endpoint.get("method", "GET").upper()
        expected_status = endpoint.get("expected_status", self.config.expected_status)
        timeout_sec = endpoint.get("timeout", self.config.timeout)

        if not url:
            return

        logger.info("Checking uptime for %s (%s)", name, url)

        start_time = time.monotonic()

        try:
            timeout = aiohttp.ClientTimeout(total=timeout_sec)
            async with session.request(
                method,
                url,
                timeout=timeout,
                ssl=True,
                allow_redirects=True,
            ) as resp:
                elapsed = time.monotonic() - start_time
                status = resp.status

                if status == expected_status:
                    severity = Severity.INFO
                    title = f"{name}: UP ({status}, {elapsed:.2f}s)"
                    description = (
                        f"Endpoint {url} responded with status {status} "
                        f"in {elapsed:.2f} seconds."
                    )
                else:
                    severity = Severity.HIGH
                    title = f"{name}: UNEXPECTED STATUS {status}"
                    description = (
                        f"Endpoint {url} responded with status {status} "
                        f"(expected {expected_status}) in {elapsed:.2f} seconds."
                    )

                # Warn on slow responses
                if elapsed > 5.0 and severity == Severity.INFO:
                    severity = Severity.MEDIUM
                    title = f"{name}: SLOW ({elapsed:.2f}s)"
                    description += " Response time exceeds 5 seconds."

                result.findings.append(Finding(
                    scanner=self.name,
                    severity=severity,
                    title=title,
                    description=description,
                    recommendation=(
                        None if severity == Severity.INFO
                        else f"Investigate {url} — unexpected status or slow response."
                    ),
                    metadata={
                        "url": url,
                        "name": name,
                        "status_code": status,
                        "expected_status": expected_status,
                        "response_time_s": round(elapsed, 3),
                    },
                ))

        except aiohttp.ClientError as e:
            elapsed = time.monotonic() - start_time
            result.findings.append(Finding(
                scanner=self.name,
                severity=Severity.CRITICAL,
                title=f"{name}: DOWN",
                description=f"Endpoint {url} is unreachable: {e}",
                recommendation=f"Check if {url} is running and accessible.",
                metadata={
                    "url": url,
                    "name": name,
                    "error": str(e),
                    "response_time_s": round(elapsed, 3),
                },
            ))

        except TimeoutError:
            result.findings.append(Finding(
                scanner=self.name,
                severity=Severity.CRITICAL,
                title=f"{name}: TIMEOUT",
                description=f"Endpoint {url} did not respond within {timeout_sec}s.",
                recommendation=f"Check if {url} is running and responding to requests.",
                metadata={
                    "url": url,
                    "name": name,
                    "timeout": timeout_sec,
                },
            ))
