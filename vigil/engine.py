"""Scan orchestration engine."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from vigil.config import VigilConfig
from vigil.models import ScanResult
from vigil.scanners.dependency import DependencyScanner
from vigil.scanners.secret import SecretScanner
from vigil.scanners.port import PortScanner
from vigil.scanners.ssl_cert import SSLCertScanner
from vigil.scanners.uptime import UptimeMonitor

logger = logging.getLogger(__name__)


class ScanEngine:
    """Orchestrates all configured scanners."""

    def __init__(self, config: VigilConfig) -> None:
        self.config = config
        self._scanners = self._build_scanners()

    def _build_scanners(self) -> list:
        scanners = []
        if self.config.dependencies.enabled:
            scanners.append(DependencyScanner(self.config.dependencies))
        if self.config.secrets.enabled:
            scanners.append(SecretScanner(self.config.secrets))
        if self.config.ports.enabled:
            scanners.append(PortScanner(self.config.ports))
        if self.config.ssl.enabled:
            scanners.append(SSLCertScanner(self.config.ssl))
        if self.config.uptime.enabled:
            scanners.append(UptimeMonitor(self.config.uptime))
        return scanners

    async def run_all(self) -> list[ScanResult]:
        """Run all enabled scanners concurrently."""
        if not self._scanners:
            logger.warning("No scanners enabled")
            return []

        logger.info("Running %d scanner(s)...", len(self._scanners))
        tasks = [scanner.scan() for scanner in self._scanners]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        scan_results = []
        for scanner, result in zip(self._scanners, results):
            if isinstance(result, Exception):
                logger.error("Scanner %s failed: %s", scanner.name, result)
                sr = ScanResult(scanner_name=scanner.name, error=str(result))
                scan_results.append(sr)
            else:
                scan_results.append(result)

        return scan_results

    async def run_scanner(self, name: str) -> Optional[ScanResult]:
        """Run a specific scanner by name."""
        for scanner in self._scanners:
            if scanner.name == name:
                return await scanner.scan()
        logger.error("Scanner '%s' not found", name)
        return None
