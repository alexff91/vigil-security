"""Lightweight port scanner."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from vigil.config import PortScanConfig
from vigil.models import Finding, ScanResult, Severity
from vigil.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Well-known port descriptions
PORT_DESCRIPTIONS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Ports that are concerning if publicly exposed
RISKY_PORTS = {
    23: ("Telnet is unencrypted. Use SSH instead.", Severity.CRITICAL),
    3306: ("MySQL should not be publicly accessible.", Severity.HIGH),
    5432: ("PostgreSQL should not be publicly accessible.", Severity.HIGH),
    6379: ("Redis should not be publicly accessible (often no auth by default).", Severity.CRITICAL),
    9200: ("Elasticsearch should not be publicly accessible.", Severity.HIGH),
    27017: ("MongoDB should not be publicly accessible.", Severity.HIGH),
    3389: ("RDP exposed to the internet is a major attack vector.", Severity.HIGH),
}


class PortScanner(BaseScanner):
    """Scan hosts for open ports."""

    name = "port"

    def __init__(self, config: PortScanConfig) -> None:
        self.config = config

    async def scan(self) -> ScanResult:
        result = self._make_result()

        if not self.config.enabled or not self.config.hosts:
            return self._finish_result(result)

        for host in self.config.hosts:
            await self._scan_host(host, result)

        return self._finish_result(result)

    async def _scan_host(self, host: str, result: ScanResult) -> None:
        """Scan all configured ports on a single host."""
        logger.info("Scanning ports on %s", host)

        tasks = [
            self._check_port(host, port)
            for port in self.config.ports
        ]

        port_results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = []
        for port, is_open in zip(self.config.ports, port_results):
            if isinstance(is_open, Exception):
                continue
            if is_open:
                open_ports.append(port)

        if not open_ports:
            result.findings.append(Finding(
                scanner=self.name,
                severity=Severity.INFO,
                title=f"No open ports found on {host}",
                description=f"Scanned {len(self.config.ports)} ports, none responded.",
                metadata={"host": host, "ports_scanned": len(self.config.ports)},
            ))
            return

        # Report open ports
        for port in open_ports:
            service = PORT_DESCRIPTIONS.get(port, "Unknown")

            if port in RISKY_PORTS:
                risk_msg, severity = RISKY_PORTS[port]
                result.findings.append(Finding(
                    scanner=self.name,
                    severity=severity,
                    title=f"Risky port {port} ({service}) open on {host}",
                    description=f"Port {port} ({service}) is open. {risk_msg}",
                    recommendation=f"Restrict access to port {port} using firewall rules or security groups.",
                    metadata={"host": host, "port": port, "service": service},
                ))
            else:
                result.findings.append(Finding(
                    scanner=self.name,
                    severity=Severity.INFO,
                    title=f"Port {port} ({service}) open on {host}",
                    description=f"Port {port} ({service}) is open on {host}.",
                    metadata={"host": host, "port": port, "service": service},
                ))

    async def _check_port(self, host: str, port: int) -> bool:
        """Check if a single port is open."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False
