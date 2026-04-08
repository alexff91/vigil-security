"""SSL/TLS certificate monitoring."""

from __future__ import annotations

import asyncio
import logging
import ssl
import socket
from datetime import datetime, timezone

from vigil.config import SSLConfig
from vigil.models import Finding, ScanResult, Severity
from vigil.scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class SSLCertScanner(BaseScanner):
    """Check SSL certificate validity and expiration."""

    name = "ssl_cert"

    def __init__(self, config: SSLConfig) -> None:
        self.config = config

    async def scan(self) -> ScanResult:
        result = self._make_result()

        if not self.config.enabled or not self.config.hosts:
            return self._finish_result(result)

        for host in self.config.hosts:
            await self._check_host(host, result)

        return self._finish_result(result)

    async def _check_host(self, host: str, result: ScanResult) -> None:
        """Check SSL certificate for a single host."""
        # Extract hostname and port
        if ":" in host:
            hostname, port_str = host.rsplit(":", 1)
            port = int(port_str)
        else:
            hostname = host
            port = 443

        logger.info("Checking SSL certificate for %s:%d", hostname, port)

        try:
            cert_info = await asyncio.get_event_loop().run_in_executor(
                None, self._get_cert_info, hostname, port
            )
        except Exception as e:
            result.findings.append(Finding(
                scanner=self.name,
                severity=Severity.HIGH,
                title=f"SSL connection failed for {hostname}",
                description=f"Could not establish SSL connection to {hostname}:{port}: {e}",
                recommendation="Verify the host is reachable and has a valid SSL certificate.",
                metadata={"host": hostname, "port": port, "error": str(e)},
            ))
            return

        if cert_info is None:
            return

        # Parse expiry date
        not_after_str = cert_info.get("notAfter", "")
        not_before_str = cert_info.get("notBefore", "")
        subject = dict(x[0] for x in cert_info.get("subject", []))
        issuer = dict(x[0] for x in cert_info.get("issuer", []))
        common_name = subject.get("commonName", "unknown")
        issuer_name = issuer.get("organizationName", issuer.get("commonName", "unknown"))

        try:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_after = not_after.replace(tzinfo=timezone.utc)
        except ValueError:
            result.findings.append(Finding(
                scanner=self.name,
                severity=Severity.MEDIUM,
                title=f"Cannot parse certificate expiry for {hostname}",
                description=f"Certificate expiry date format unrecognized: {not_after_str}",
                metadata={"host": hostname},
            ))
            return

        now = datetime.now(timezone.utc)
        days_until_expiry = (not_after - now).days

        # Already expired
        if days_until_expiry < 0:
            result.findings.append(Finding(
                scanner=self.name,
                severity=Severity.CRITICAL,
                title=f"SSL certificate EXPIRED for {hostname}",
                description=(
                    f"Certificate for {common_name} (issued by {issuer_name}) "
                    f"expired {abs(days_until_expiry)} days ago on {not_after.date()}."
                ),
                recommendation="Renew the SSL certificate immediately.",
                metadata={
                    "host": hostname,
                    "common_name": common_name,
                    "expiry": not_after.isoformat(),
                    "days_until_expiry": days_until_expiry,
                    "issuer": issuer_name,
                },
            ))
        # Expiring within critical threshold
        elif days_until_expiry <= self.config.critical_days:
            result.findings.append(Finding(
                scanner=self.name,
                severity=Severity.CRITICAL,
                title=f"SSL certificate expiring SOON for {hostname}",
                description=(
                    f"Certificate for {common_name} expires in {days_until_expiry} days "
                    f"on {not_after.date()}. Issued by {issuer_name}."
                ),
                recommendation="Renew the SSL certificate urgently.",
                metadata={
                    "host": hostname,
                    "common_name": common_name,
                    "expiry": not_after.isoformat(),
                    "days_until_expiry": days_until_expiry,
                    "issuer": issuer_name,
                },
            ))
        # Expiring within warning threshold
        elif days_until_expiry <= self.config.warn_days:
            result.findings.append(Finding(
                scanner=self.name,
                severity=Severity.MEDIUM,
                title=f"SSL certificate expiring for {hostname}",
                description=(
                    f"Certificate for {common_name} expires in {days_until_expiry} days "
                    f"on {not_after.date()}. Issued by {issuer_name}."
                ),
                recommendation="Plan SSL certificate renewal.",
                metadata={
                    "host": hostname,
                    "common_name": common_name,
                    "expiry": not_after.isoformat(),
                    "days_until_expiry": days_until_expiry,
                    "issuer": issuer_name,
                },
            ))
        else:
            result.findings.append(Finding(
                scanner=self.name,
                severity=Severity.INFO,
                title=f"SSL certificate valid for {hostname}",
                description=(
                    f"Certificate for {common_name} is valid for {days_until_expiry} more days "
                    f"(expires {not_after.date()}). Issued by {issuer_name}."
                ),
                metadata={
                    "host": hostname,
                    "common_name": common_name,
                    "expiry": not_after.isoformat(),
                    "days_until_expiry": days_until_expiry,
                    "issuer": issuer_name,
                },
            ))

    @staticmethod
    def _get_cert_info(hostname: str, port: int) -> dict:
        """Retrieve SSL certificate information (runs in thread executor)."""
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert  # type: ignore[return-value]
