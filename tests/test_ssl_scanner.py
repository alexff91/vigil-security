"""Tests for the SSL certificate scanner."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from vigil.config import SSLConfig
from vigil.models import Severity
from vigil.scanners.ssl_cert import SSLCertScanner


def _make_cert(days_until_expiry: int) -> dict:
    """Create a mock certificate dict."""
    expiry = datetime.now(timezone.utc) + timedelta(days=days_until_expiry)
    return {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notBefore": "Jan  1 00:00:00 2024 GMT",
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
    }


@pytest.fixture
def scanner():
    config = SSLConfig(
        enabled=True,
        hosts=["example.com"],
        warn_days=30,
        critical_days=7,
    )
    return SSLCertScanner(config)


class TestSSLCertScanner:
    @pytest.mark.asyncio
    async def test_valid_cert(self, scanner):
        with patch.object(SSLCertScanner, "_get_cert_info", return_value=_make_cert(90)):
            result = await scanner.scan()
            assert result.total_count == 1
            assert result.findings[0].severity == Severity.INFO

    @pytest.mark.asyncio
    async def test_expiring_soon_warning(self, scanner):
        with patch.object(SSLCertScanner, "_get_cert_info", return_value=_make_cert(20)):
            result = await scanner.scan()
            assert result.total_count == 1
            assert result.findings[0].severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_expiring_critical(self, scanner):
        with patch.object(SSLCertScanner, "_get_cert_info", return_value=_make_cert(3)):
            result = await scanner.scan()
            assert result.total_count == 1
            assert result.findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_expired_cert(self, scanner):
        with patch.object(SSLCertScanner, "_get_cert_info", return_value=_make_cert(-5)):
            result = await scanner.scan()
            assert result.total_count == 1
            assert result.findings[0].severity == Severity.CRITICAL
            assert "EXPIRED" in result.findings[0].title

    @pytest.mark.asyncio
    async def test_connection_failure(self, scanner):
        with patch.object(
            SSLCertScanner, "_get_cert_info",
            side_effect=ConnectionRefusedError("Connection refused"),
        ):
            result = await scanner.scan()
            assert result.total_count == 1
            assert result.findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_disabled(self):
        config = SSLConfig(enabled=False, hosts=["example.com"])
        scanner = SSLCertScanner(config)
        result = await scanner.scan()
        assert result.total_count == 0

    @pytest.mark.asyncio
    async def test_no_hosts(self):
        config = SSLConfig(enabled=True, hosts=[])
        scanner = SSLCertScanner(config)
        result = await scanner.scan()
        assert result.total_count == 0
