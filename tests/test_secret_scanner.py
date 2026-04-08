"""Tests for the secret scanner."""

import pytest
from pathlib import Path
from unittest.mock import patch

from vigil.config import SecretScanConfig
from vigil.models import Severity
from vigil.scanners.secret import SecretScanner


@pytest.fixture
def scanner():
    config = SecretScanConfig(enabled=True, paths=[], max_file_size_kb=512)
    return SecretScanner(config)


@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path


class TestSecretPatterns:
    """Test individual secret pattern detection."""

    @pytest.mark.asyncio
    async def test_aws_access_key(self, temp_dir, scanner):
        f = temp_dir / "config.py"
        f.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        scanner.config.paths = [str(temp_dir)]
        result = await scanner.scan()
        assert result.total_count >= 1
        found = [f for f in result.findings if "AWS Access Key" in f.title]
        assert len(found) >= 1
        assert found[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_github_token(self, temp_dir, scanner):
        f = temp_dir / "env.sh"
        f.write_text('export TOKEN="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"\n')
        scanner.config.paths = [str(temp_dir)]
        result = await scanner.scan()
        found = [f for f in result.findings if "GitHub" in f.title]
        assert len(found) >= 1

    @pytest.mark.asyncio
    async def test_private_key(self, temp_dir, scanner):
        f = temp_dir / "key.pem"
        f.write_text('-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAL...\n-----END RSA PRIVATE KEY-----\n')
        scanner.config.paths = [str(temp_dir)]
        result = await scanner.scan()
        found = [f for f in result.findings if "Private Key" in f.title]
        assert len(found) >= 1
        assert found[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_database_url(self, temp_dir, scanner):
        f = temp_dir / ".env"
        f.write_text('DATABASE_URL=postgres://user:password123@db.example.com:5432/mydb\n')
        scanner.config.paths = [str(temp_dir)]
        result = await scanner.scan()
        found = [f for f in result.findings if "Database" in f.title]
        assert len(found) >= 1

    @pytest.mark.asyncio
    async def test_generic_password(self, temp_dir, scanner):
        f = temp_dir / "settings.py"
        f.write_text('password = "super_secret_password_123"\n')
        scanner.config.paths = [str(temp_dir)]
        result = await scanner.scan()
        found = [f for f in result.findings if "Password" in f.title or "password" in f.description.lower()]
        assert len(found) >= 1

    @pytest.mark.asyncio
    async def test_clean_file_no_findings(self, temp_dir, scanner):
        f = temp_dir / "clean.py"
        f.write_text('x = 42\nprint("hello world")\n')
        scanner.config.paths = [str(temp_dir)]
        result = await scanner.scan()
        assert result.total_count == 0

    @pytest.mark.asyncio
    async def test_skips_binary_files(self, temp_dir, scanner):
        f = temp_dir / "image.png"
        f.write_bytes(b'\x89PNG\r\n\x1a\nAKIAIOSFODNN7EXAMPLE')
        scanner.config.paths = [str(temp_dir)]
        result = await scanner.scan()
        assert result.total_count == 0

    @pytest.mark.asyncio
    async def test_skips_excluded_dirs(self, temp_dir, scanner):
        node_modules = temp_dir / "node_modules" / "pkg"
        node_modules.mkdir(parents=True)
        f = node_modules / "index.js"
        f.write_text('const key = "AKIAIOSFODNN7EXAMPLE";\n')
        scanner.config.paths = [str(temp_dir)]
        result = await scanner.scan()
        assert result.total_count == 0


class TestRedaction:
    def test_short_secret(self, scanner):
        assert "****" in scanner._redact("short123")

    def test_long_secret(self, scanner):
        result = scanner._redact("AKIAIOSFODNN7EXAMPLE")
        assert result.startswith("AKIA")
        assert result.endswith("MPLE")
        assert "****" in result


class TestDisabled:
    @pytest.mark.asyncio
    async def test_disabled_scanner_returns_empty(self):
        config = SecretScanConfig(enabled=False)
        scanner = SecretScanner(config)
        result = await scanner.scan()
        assert result.total_count == 0
