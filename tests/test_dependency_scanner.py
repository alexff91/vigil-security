"""Tests for the dependency vulnerability scanner."""

import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

from vigil.config import DependencyScanConfig
from vigil.models import Severity
from vigil.scanners.dependency import DependencyScanner


@pytest.fixture
def scanner():
    config = DependencyScanConfig(enabled=True, paths=[])
    return DependencyScanner(config)


class TestManifestParsing:
    """Test parsing of various dependency file formats."""

    def test_parse_package_json(self, scanner, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({
            "dependencies": {
                "express": "^4.18.2",
                "lodash": "~4.17.21",
            },
            "devDependencies": {
                "jest": "29.7.0",
            },
        }))
        result = scanner._parse_manifest(pkg)
        assert len(result) == 3
        names = [r[0] for r in result]
        assert "express" in names
        assert "lodash" in names
        assert "jest" in names
        # All should be npm ecosystem
        assert all(r[2] == "npm" for r in result)

    def test_parse_requirements_txt(self, scanner, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\nrequests>=2.28.0\n# comment\n-r other.txt\nnumpy\n")
        result = scanner._parse_manifest(req)
        assert len(result) == 3
        assert ("flask", "2.3.0", "PyPI") in result
        assert ("requests", "2.28.0", "PyPI") in result
        assert ("numpy", None, "PyPI") in result

    def test_parse_empty_package_json(self, scanner, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text("{}")
        result = scanner._parse_manifest(pkg)
        assert result == []

    def test_parse_invalid_json(self, scanner, tmp_path):
        pkg = tmp_path / "package.json"
        pkg.write_text("not json {{{")
        result = scanner._parse_manifest(pkg)
        assert result == []

    def test_parse_pipfile_lock(self, scanner, tmp_path):
        pipfile = tmp_path / "Pipfile.lock"
        pipfile.write_text(json.dumps({
            "default": {
                "flask": {"version": "==2.3.0"},
                "click": {"version": "==8.1.7"},
            },
            "develop": {
                "pytest": {"version": "==7.4.0"},
            },
        }))
        result = scanner._parse_manifest(pipfile)
        assert len(result) == 3

    def test_parse_composer_lock(self, scanner, tmp_path):
        composer = tmp_path / "composer.lock"
        composer.write_text(json.dumps({
            "packages": [
                {"name": "monolog/monolog", "version": "v3.5.0"},
            ],
            "packages-dev": [
                {"name": "phpunit/phpunit", "version": "v10.5.0"},
            ],
        }))
        result = scanner._parse_manifest(composer)
        assert len(result) == 2
        assert all(r[2] == "Packagist" for r in result)


class TestFindManifests:
    def test_finds_manifests_in_tree(self, scanner, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        sub = tmp_path / "backend"
        sub.mkdir()
        (sub / "requirements.txt").write_text("flask==2.0\n")

        # Should NOT find things inside node_modules
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text("{}")

        manifests = scanner._find_manifests(tmp_path)
        paths = [str(m) for m in manifests]
        assert any("requirements.txt" in p for p in paths)
        assert not any("node_modules" in p for p in paths)


class TestDisabled:
    @pytest.mark.asyncio
    async def test_disabled_scanner(self):
        config = DependencyScanConfig(enabled=False)
        scanner = DependencyScanner(config)
        result = await scanner.scan()
        assert result.total_count == 0
