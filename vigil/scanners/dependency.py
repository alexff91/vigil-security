"""Dependency vulnerability scanner using the OSV.dev API."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import aiohttp

from vigil.config import DependencyScanConfig
from vigil.models import Finding, ScanResult, Severity
from vigil.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def _severity_from_osv(vuln: dict) -> Severity:
    """Map OSV severity to our Severity enum."""
    for severity_entry in vuln.get("severity", []):
        score_str = severity_entry.get("score", "")
        # CVSS score string — extract numeric if present
        try:
            # Try to parse as CVSS vector and extract base score
            if ":" in score_str:
                parts = score_str.split("/")
                for part in parts:
                    try:
                        val = float(part)
                        if val >= 9.0:
                            return Severity.CRITICAL
                        if val >= 7.0:
                            return Severity.HIGH
                        if val >= 4.0:
                            return Severity.MEDIUM
                        return Severity.LOW
                    except ValueError:
                        continue
        except (ValueError, IndexError):
            pass

    # Fall back to database_specific severity
    db_specific = vuln.get("database_specific", {})
    sev = db_specific.get("severity", "").upper()
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(sev, Severity.MEDIUM)


class DependencyScanner(BaseScanner):
    """Scan dependency files for known vulnerabilities via OSV.dev."""

    name = "dependency"

    def __init__(self, config: DependencyScanConfig) -> None:
        self.config = config

    async def scan(self) -> ScanResult:
        result = self._make_result()

        if not self.config.enabled:
            return self._finish_result(result)

        paths = self.config.paths or ["."]

        for scan_path in paths:
            p = Path(scan_path).resolve()
            if p.is_file():
                await self._scan_file(p, result)
            elif p.is_dir():
                for manifest in self._find_manifests(p):
                    await self._scan_file(manifest, result)
            else:
                logger.warning("Path does not exist: %s", scan_path)

        return self._finish_result(result)

    def _find_manifests(self, directory: Path) -> list[Path]:
        """Find dependency manifest files in a directory tree."""
        manifests = []
        patterns = [
            "package.json",
            "requirements.txt",
            "Pipfile.lock",
            "poetry.lock",
            "Gemfile.lock",
            "go.sum",
            "Cargo.lock",
            "pom.xml",
            "build.gradle",
            "composer.lock",
        ]
        for pattern in patterns:
            manifests.extend(directory.rglob(pattern))

        # Filter out node_modules and .venv
        return [
            m for m in manifests
            if "node_modules" not in m.parts
            and ".venv" not in m.parts
            and "venv" not in m.parts
        ]

    async def _scan_file(self, file_path: Path, result: ScanResult) -> None:
        """Parse a manifest file and query OSV for vulnerabilities."""
        logger.info("Scanning %s", file_path)
        packages = self._parse_manifest(file_path)

        if not packages:
            return

        queries = []
        for pkg_name, version, ecosystem in packages:
            if version:
                queries.append({
                    "package": {"name": pkg_name, "ecosystem": ecosystem},
                    "version": version,
                })

        if not queries:
            return

        # Batch query OSV.dev
        try:
            async with aiohttp.ClientSession() as session:
                # OSV batch endpoint accepts up to 1000 queries
                for i in range(0, len(queries), 1000):
                    batch = queries[i:i + 1000]
                    async with session.post(
                        OSV_BATCH_URL,
                        json={"queries": batch},
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as resp:
                        if resp.status != 200:
                            logger.error("OSV API returned %d", resp.status)
                            continue
                        data = await resp.json()

                    for idx, resp_item in enumerate(data.get("results", [])):
                        vulns = resp_item.get("vulns", [])
                        if not vulns:
                            continue
                        query = batch[idx]
                        pkg = query["package"]["name"]
                        ver = query.get("version", "unknown")
                        for vuln in vulns:
                            finding = self._vuln_to_finding(vuln, pkg, ver, file_path)
                            result.findings.append(finding)

        except aiohttp.ClientError as e:
            logger.error("Failed to query OSV.dev: %s", e)
            result.error = f"OSV API error: {e}"

    def _vuln_to_finding(
        self, vuln: dict, package: str, version: str, file_path: Path
    ) -> Finding:
        vuln_id = vuln.get("id", "UNKNOWN")
        summary = vuln.get("summary", "No description available")
        aliases = vuln.get("aliases", [])
        cve = next((a for a in aliases if a.startswith("CVE-")), None)
        severity = _severity_from_osv(vuln)

        return Finding(
            scanner=self.name,
            severity=severity,
            title=f"{vuln_id}: {package}@{version}",
            description=summary,
            file_path=str(file_path),
            cve_id=cve or vuln_id,
            recommendation=f"Update {package} to a patched version. See https://osv.dev/vulnerability/{vuln_id}",
            metadata={
                "package": package,
                "version": version,
                "vuln_id": vuln_id,
                "aliases": aliases,
                "references": [r.get("url") for r in vuln.get("references", [])],
            },
        )

    def _parse_manifest(self, file_path: Path) -> list[tuple[str, Optional[str], str]]:
        """Parse a manifest file and return (name, version, ecosystem) tuples."""
        name = file_path.name.lower()

        if name == "package.json":
            return self._parse_package_json(file_path)
        if name == "requirements.txt":
            return self._parse_requirements_txt(file_path)
        if name == "pipfile.lock":
            return self._parse_pipfile_lock(file_path)
        if name == "poetry.lock":
            return self._parse_poetry_lock(file_path)
        if name == "gemfile.lock":
            return self._parse_gemfile_lock(file_path)
        if name == "go.sum":
            return self._parse_go_sum(file_path)
        if name == "cargo.lock":
            return self._parse_cargo_lock(file_path)
        if name == "composer.lock":
            return self._parse_composer_lock(file_path)

        return []

    def _parse_package_json(self, path: Path) -> list[tuple[str, Optional[str], str]]:
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return []

        packages = []
        for section in ("dependencies", "devDependencies"):
            for name, version_spec in data.get(section, {}).items():
                # Strip ^ ~ >= etc to get a semver-ish version
                version = version_spec.lstrip("^~>=<! ")
                if version:
                    packages.append((name, version, "npm"))
        return packages

    def _parse_requirements_txt(self, path: Path) -> list[tuple[str, Optional[str], str]]:
        packages = []
        try:
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Handle name==version, name>=version, etc.
                for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
                    if sep in line:
                        name, version = line.split(sep, 1)
                        packages.append((name.strip(), version.strip(), "PyPI"))
                        break
                else:
                    packages.append((line.split("[")[0].strip(), None, "PyPI"))
        except OSError:
            pass
        return packages

    def _parse_pipfile_lock(self, path: Path) -> list[tuple[str, Optional[str], str]]:
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return []
        packages = []
        for section in ("default", "develop"):
            for name, info in data.get(section, {}).items():
                version = info.get("version", "").lstrip("=")
                if version:
                    packages.append((name, version, "PyPI"))
        return packages

    def _parse_poetry_lock(self, path: Path) -> list[tuple[str, Optional[str], str]]:
        packages = []
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                logger.warning("tomllib/tomli not available, skipping poetry.lock")
                return []
        try:
            data = tomllib.loads(path.read_text())
            for pkg in data.get("package", []):
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                if name and version:
                    packages.append((name, version, "PyPI"))
        except (OSError, Exception) as e:
            logger.warning("Failed to parse %s: %s", path, e)
        return packages

    def _parse_gemfile_lock(self, path: Path) -> list[tuple[str, Optional[str], str]]:
        packages = []
        try:
            in_specs = False
            for line in path.read_text().splitlines():
                if line.strip() == "GEM":
                    in_specs = False
                if line.strip() == "specs:":
                    in_specs = True
                    continue
                if in_specs and line.startswith("      "):
                    # Indented under specs — these are sub-dependencies
                    continue
                if in_specs and line.startswith("    "):
                    parts = line.strip().split(" ")
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1].strip("()")
                        packages.append((name, version, "RubyGems"))
        except OSError:
            pass
        return packages

    def _parse_go_sum(self, path: Path) -> list[tuple[str, Optional[str], str]]:
        packages = []
        seen = set()
        try:
            for line in path.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].split("/")[0].lstrip("v")
                    key = (name, version)
                    if key not in seen:
                        seen.add(key)
                        packages.append((name, version, "Go"))
        except OSError:
            pass
        return packages

    def _parse_cargo_lock(self, path: Path) -> list[tuple[str, Optional[str], str]]:
        packages = []
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                return []
        try:
            data = tomllib.loads(path.read_text())
            for pkg in data.get("package", []):
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                if name and version:
                    packages.append((name, version, "crates.io"))
        except (OSError, Exception):
            pass
        return packages

    def _parse_composer_lock(self, path: Path) -> list[tuple[str, Optional[str], str]]:
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return []
        packages = []
        for section in ("packages", "packages-dev"):
            for pkg in data.get(section, []):
                name = pkg.get("name", "")
                version = pkg.get("version", "").lstrip("v")
                if name and version:
                    packages.append((name, version, "Packagist"))
        return packages
