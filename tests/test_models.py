"""Tests for data models."""

import pytest
from vigil.models import Finding, ScanResult, Severity


class TestSeverity:
    def test_ordering(self):
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL
        assert not (Severity.CRITICAL < Severity.LOW)


class TestFinding:
    def test_to_dict(self):
        f = Finding(
            scanner="test",
            severity=Severity.HIGH,
            title="Test Finding",
            description="A test",
        )
        d = f.to_dict()
        assert d["scanner"] == "test"
        assert d["severity"] == "high"
        assert d["title"] == "Test Finding"

    def test_optional_fields(self):
        f = Finding(
            scanner="test",
            severity=Severity.LOW,
            title="Minimal",
            description="Minimal finding",
        )
        d = f.to_dict()
        assert d["file_path"] is None
        assert d["cve_id"] is None


class TestScanResult:
    def test_counts(self):
        result = ScanResult(scanner_name="test")
        result.findings = [
            Finding(scanner="test", severity=Severity.CRITICAL, title="c1", description=""),
            Finding(scanner="test", severity=Severity.CRITICAL, title="c2", description=""),
            Finding(scanner="test", severity=Severity.HIGH, title="h1", description=""),
            Finding(scanner="test", severity=Severity.LOW, title="l1", description=""),
        ]
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.total_count == 4

    def test_empty_result(self):
        result = ScanResult(scanner_name="test")
        assert result.total_count == 0
        assert result.critical_count == 0

    def test_to_dict(self):
        result = ScanResult(scanner_name="test")
        d = result.to_dict()
        assert d["scanner"] == "test"
        assert d["total_findings"] == 0
