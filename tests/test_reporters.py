"""Tests for report generators."""

import json
import pytest
from datetime import datetime

from vigil.models import Finding, ScanResult, Severity
from vigil.reporters.json_reporter import JSONReporter
from vigil.reporters.html_reporter import HTMLReporter


@pytest.fixture
def sample_results():
    result = ScanResult(scanner_name="test_scanner")
    result.findings = [
        Finding(
            scanner="test",
            severity=Severity.CRITICAL,
            title="Critical Issue",
            description="Something very bad",
            file_path="/tmp/test.py",
            line_number=42,
            recommendation="Fix it now",
        ),
        Finding(
            scanner="test",
            severity=Severity.INFO,
            title="Info",
            description="Everything is fine",
        ),
    ]
    result.finished_at = datetime.utcnow()
    return [result]


class TestJSONReporter:
    def test_generates_valid_json(self, sample_results):
        reporter = JSONReporter()
        output = reporter.generate(sample_results)
        data = json.loads(output)
        assert data["summary"]["total_findings"] == 2
        assert data["summary"]["critical"] == 1

    def test_writes_to_file(self, sample_results, tmp_path):
        reporter = JSONReporter()
        output_file = str(tmp_path / "report.json")
        reporter.generate(sample_results, output_file)
        data = json.loads((tmp_path / "report.json").read_text())
        assert data["summary"]["total_findings"] == 2


class TestHTMLReporter:
    def test_generates_html(self, sample_results):
        reporter = HTMLReporter()
        html = reporter.generate(sample_results)
        assert "<html" in html
        assert "Vigil Security Report" in html
        assert "Critical Issue" in html

    def test_writes_to_file(self, sample_results, tmp_path):
        reporter = HTMLReporter()
        output_file = str(tmp_path / "report.html")
        reporter.generate(sample_results, output_file)
        html = (tmp_path / "report.html").read_text()
        assert "Critical Issue" in html

    def test_escapes_html(self, sample_results):
        sample_results[0].findings[0].title = '<script>alert("xss")</script>'
        reporter = HTMLReporter()
        html = reporter.generate(sample_results)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
