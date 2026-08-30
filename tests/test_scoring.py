"""Tests for security posture scoring."""

import pytest

from vigil.models import Finding, ScanResult, Severity
from vigil.reporters.markdown_reporter import MarkdownReporter
from vigil.scoring import (
    GRADE_THRESHOLDS,
    SEVERITY_WEIGHTS,
    build_digest,
    compute_score,
    score_to_grade,
)


def _result(scanner, findings):
    r = ScanResult(scanner_name=scanner)
    r.findings = findings
    return r


def _finding(severity, title="t", scanner="dependency", recommendation=None):
    return Finding(
        scanner=scanner,
        severity=severity,
        title=title,
        description="desc",
        recommendation=recommendation,
    )


class TestSeverityWeights:
    def test_weights_descend_by_severity(self):
        assert (
            SEVERITY_WEIGHTS[Severity.CRITICAL]
            > SEVERITY_WEIGHTS[Severity.HIGH]
            > SEVERITY_WEIGHTS[Severity.MEDIUM]
            > SEVERITY_WEIGHTS[Severity.LOW]
        )

    def test_info_has_no_penalty(self):
        assert SEVERITY_WEIGHTS[Severity.INFO] == 0

    def test_penalty_sums_weights(self):
        results = [
            _result("dependency", [
                _finding(Severity.CRITICAL, "c"),
                _finding(Severity.HIGH, "h"),
                _finding(Severity.LOW, "l"),
            ])
        ]
        posture = compute_score(results)
        expected = (
            SEVERITY_WEIGHTS[Severity.CRITICAL]
            + SEVERITY_WEIGHTS[Severity.HIGH]
            + SEVERITY_WEIGHTS[Severity.LOW]
        )
        assert posture.penalty == expected
        assert posture.score == 100 - expected


class TestScoreToGrade:
    @pytest.mark.parametrize(
        "score,grade",
        [(100, "A"), (90, "A"), (89, "B"), (80, "B"), (70, "C"), (65, "D"),
         (60, "D"), (59, "F"), (0, "F")],
    )
    def test_grade_mapping(self, score, grade):
        assert score_to_grade(score) == grade

    def test_thresholds_cover_zero(self):
        assert GRADE_THRESHOLDS[-1][0] == 0


class TestComputeScore:
    def test_perfect_score_when_no_findings(self):
        posture = compute_score([_result("dependency", [])])
        assert posture.score == 100
        assert posture.grade == "A"
        assert posture.total_findings == 0
        assert posture.remediation == []

    def test_info_findings_do_not_lower_score(self):
        posture = compute_score([_result("uptime", [_finding(Severity.INFO)])])
        assert posture.score == 100
        assert posture.total_findings == 1

    def test_score_floored_at_zero(self):
        findings = [_finding(Severity.CRITICAL, f"c{i}") for i in range(10)]
        posture = compute_score([_result("dependency", findings)])
        assert posture.score == 0
        assert posture.grade == "F"

    def test_severity_counts(self):
        results = [_result("dependency", [
            _finding(Severity.CRITICAL, "c"),
            _finding(Severity.MEDIUM, "m1"),
            _finding(Severity.MEDIUM, "m2"),
        ])]
        posture = compute_score(results)
        assert posture.severity_counts[Severity.CRITICAL] == 1
        assert posture.severity_counts[Severity.MEDIUM] == 2
        assert posture.severity_counts[Severity.LOW] == 0

    def test_errors_collected(self):
        r = ScanResult(scanner_name="port", error="boom")
        posture = compute_score([r])
        assert posture.errors == ["port: boom"]


class TestRemediationDedup:
    def test_dedup_by_recommendation(self):
        rec = "Upgrade the package"
        results = [_result("dependency", [
            _finding(Severity.HIGH, "vuln A", recommendation=rec),
            _finding(Severity.HIGH, "vuln B", recommendation=rec),
        ])]
        posture = compute_score(results)
        assert len(posture.remediation) == 1
        assert posture.remediation[0].count == 2

    def test_dedup_keeps_highest_severity(self):
        rec = "Rotate the key"
        results = [_result("secret", [
            _finding(Severity.LOW, "x", recommendation=rec),
            _finding(Severity.CRITICAL, "y", recommendation=rec),
        ])]
        posture = compute_score(results)
        assert posture.remediation[0].severity == Severity.CRITICAL

    def test_distinct_findings_not_collapsed(self):
        results = [_result("dependency", [
            _finding(Severity.HIGH, "a", recommendation="fix a"),
            _finding(Severity.HIGH, "b", recommendation="fix b"),
        ])]
        posture = compute_score(results)
        assert len(posture.remediation) == 2

    def test_prioritized_by_severity_then_count(self):
        results = [_result("dependency", [
            _finding(Severity.MEDIUM, "m", recommendation="fix m"),
            _finding(Severity.MEDIUM, "m", recommendation="fix m"),
            _finding(Severity.CRITICAL, "c", recommendation="fix c"),
            _finding(Severity.LOW, "l", recommendation="fix l"),
        ])]
        posture = compute_score(results)
        severities = [r.severity for r in posture.remediation]
        assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]

    def test_scanners_merged_across_findings(self):
        rec = "shared fix"
        results = [
            _result("dependency", [_finding(Severity.HIGH, "x", "dependency", rec)]),
            _result("secret", [_finding(Severity.HIGH, "y", "secret", rec)]),
        ]
        posture = compute_score(results)
        assert set(posture.remediation[0].scanners) == {"dependency", "secret"}


class TestDigest:
    def test_digest_contains_score_and_grade(self):
        posture = compute_score([_result("dependency", [
            _finding(Severity.CRITICAL, "boom", recommendation="patch it"),
        ])])
        text = build_digest(posture)
        assert f"{posture.score}/100" in text
        assert f"Grade {posture.grade}" in text
        assert "boom" in text

    def test_digest_respects_top_n(self):
        findings = [
            _finding(Severity.HIGH, f"v{i}", recommendation=f"fix {i}")
            for i in range(10)
        ]
        posture = compute_score([_result("dependency", findings)])
        text = build_digest(posture, top_n=3)
        assert text.count("[HIGH]") == 3


class TestMarkdownReporter:
    def test_renders_score_and_remediation(self):
        posture = compute_score([_result("dependency", [
            _finding(Severity.CRITICAL, "Critical bug", recommendation="Patch now"),
        ])])
        md = MarkdownReporter().generate(posture)
        assert "# Vigil Security Posture Report" in md
        assert f"Score: {posture.score}/100" in md
        assert "Critical bug" in md
        assert "Patch now" in md

    def test_writes_to_file(self, tmp_path):
        posture = compute_score([_result("dependency", [])])
        out = tmp_path / "posture.md"
        MarkdownReporter().generate(posture, str(out))
        assert "No remediation needed" in out.read_text()
