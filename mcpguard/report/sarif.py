"""SARIF 2.1.0 report formatter for mcpguard scan results.

Produces Static Analysis Results Interchange Format (SARIF) output
compatible with GitHub Code Scanning and other SAST tooling.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from mcpguard import __version__
from mcpguard.rules.base import Severity
from mcpguard.scanner import ScanResult

__all__ = ["render_sarif"]

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

_SEVERITY_TO_LEVEL: dict[str, str] = {
    Severity.CRITICAL.value: "error",
    Severity.HIGH.value: "error",
    Severity.MEDIUM.value: "warning",
    Severity.LOW.value: "note",
    Severity.INFO.value: "note",
}


def render_sarif(result: ScanResult, *, indent: int = 2) -> str:
    """Serialise *result* to a SARIF 2.1.0 JSON string.

    Args:
        result: The completed scan result.
        indent: JSON indentation level (default 2).

    Returns:
        A SARIF 2.1.0 JSON string suitable for GitHub Code Scanning upload.
    """
    # Build unique rule descriptors from findings
    seen_rules: dict[str, dict[str, Any]] = {}
    for finding in result.findings:
        if finding.rule_id not in seen_rules:
            seen_rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": _to_pascal(finding.title),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_LEVEL.get(finding.severity.value, "warning"),
                },
                "helpUri": (f"https://github.com/arda-mcp/mcpguard/wiki/rules/{finding.rule_id}"),
                "help": {
                    "text": finding.description,
                    "markdown": f"**{finding.title}**\n\n{finding.description}",
                },
            }

    # Add rules that ran but produced no findings
    try:
        from mcpguard.rules import ALL_RULES

        for rule in ALL_RULES:
            if rule.id not in seen_rules:
                seen_rules[rule.id] = {
                    "id": rule.id,
                    "name": _to_pascal(rule.title),
                    "shortDescription": {"text": rule.title},
                    "fullDescription": {"text": rule.description},
                    "defaultConfiguration": {"level": "warning"},
                    "helpUri": (f"https://github.com/arda-mcp/mcpguard/wiki/rules/{rule.id}"),
                }
    except Exception:  # noqa: BLE001
        pass

    # Build SARIF results array
    sarif_results: list[dict[str, Any]] = []
    for finding in result.findings:
        sarif_result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _SEVERITY_TO_LEVEL.get(finding.severity.value, "warning"),
            "message": {
                "text": _build_message(finding),
            },
            "properties": {
                "severity": finding.severity.value,
                "remediation": finding.remediation,
            },
        }

        if finding.file_path:
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path.replace("\\", "/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                },
            }
            if finding.line is not None:
                location["physicalLocation"]["region"] = {
                    "startLine": finding.line,
                    "startColumn": 1,
                }
            sarif_result["locations"] = [location]

        sarif_results.append(sarif_result)

    now_iso = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    doc: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpguard",
                        "version": __version__,
                        "informationUri": "https://github.com/arda-mcp/mcpguard",
                        "rules": list(seen_rules.values()),
                    },
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": now_iso,
                        "toolExecutionNotifications": [],
                    }
                ],
                "results": sarif_results,
                "properties": {
                    "mcpguard:score": result.score,
                    "mcpguard:grade": result.grade,
                    "mcpguard:package": f"{result.name}@{result.version}",
                    "mcpguard:filesScanned": result.files_scanned,
                },
            }
        ],
    }

    return json.dumps(doc, indent=indent, ensure_ascii=False)


def _to_pascal(text: str) -> str:
    """Convert a space-separated title to PascalCase."""
    return "".join(word.capitalize() for word in text.split())


def _build_message(finding: object) -> str:
    """Build a human-readable SARIF result message."""
    from mcpguard.rules.base import Finding

    assert isinstance(finding, Finding)
    parts = [finding.description]
    if finding.evidence:
        parts.append(f"Evidence: {finding.evidence}")
    parts.append(f"Remediation: {finding.remediation}")
    return "  ".join(parts)
