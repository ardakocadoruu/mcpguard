"""Output reporters for mcpguard scan results."""

from __future__ import annotations

import json
from typing import Any

from mcpguard.scanner import ScanResult

__all__ = ["JSONReporter", "SARIFReporter"]

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


class JSONReporter:
    """Render a :class:`ScanResult` as a JSON document."""

    def render(self, result: ScanResult) -> str:
        """Return a pretty-printed JSON string representing *result*."""
        data: dict[str, Any] = {
            "schema_version": "1.0",
            "name": result.name,
            "version": result.version,
            "score": result.score,
            "grade": result.grade,
            "files_scanned": result.files_scanned,
            "summary": {
                "critical": result.critical_count,
                "high": result.high_count,
                "total": len(result.findings),
            },
            "findings": [f.as_dict() for f in result.findings],
        }
        return json.dumps(data, indent=2)


class SARIFReporter:
    """Render a :class:`ScanResult` as a SARIF 2.1.0 document."""

    def render(self, result: ScanResult) -> str:
        """Return a SARIF 2.1.0 JSON string for *result*."""
        from mcpguard import __version__

        # Collect unique rule metadata
        rules_seen: dict[str, dict[str, Any]] = {}
        for finding in result.findings:
            if finding.rule_id not in rules_seen:
                rules_seen[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.rule_id,
                    "shortDescription": {"text": finding.title},
                    "helpUri": f"https://github.com/arda-mcp/mcpguard/wiki/{finding.rule_id}",
                }

        _severity_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "none",
        }

        sarif_results = []
        for finding in result.findings:
            sarif_result: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": _severity_map.get(finding.severity.value, "warning"),
                "message": {
                    "text": f"{finding.title}: {finding.description}"
                },
            }
            if finding.file_path and finding.line is not None:
                sarif_result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": finding.line},
                        }
                    }
                ]
            sarif_results.append(sarif_result)

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
                            "rules": list(rules_seen.values()),
                        }
                    },
                    "results": sarif_results,
                    "properties": {
                        "score": result.score,
                        "grade": result.grade,
                    },
                }
            ],
        }
        return json.dumps(doc, indent=2)
