"""JSON report formatter for mcpguard scan results.

Produces a machine-readable JSON document suitable for CI pipelines,
programmatic consumption, and archiving.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from mcpguard.rules.base import Severity
from mcpguard.scanner import ScanResult

__all__ = ["render_json"]

_SCHEMA_VERSION = "1.0"


def render_json(result: ScanResult, *, indent: int = 2) -> str:
    """Serialise *result* to a JSON string.

    Args:
        result: The completed scan result.
        indent: JSON indentation level (default 2).

    Returns:
        A formatted JSON string conforming to the mcpguard report schema v1.0.
    """
    by_sev: dict[str, int] = {s.value.lower(): 0 for s in Severity}
    for f in result.findings:
        by_sev[f.severity.value.lower()] += 1

    doc: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "package": {
            "name": result.name,
            "version": result.version,
        },
        "score": result.score,
        "grade": result.grade,
        "summary": by_sev,
        "findings": [f.as_dict() for f in result.findings],
        "files_scanned": result.files_scanned,
        "scanned_at": datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    return json.dumps(doc, indent=indent, ensure_ascii=False)
