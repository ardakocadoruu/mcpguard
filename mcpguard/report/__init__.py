"""Output formatters for mcpguard scan results.

Three built-in reporters are provided:

* :mod:`~mcpguard.report.terminal` — Rich-powered interactive terminal output
  with coloured findings panels, a score bar, and a live scan spinner.
* :mod:`~mcpguard.report.json_reporter` — Machine-readable JSON (schema v1.0)
  for CI pipelines and programmatic consumption.
* :mod:`~mcpguard.report.sarif` — SARIF 2.1.0 output for GitHub Code Scanning
  and other SAST integrations.

Typical usage::

    from mcpguard.report import render_json, render_sarif, render_result, ScanProgress
"""

from mcpguard.report.json_reporter import render_json
from mcpguard.report.sarif import render_sarif
from mcpguard.report.terminal import ScanProgress, render_result

__all__ = [
    "ScanProgress",
    "render_json",
    "render_result",
    "render_sarif",
]
