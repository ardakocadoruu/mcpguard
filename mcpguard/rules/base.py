"""Core data types shared across the mcpguard rule system."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

_SEVERITY_PENALTIES: dict[str, int] = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 1,
}


class Severity(StrEnum):
    """Ordered severity levels used throughout mcpguard.

    The ``str`` mixin allows direct comparison with plain strings and
    produces clean JSON serialisation without extra transformation.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score_penalty(self) -> int:
        """Return the score deduction associated with this severity level."""
        return _SEVERITY_PENALTIES[self.value]


#: Score deduction per finding at each severity level (kept for compatibility).
SEVERITY_DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 1,
}


@dataclass
class Finding:
    """A single security or quality issue discovered by a rule.

    Attributes:
        rule_id:      Stable identifier of the rule that produced this finding.
        severity:     How serious the issue is.
        title:        Short, human-readable summary (one sentence).
        description:  Detailed explanation of the problem and its impact.
        file_path:    Source file where the issue was found, relative to package root.
        line:         1-based line number inside *file_path*, if applicable.
        evidence:     Verbatim (possibly redacted) snippet that triggered the finding.
        remediation:  Actionable guidance for fixing the issue.
    """

    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: str | None = None
    line: int | None = None
    evidence: str | None = None
    remediation: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line": self.line,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ScanTarget:
    """Fully resolved description of the package being scanned.

    Attributes:
        name:         Package name as declared in ``package.json``.
        version:      Package version string.
        package_dir:  Absolute path to the unpacked package root.
        manifest:     Parsed ``package.json`` contents.
        source_files: JS/TS source files selected for analysis.
    """

    name: str
    version: str
    package_dir: Path
    manifest: dict  # type: ignore[type-arg]
    source_files: list[Path] = field(default_factory=list)


class Rule(abc.ABC):
    """Abstract base class for all mcpguard security rules.

    Subclasses must:
    1. Set a unique class-level ``id`` (e.g. ``"MCP001"``).
    2. Implement :meth:`check`, which receives a :class:`ScanTarget` and
       returns a (possibly empty) list of :class:`Finding` objects.
    3. Register themselves by appending an instance to
       ``mcpguard.rules.ALL_RULES``.
    """

    #: Stable, unique identifier for this rule (e.g. ``"MCP001"``).
    id: str = ""
    title: str = ""
    description: str = ""

    @abc.abstractmethod
    def check(self, target: ScanTarget) -> list[Finding]:
        """Analyse *target* and return any findings.

        This method **must not raise** — callers wrap it in try/except so a
        single broken rule cannot abort a full scan.

        Args:
            target: Fully resolved package to inspect.

        Returns:
            A list of :class:`Finding` objects (empty if the package is clean).
        """
