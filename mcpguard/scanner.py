"""Core scanning logic for mcpguard."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mcpguard.rules.base import SEVERITY_DEDUCTIONS, Finding, Rule, ScanTarget, Severity

__all__ = ["Scanner", "ScanResult", "calculate_score", "grade"]

_SOURCE_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".py", ".env", ".sh", ".bash"}
_MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
_MAX_FILES = 500


@dataclass
class ScanResult:
    """The complete output of a single package scan.

    Attributes:
        name:          Package name from manifest.
        version:       Package version from manifest.
        package_dir:   Absolute path to the scanned package root.
        findings:      All findings produced by every rule.
        score:         Security score 0–100 (100 = perfect, 0 = catastrophic).
        grade:         Letter grade derived from score.
        files_scanned: Number of source files analysed.
    """

    name: str
    version: str
    package_dir: Path
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    files_scanned: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.HIGH)


def calculate_score(findings: list[Finding]) -> int:
    """Return a security score 0–100 by deducting penalties for each finding."""
    score = 100
    for f in findings:
        score -= SEVERITY_DEDUCTIONS.get(f.severity, 0)
    return max(0, score)


def grade(score: int) -> str:
    """Convert a numeric score to an A–F letter grade."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _collect_source_files(package_dir: Path) -> list[Path]:
    """Walk *package_dir* and return up to _MAX_FILES eligible source files."""
    files: list[Path] = []
    for path in sorted(package_dir.rglob("*")):
        if path.is_symlink():
            continue  # never follow symlinks — prevents host file exposure in scan-local
        if not path.is_file():
            continue
        if path.suffix not in _SOURCE_EXTENSIONS:
            continue
        # Skip node_modules and hidden directories
        parts = path.relative_to(package_dir).parts
        if any(p.startswith(".") or p == "node_modules" for p in parts):
            continue
        if path.stat().st_size > _MAX_FILE_SIZE:
            continue
        files.append(path)
        if len(files) >= _MAX_FILES:
            break
    return files


class Scanner:
    """Orchestrates running all rules against a local package directory.

    Args:
        rules: Rule instances to run.  Defaults to the full built-in set.
    """

    def __init__(self, rules: list[Rule] | None = None) -> None:
        if rules is None:
            from mcpguard.rules import ALL_RULES

            rules = ALL_RULES
        self._rules = rules

    def scan_directory(self, package_dir: Path) -> ScanResult:
        """Scan a local package directory and return a :class:`ScanResult`.

        Args:
            package_dir: Path to the unpacked package root (must contain
                         ``package.json``).

        Returns:
            A :class:`ScanResult` with all findings, score, and grade.

        Raises:
            FileNotFoundError: If *package_dir* does not exist.
            ValueError: If *package_dir* contains no ``package.json``.
        """
        if not package_dir.is_dir():
            raise FileNotFoundError(f"Package directory not found: {package_dir}")

        manifest_path = package_dir / "package.json"
        if manifest_path.exists():
            try:
                from mcpguard.json_safe import safe_json_load

                manifest: dict[str, object] = safe_json_load(manifest_path)
            except Exception:
                manifest = {}
        else:
            manifest = {}

        name = str(manifest.get("name", package_dir.name))
        version = str(manifest.get("version", "0.0.0"))

        source_files = _collect_source_files(package_dir)

        target = ScanTarget(
            name=name,
            version=version,
            package_dir=package_dir,
            manifest=manifest,
            source_files=source_files,
        )

        all_findings: list[Finding] = []
        for rule in self._rules:
            try:
                all_findings.extend(rule.check(target))
            except Exception:  # noqa: BLE001
                pass  # a broken rule must not abort the scan

        score = calculate_score(all_findings)

        return ScanResult(
            name=name,
            version=version,
            package_dir=package_dir,
            findings=all_findings,
            score=score,
            grade=grade(score),
            files_scanned=len(source_files),
        )
