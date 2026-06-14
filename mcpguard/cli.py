"""mcpguard command-line interface."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from mcpguard import __version__
from mcpguard.rules import ALL_RULES
from mcpguard.scanner import Scanner

# Severity order for --fail-on comparisons
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _should_fail(result: object, fail_on: str) -> bool:
    """Return True if any finding meets or exceeds the *fail_on* threshold."""
    if fail_on == "never":
        return False
    threshold_idx = _SEVERITY_ORDER.index(fail_on.lower())
    from mcpguard.scanner import ScanResult
    assert isinstance(result, ScanResult)
    for finding in result.findings:
        if _SEVERITY_ORDER.index(finding.severity.value.lower()) >= threshold_idx:
            return True
    return False


def _write_output(text: str, output_path: str | None) -> None:
    """Write *text* to *output_path* or stdout."""
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
    else:
        click.echo(text)


@click.group()
@click.version_option(__version__, "--version", "-V", message="mcpguard %(version)s")
def main() -> None:
    """mcpguard — security scanner for MCP (Model Context Protocol) packages."""


@main.command("version")
def version_cmd() -> None:
    """Print the mcpguard version and exit."""
    click.echo(f"mcpguard {__version__}")


@main.command("rules")
def rules_cmd() -> None:
    """List all built-in security rules."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="mcpguard built-in rules", show_lines=True)
    table.add_column("ID", style="bold cyan", no_wrap=True)
    table.add_column("Title")
    table.add_column("Description")

    for rule in ALL_RULES:
        desc = rule.description
        if len(desc) > 80:
            # truncate at the last word boundary before character 80
            cut = desc[:80].rsplit(" ", 1)[0]
            short_desc = cut + "…"
        else:
            short_desc = desc
        table.add_row(rule.id, rule.title, short_desc)

    console.print(table)


def _scan_and_report(
    package_dir: Path,
    output_format: str,
    min_severity: str,
    fail_on: str,
    output: str | None,
    quiet: bool,
) -> None:
    """Core scan logic shared by `scan` and `scan-local`."""
    scanner = Scanner()
    result = scanner.scan_directory(package_dir)

    if output_format == "json":
        from mcpguard.reporter import JSONReporter
        _write_output(JSONReporter().render(result), output)

    elif output_format == "sarif":
        from mcpguard.reporter import SARIFReporter
        _write_output(SARIFReporter().render(result), output)

    else:
        # Terminal output — use render_result() from report/terminal.py when
        # available, otherwise fall back to the inline renderer below.
        try:
            from rich.console import Console

            from mcpguard.report.terminal import render_result
            console = Console(quiet=quiet)
            render_result(result, console, min_severity=min_severity)
        except (ImportError, AttributeError):
            _render_inline(result, min_severity, quiet)

    # Exit code
    if _should_fail(result, fail_on):
        sys.exit(1)


def _render_inline(result: object, min_severity: str, quiet: bool) -> None:
    """Minimal inline terminal renderer (fallback).

    All untrusted package data (name, version, finding fields) is escaped via
    rich.markup.escape() before being passed to Console.print() to prevent
    Rich markup injection from maliciously crafted package.json fields.
    """
    from rich.console import Console
    from rich.markup import escape

    from mcpguard.scanner import ScanResult
    if not isinstance(result, ScanResult):
        raise TypeError(f"Expected ScanResult, got {type(result)}")

    _severity_colour = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }
    _grade_colour = {
        "A": "bold green",
        "B": "green",
        "C": "yellow",
        "D": "red",
        "F": "bold red",
    }

    console = Console(quiet=quiet)
    grade_colour = _grade_colour.get(result.grade, "white")
    console.print(
        f"\n[bold]mcpguard[/bold] — {escape(result.name)} v{escape(result.version)}"
    )
    console.print(
        f"Score: [{grade_colour}]{result.score}/100 ({result.grade})[/]  |  "
        f"Files: {result.files_scanned}  |  "
        f"Findings: {len(result.findings)}\n"
    )

    _min_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]  # lower index = more severe
    min_idx = _min_order.index(min_severity.upper()) if min_severity.upper() in _min_order else len(_min_order) - 1
    shown = [
        f for f in result.findings
        if _min_order.index(f.severity.value) <= min_idx
    ]

    if not shown:
        console.print("[green]No findings above threshold.[/green]")
    else:
        for f in shown:
            colour = _severity_colour.get(f.severity.value, "white")
            sev = escape(f.severity.value)
            rid = escape(f.rule_id)
            console.print(f"[{colour}][{sev}][/] [{rid}] {escape(f.title)}")
            if f.file_path:
                loc = f"{f.file_path}:{f.line}" if f.line else f.file_path
                console.print(f"  [dim]{escape(loc)}[/dim]")
            if f.evidence:
                console.print(f"  [dim italic]{escape(f.evidence)}[/dim italic]")
            console.print(f"  [blue]Fix:[/blue] {escape(f.remediation)}\n")


# ---------------------------------------------------------------------------
# scan-local command
# ---------------------------------------------------------------------------

@main.command("scan-local")
@click.argument("package_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text", show_default=True,
    help="Output format.",
)
@click.option(
    "--output", "-o",
    default=None, metavar="FILE",
    help="Write output to FILE instead of stdout.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["never", "info", "low", "medium", "high", "critical"], case_sensitive=False),
    default="critical", show_default=True,
    help="Exit with code 1 if any finding meets or exceeds this severity.",
)
@click.option(
    "--min-severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    default="INFO", show_default=True,
    help="Only display findings at or above this severity.",
)
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress progress output.")
def scan_local_cmd(
    package_dir: Path,
    output_format: str,
    output: str | None,
    fail_on: str,
    min_severity: str,
    quiet: bool,
) -> None:
    """Scan a local MCP package directory for security issues."""
    _scan_and_report(package_dir, output_format, min_severity, fail_on, output, quiet)


# ---------------------------------------------------------------------------
# scan command — auto-detects local path vs npm package spec
# ---------------------------------------------------------------------------

@main.command("scan")
@click.argument("package_spec")
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text", show_default=True,
    help="Output format.",
)
@click.option(
    "--output", "-o",
    default=None, metavar="FILE",
    help="Write output to FILE instead of stdout.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["never", "info", "low", "medium", "high", "critical"], case_sensitive=False),
    default="critical", show_default=True,
    help="Exit with code 1 if any finding meets or exceeds this severity.",
)
@click.option(
    "--min-severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    default="INFO", show_default=True,
    help="Only display findings at or above this severity.",
)
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress progress output.")
def scan_cmd(
    package_spec: str,
    output_format: str,
    output: str | None,
    fail_on: str,
    min_severity: str,
    quiet: bool,
) -> None:
    """Scan an MCP package by path or npm package name.

    PACKAGE_SPEC can be:
    \b
      ./path/to/local/pkg    — local directory
      /absolute/path         — local directory
      mcp-server-sqlite      — npm package (latest)
      mcp-server-sqlite@1.0  — npm package (specific version)
      @scope/package         — scoped npm package
    """
    import tempfile

    # Detect whether this is a local path or an npm package spec.
    path = Path(package_spec)
    if path.exists() and path.is_dir():
        _scan_and_report(path, output_format, min_severity, fail_on, output, quiet)
        return

    # Remote npm package — fetch then scan.
    from mcpguard.fetcher import PackageFetcher, PackageFetchError

    with tempfile.TemporaryDirectory(prefix="mcpguard-") as tmpdir:
        fetcher = PackageFetcher()
        import asyncio
        try:
            pkg_dir = asyncio.run(fetcher.fetch(package_spec, Path(tmpdir)))
        except PackageFetchError as exc:
            click.echo(f"[red]Error:[/red] {exc}", err=True)
            sys.exit(2)

        _scan_and_report(pkg_dir, output_format, min_severity, fail_on, output, quiet)
