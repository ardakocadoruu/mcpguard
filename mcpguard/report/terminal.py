"""Rich-powered terminal report renderer for mcpguard.

Provides two public APIs:

* :class:`ScanProgress` — a context manager that displays a live spinner
  and prints progress milestones while a scan is running.
* :func:`render_result` — renders the final scan results to a Rich
  :class:`~rich.console.Console` after the scan completes.
"""

from __future__ import annotations

from types import TracebackType
from typing import TYPE_CHECKING

from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.style import Style
from rich.text import Text

from mcpguard.rules.base import Severity

if TYPE_CHECKING:
    from mcpguard.scanner import ScanResult

__all__ = ["ScanProgress", "render_result"]

# ── Severity styling ──────────────────────────────────────────────────────────

_SEVERITY_STYLE: dict[str, Style] = {
    Severity.CRITICAL.value: Style(color="bright_red", bold=True),
    Severity.HIGH.value: Style(color="red"),
    Severity.MEDIUM.value: Style(color="yellow"),
    Severity.LOW.value: Style(color="blue"),
    Severity.INFO.value: Style(dim=True),
}

_SEVERITY_BORDER: dict[str, str] = {
    Severity.CRITICAL.value: "bright_red",
    Severity.HIGH.value: "red",
    Severity.MEDIUM.value: "yellow",
    Severity.LOW.value: "blue",
    Severity.INFO.value: "white",
}

_SEVERITY_ORDER = [s.value for s in Severity]

# ── Score bar helpers ─────────────────────────────────────────────────────────

_BAR_WIDTH = 20
_BAR_FILL = "█"
_BAR_EMPTY = "░"


def _score_color(score: int) -> str:
    if score >= 80:
        return "green"
    if score >= 60:
        return "yellow"
    return "red"


def _build_score_bar(score: int) -> Text:
    """Return a 20-character coloured block bar representing *score*."""
    filled = round(_BAR_WIDTH * score / 100)
    empty = _BAR_WIDTH - filled
    color = _score_color(score)
    bar = Text()
    bar.append(_BAR_FILL * filled, style=color)
    bar.append(_BAR_EMPTY * empty, style="dim")
    return bar


def _print_header(console: Console) -> None:
    header = Text()
    header.append("mcpguard", style="bold cyan")
    header.append(" • ", style="dim")
    header.append("MCP Security Scanner", style="bold white")
    console.print(Panel(header, expand=False, border_style="cyan"))
    console.print()


# ── ScanProgress ──────────────────────────────────────────────────────────────


class ScanProgress:
    """Context manager that shows a Rich spinner while a scan runs.

    The :meth:`update` method is compatible with a progress-callback signature
    ``(message: str) -> None`` and should be called from scan orchestration code.

    Args:
        quiet:    If ``True`` suppress all progress output.
        no_color: If ``True`` disable Rich markup and colour.

    Example::

        with ScanProgress() as prog:
            result = run_scan(progress_cb=prog.update)
        render_result(result, console)
    """

    def __init__(self, quiet: bool = False, no_color: bool = False) -> None:
        self._quiet = quiet
        self._no_color = no_color
        self._console = Console(stderr=True, no_color=no_color, highlight=False)
        self._progress: Progress | None = None
        self._task_id: object = None
        self._milestones: list[str] = []

    def __enter__(self) -> ScanProgress:
        if not self._quiet:
            _print_header(self._console)
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self._console,
                transient=True,
            )
            self._progress.__enter__()
            self._task_id = self._progress.add_task("Initialising …", total=None)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._progress is not None:
            self._progress.__exit__(exc_type, exc_val, exc_tb)
            self._progress = None

        if not self._quiet and exc_type is None:
            for msg in self._milestones:
                self._console.print(f"  [green]✓[/green] {msg}")
            self._console.print()

    def update(self, message: str) -> None:
        """Progress callback — call with a status string during scan execution."""
        if self._quiet:
            return
        if self._progress is not None and self._task_id is not None:
            self._progress.update(self._task_id, description=message)  # type: ignore[arg-type]
        self._track_milestone(message)

    def _track_milestone(self, message: str) -> None:
        """Capture key milestones for the post-scan summary."""
        keywords = ("fetched", "parsed manifest", "running", "scanning")
        lower = message.lower()
        if any(kw in lower for kw in keywords):
            self._milestones.append(message)


# ── render_result ─────────────────────────────────────────────────────────────


def render_result(
    result: ScanResult,
    console: Console,
    *,
    package_spec: str | None = None,
    scan_duration_s: float | None = None,
    min_severity: str = "INFO",
) -> None:
    """Render a complete scan report to *console*.

    Args:
        result:          The completed :class:`~mcpguard.scanner.ScanResult`.
        console:         The :class:`~rich.console.Console` to write to.
        package_spec:    The original package argument used in the header.
        scan_duration_s: Wall-clock scan time in seconds, if known.
        min_severity:    Only display findings at or above this level.
    """
    display_name = package_spec or f"{result.name}@{result.version}"

    console.print(Rule(style="dim"))
    console.print()

    # ── Title ─────────────────────────────────────────────────────────────────
    title = Text()
    title.append("  SCAN RESULTS  ", style="bold white")
    title.append(display_name, style="bold cyan")
    console.print(title)
    console.print()

    # ── Score bar ─────────────────────────────────────────────────────────────
    score = result.score
    color = _score_color(score)
    bar = _build_score_bar(score)

    score_line = Text("  Security Score:  ")
    score_line.append(f"{score} / 100", style=f"bold {color}")
    score_line.append("   Grade: ", style="dim")
    score_line.append(result.grade, style=f"bold {color}")
    console.print(score_line)

    bar_line = Text("  ")
    bar_line.append_text(bar)
    console.print(bar_line)
    console.print()

    # ── Findings ──────────────────────────────────────────────────────────────
    # _SEVERITY_ORDER is [CRITICAL, HIGH, MEDIUM, LOW, INFO] — lower index = more severe.
    # "At or above CRITICAL" means index <= CRITICAL's index (0).
    # "At or above INFO" means index <= INFO's index (4) → show everything.
    min_idx = (
        _SEVERITY_ORDER.index(min_severity.upper())
        if min_severity.upper() in _SEVERITY_ORDER
        else len(_SEVERITY_ORDER) - 1
    )
    by_sev: dict[str, list[object]] = {s: [] for s in _SEVERITY_ORDER}
    for f in result.findings:
        if _SEVERITY_ORDER.index(f.severity.value) <= min_idx:
            by_sev[f.severity.value].append(f)

    total = sum(len(v) for v in by_sev.values())

    if total == 0:
        console.print(Padding("[dim]  No findings.[/dim]", (0, 0, 1, 0)))
    else:
        console.print("  [bold]Findings:[/bold]")
        console.print()
        for sev in _SEVERITY_ORDER:
            for finding in by_sev[sev]:
                _render_finding_panel(finding, console)

    # ── Summary ───────────────────────────────────────────────────────────────
    summary_line = Text("  Summary: ")
    for i, sev in enumerate(_SEVERITY_ORDER):
        if i:
            summary_line.append("  ·  ", style="dim")
        count = len(by_sev[sev])
        style = _SEVERITY_STYLE.get(sev, Style())
        summary_line.append(str(count), style=style)
        summary_line.append(f" {sev}", style=style)
    console.print(summary_line)

    # ── Stats ─────────────────────────────────────────────────────────────────
    stats = Text("  Scan completed", style="dim")
    if scan_duration_s is not None:
        stats.append(f" in {scan_duration_s:.1f}s", style="dim")
    stats.append(f"  ·  {result.files_scanned} files analyzed", style="dim")
    console.print(stats)
    console.print()

    # ── Verdict ───────────────────────────────────────────────────────────────
    _render_verdict(result, console)
    console.print()


# ── Internal helpers ──────────────────────────────────────────────────────────


def _render_finding_panel(finding: object, console: Console) -> None:
    """Render a single finding as a bordered Rich Panel."""
    from mcpguard.rules.base import Finding

    assert isinstance(finding, Finding)

    sev = finding.severity.value
    sev_style = _SEVERITY_STYLE.get(sev, Style())
    border_color = _SEVERITY_BORDER.get(sev, "white")

    # Header: [SEVERITY] RULE_ID  Title
    header = Text()
    header.append(f"[{sev}]", style=sev_style)
    header.append(f"  {finding.rule_id}", style="bold")
    header.append(f"  {finding.title}", style="bold white")

    # Body
    body = Text()
    body.append(finding.description, style="white")

    if finding.evidence:
        body.append("\n")
        body.append("Evidence: ", style="dim")
        body.append(finding.evidence, style="italic")

    body.append("\n")
    body.append("Remediation: ", style="dim")
    body.append(finding.remediation, style="green")

    if finding.file_path:
        loc = finding.file_path
        if finding.line is not None:
            loc += f":{finding.line}"
        body.append("\n")
        body.append("Location: ", style="dim")
        body.append(loc, style="cyan")

    panel = Panel(
        body,
        title=header,
        title_align="left",
        border_style=border_color,
        padding=(0, 1),
    )
    console.print(Padding(panel, (0, 2, 1, 2)))


def _render_verdict(result: ScanResult, console: Console) -> None:
    """Print the PASSED / FAILED verdict line."""
    critical = result.critical_count
    high = result.high_count
    score = result.score

    if critical > 0:
        noun = "issue" if critical == 1 else "issues"
        msg = Text("  ")
        msg.append("✗", style="bold bright_red")
        msg.append("  FAILED", style="bold bright_red")
        msg.append(
            f" — {critical} critical {noun} require immediate attention",
            style="bright_red",
        )
        console.print(msg)
    elif high > 0:
        noun = "issue" if high == 1 else "issues"
        msg = Text("  ")
        msg.append("✗", style="bold red")
        msg.append("  FAILED", style="bold red")
        msg.append(f" — {high} high-severity {noun} detected", style="red")
        console.print(msg)
    elif score < 60:
        msg = Text("  ")
        msg.append("⚠", style="bold yellow")
        msg.append("  WARNING", style="bold yellow")
        msg.append(" — security score below acceptable threshold", style="yellow")
        console.print(msg)
    elif score >= 90:
        msg = Text("  ")
        msg.append("✓", style="bold green")
        msg.append("  PASSED", style="bold green")
        msg.append(" — package appears safe", style="green")
        console.print(msg)
    else:
        msg = Text("  ")
        msg.append("✓", style="bold green")
        msg.append("  PASSED", style="bold green")
        msg.append(f" — no critical issues found (score: {score}/100)", style="green")
        console.print(msg)
