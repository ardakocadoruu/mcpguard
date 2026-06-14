"""Rule MCP001 — missing or weak authentication on MCP tool endpoints."""

from __future__ import annotations

import re

from mcpguard.rules.base import Finding, Rule, ScanTarget, Severity

__all__ = ["AuthRule"]

_TOOL_HANDLER_RE = re.compile(
    r"""
    (?:server\.tool|app\.tool|mcp\.tool|addTool|registerTool)
    \s*\(
    """,
    re.VERBOSE,
)

_AUTH_GUARD_RE = re.compile(
    r"""
    (?:
        authenticate|authorize|verifyToken|checkAuth|
        requireAuth|isAuthenticated|validateApiKey|
        bearerToken|apiKey\s*===|session\.user
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_JS_SUFFIXES = {".js", ".ts", ".mjs", ".cjs"}


def _has_auth_nearby(lines: list[str], tool_line_idx: int, window: int = 20) -> bool:
    start = max(0, tool_line_idx - window)
    end = min(len(lines), tool_line_idx + window)
    snippet = "\n".join(lines[start:end])
    return bool(_AUTH_GUARD_RE.search(snippet))


class AuthRule(Rule):
    """Detect MCP tool registrations that lack any authentication guard.

    Rule ID: MCP001  Severity: HIGH
    """

    id = "MCP001"
    title = "Missing authentication on MCP tool endpoint"
    description = (
        "An MCP tool is registered without any visible authentication or "
        "authorisation guard.  Unauthenticated tools can be invoked by any "
        "client connected to the MCP server, including malicious ones."
    )

    def check(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        js_files = [f for f in target.source_files if f.suffix in _JS_SUFFIXES]

        for source_file in js_files:
            try:
                content = source_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            for idx, line in enumerate(lines):
                if not _TOOL_HANDLER_RE.search(line):
                    continue
                if _has_auth_nearby(lines, idx):
                    continue

                rel_path = str(source_file.relative_to(target.package_dir))
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=Severity.HIGH,
                        title=self.title,
                        description=self.description,
                        file_path=rel_path,
                        line=idx + 1,
                        evidence=line.strip()[:120],
                        remediation=(
                            "Add an authentication check before the tool handler executes.  "
                            "Verify a bearer token, API key, or session credential supplied "
                            "by the client in the MCP request context."
                        ),
                    )
                )

        return findings
