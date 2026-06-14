"""Rule: unrestricted or suspicious outbound network calls in MCP source files.

MCP servers that make arbitrary outbound HTTP/S requests can exfiltrate data,
phone home to attacker-controlled infrastructure, or download and execute
secondary payloads.  This rule flags patterns that indicate unrestricted or
dynamically-constructed network calls.
"""

from __future__ import annotations

import re

from mcpguard.rules.base import Finding, Rule, ScanTarget, Severity

# ── Patterns ──────────────────────────────────────────────────────────────────

_EXFIL_DOMAINS_RE = re.compile(
    r"""
    (?:
        webhook\.site | requestbin\.(?:com|net|io) | pipedream\.net
        | ngrok\.(?:io|app) | burpcollaborator\.net | interact\.sh
        | oast\.(?:pro|fun|me|live|site|online) | canarytokens\.com
        | dnslog\.cn | ceye\.io | xss\.ht | beeceptor\.com | hookbin\.com
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    # CRITICAL — known exfiltration / webhook services
    (
        _EXFIL_DOMAINS_RE,
        "Call to known exfiltration or webhook service",
        Severity.CRITICAL,
    ),
    # Dynamic URL construction — high risk of SSRF / data exfiltration
    (
        re.compile(
            r"""
            (?:fetch|axios|got|request|httpx|urllib)\s*\(
            \s*
            (?:
                [a-zA-Z_$][a-zA-Z0-9_$]*   # variable, not a string literal
                | `[^`]*\$\{                # template literal with interpolation
            )
            """,
            re.VERBOSE,
        ),
        "Dynamic URL in network call (SSRF / exfiltration risk)",
        Severity.HIGH,
    ),
    # Hardcoded non-localhost HTTP URLs (potential data exfiltration beacons)
    (
        re.compile(
            r"""
            (?:fetch|axios\.get|axios\.post|got\.get|got\.post|request\.get|request\.post)
            \s*\(\s*
            ['"](https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"]{10,})['"]\s*,?
            """,
            re.VERBOSE | re.IGNORECASE,
        ),
        "Hardcoded external HTTP URL",
        Severity.MEDIUM,
    ),
    # WebSocket connections to non-localhost addresses
    (
        re.compile(
            r"""new\s+WebSocket\s*\(\s*['"](wss?://(?!localhost|127\.0\.0\.1)[^'"]+)['"]""",
            re.VERBOSE,
        ),
        "WebSocket connection to external host",
        Severity.MEDIUM,
    ),
    # DNS / IP resolution that could be used for C2 beaconing
    (
        re.compile(
            r"""
            (?:
                dns\.resolve|dns\.lookup|
                net\.connect\s*\(\s*\d+\s*,\s*['"]\d+\.\d+\.\d+\.\d+
            )
            """,
            re.VERBOSE,
        ),
        "DNS resolution or raw TCP connection",
        Severity.MEDIUM,
    ),
    # Python-side patterns
    (
        re.compile(
            r"""
            (?:
                requests\.(?:get|post|put|delete|patch|head)\s*\(
                | httpx\.(?:get|post|put|delete|patch)\s*\(
                | urllib\.request\.urlopen\s*\(
                | aiohttp\.ClientSession\s*\(
            )
            \s*
            [a-zA-Z_][a-zA-Z0-9_]*   # variable argument, not a string literal
            """,
            re.VERBOSE,
        ),
        "Python HTTP call with dynamic URL",
        Severity.HIGH,
    ),
]

_SOURCE_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".py"}


class NetworkRule(Rule):
    """Detect unrestricted or suspicious outbound network calls.

    Flags dynamic URL construction in network calls (SSRF risk) and
    connections to external hardcoded hosts (potential data exfiltration).

    Rule ID: NET001
    Severity: HIGH / MEDIUM
    """

    id = "MCP003"
    title = "Suspicious or unrestricted outbound network call"
    description = (
        "The package makes outbound network requests with dynamic or externally-controlled "
        "URLs.  This creates a risk of Server-Side Request Forgery (SSRF), data exfiltration, "
        "or connection to attacker-controlled infrastructure."
    )
    severity_display = "HIGH / MEDIUM"

    def check(self, target: ScanTarget) -> list[Finding]:
        """Scan source files for suspicious outbound network patterns.

        Args:
            target: The populated scan target.

        Returns:
            One finding per suspicious network call site detected.
        """
        findings: list[Finding] = []

        candidate_files = [
            f for f in target.source_files if f.suffix in _SOURCE_EXTENSIONS
        ]

        for source_file in candidate_files:
            try:
                content = source_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            for line_idx, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith(("#", "//")):
                    continue

                for pattern, label, severity in _PATTERNS:
                    if not pattern.search(line):
                        continue

                    rel_path = str(source_file.relative_to(target.package_dir))
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=severity,
                            title=f"Network: {label}",
                            description=self.description,
                            file_path=rel_path,
                            line=line_idx + 1,
                            evidence=stripped[:120],
                            remediation=(
                                "Restrict all outbound network calls to a static allow-list of "
                                "known-good hostnames.  Validate any user- or LLM-supplied URL "
                                "against the allow-list before making the request.  Document all "
                                "external endpoints in the package README."
                            ),
                        )
                    )
                    break  # one finding per line

        return findings
