"""Rule MCP002 — overly broad permission usage in MCP tool handlers.

MCP servers run with full OS privileges granted to the host process.  When
tool handlers expose unrestricted filesystem access, dynamic code execution,
or blanket environment-variable reads, the AI models that invoke those tools
gain capabilities far beyond what is needed.  This rule flags patterns that
indicate an overly permissive tool implementation.
"""

from __future__ import annotations

import re

from mcpguard.rules.base import Finding, Rule, ScanTarget, Severity

__all__ = ["PermissionsRule"]

# ---------------------------------------------------------------------------
# Compiled detection patterns
# ---------------------------------------------------------------------------

# Root-filesystem access: readdir("/") or readFileSync("/etc/…")
_ROOT_FS_RE = re.compile(
    r"""
    (?:
        readdirSync\s*\(\s*["'`]/["'`]          # readdirSync("/")
        | readdirSync\s*\(\s*["'`]/\s*["'`]     # readdirSync("/ ")
        | readFileSync\s*\(\s*["'`]/(?:etc|proc|sys|root|var|usr)
        | readFile\s*\(\s*["'`]/(?:etc|proc|sys|root|var|usr)
    )
    """,
    re.VERBOSE,
)

# General unrestricted filesystem operations
_FS_OPS_RE = re.compile(
    r"""
    (?:
        fs\.readFileSync\s*\(
        | fs\.writeFileSync\s*\(
        | fs\.rmSync\s*\(
        | fs\.unlinkSync\s*\(
        | fs\.appendFileSync\s*\(
        | fs\.copyFileSync\s*\(
        | fs\.renameSync\s*\(
        | fs\.mkdirSync\s*\(
        | fs\.rmdirSync\s*\(
    )
    """,
    re.VERBOSE,
)

# process.env reads (expose all env vars to AI)
_PROCESS_ENV_RE = re.compile(r"process\.env\b")

# eval() or new Function() with dynamic content
_EVAL_RE = re.compile(
    r"""
    (?:
        \beval\s*\(                   # eval(
        | new\s+Function\s*\(         # new Function(
    )
    """,
    re.VERBOSE,
)

# Dynamic require: require(variable) or require(`${…}`)
_DYNAMIC_REQUIRE_RE = re.compile(
    r"""
    \brequire\s*\(
    \s*
    (?!
        ['"`]                         # NOT a plain string literal
    )
    """,
    re.VERBOSE,
)

# JS/TS file suffixes we analyse
_JS_SUFFIXES = {".js", ".ts", ".mjs", ".cjs"}


class PermissionsRule(Rule):
    """Detect overly broad permission usage in MCP tool handler source files.

    MCP tools that grant the invoking AI model unrestricted filesystem access,
    dynamic code-execution primitives (eval / Function constructor), or the
    ability to read the entire process environment create an attack surface that
    an adversarial prompt or a compromised AI can exploit.

    Checks performed:
    - CRITICAL: root-filesystem traversal (``readdirSync("/")``,
      ``readFileSync("/etc/…")``)
    - HIGH: arbitrary ``fs.readFileSync``, ``fs.writeFileSync``,
      ``fs.rmSync``, ``fs.unlinkSync`` calls
    - CRITICAL: ``eval(…)`` or ``new Function(…)`` with dynamic content
    - HIGH: dynamic ``require(variable)``
    - MEDIUM: ``process.env`` reads inside tool handler files

    Rule ID: MCP002
    """

    id = "MCP002"
    title = "Overly broad permissions in MCP tool handler"
    description = (
        "The MCP tool handler uses filesystem, eval, or environment APIs "
        "that grant the invoking AI model capabilities far beyond what is "
        "necessary.  This violates the principle of least privilege and can "
        "be exploited by a malicious prompt or a compromised AI client."
    )

    def check(self, target: ScanTarget) -> list[Finding]:  # noqa: PLR0912
        """Scan JS/TS source files for overly permissive API usage.

        Args:
            target: The populated scan target.

        Returns:
            A list of :class:`Finding` objects, one per suspicious line.
        """
        findings: list[Finding] = []

        js_files = [f for f in target.source_files if f.suffix in _JS_SUFFIXES]

        for source_file in js_files:
            try:
                content = source_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            lines = content.splitlines()
            rel_path = str(source_file.relative_to(target.package_dir))

            for idx, line in enumerate(lines):
                lineno = idx + 1
                stripped = line.strip()
                evidence = stripped[:120]

                # CRITICAL — root filesystem access
                if _ROOT_FS_RE.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=Severity.CRITICAL,
                            title="Root filesystem access in tool handler",
                            description=(
                                "The tool handler reads from the root filesystem (e.g. '/etc', "
                                "'/proc') which exposes sensitive host data to AI model invocations."
                            ),
                            remediation=(
                                "Restrict filesystem access to a dedicated, sandboxed directory.  "
                                "Never expose '/etc', '/proc', or other sensitive paths via MCP tools."
                            ),
                            file_path=rel_path,
                            line=lineno,
                            evidence=evidence,
                        )
                    )
                    continue  # already reported the most severe issue for this line

                # HIGH — general unrestricted fs ops
                if _FS_OPS_RE.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=Severity.HIGH,
                            title="Unrestricted filesystem access in tool handler",
                            description=(
                                "The tool handler performs unrestricted filesystem operations "
                                "(read, write, delete).  An AI model invoking this tool can "
                                "read or modify arbitrary files on the host."
                            ),
                            remediation=(
                                "Scope filesystem access to an allowlisted directory.  Validate "
                                "and sanitise all path arguments before performing any I/O."
                            ),
                            file_path=rel_path,
                            line=lineno,
                            evidence=evidence,
                        )
                    )

                # CRITICAL — eval / new Function
                if _EVAL_RE.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=Severity.CRITICAL,
                            title="Dynamic code execution (eval / Function) in tool handler",
                            description=(
                                "The tool handler uses eval() or the Function constructor, "
                                "which executes arbitrary JavaScript.  If an AI model can "
                                "influence the argument, this becomes remote code execution."
                            ),
                            remediation=(
                                "Remove eval() and the Function constructor entirely.  "
                                "Use a safe, purpose-built interpreter or JSON-based DSL "
                                "if dynamic logic is genuinely required."
                            ),
                            file_path=rel_path,
                            line=lineno,
                            evidence=evidence,
                        )
                    )

                # HIGH — dynamic require
                if _DYNAMIC_REQUIRE_RE.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=Severity.HIGH,
                            title="Dynamic require() in tool handler",
                            description=(
                                "The tool handler calls require() with a dynamic argument.  "
                                "This can be exploited to load arbitrary modules or files "
                                "if an AI model can control the argument value."
                            ),
                            remediation=(
                                "Use a static allowlist of permitted module names.  "
                                "Never pass user-supplied or AI-supplied values to require()."
                            ),
                            file_path=rel_path,
                            line=lineno,
                            evidence=evidence,
                        )
                    )

                # INFO — process.env (reading env vars for config is normal; flag only as info)
                if _PROCESS_ENV_RE.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=Severity.INFO,
                            title="process.env access in tool handler",
                            description=(
                                "The tool handler reads from process.env.  This is normal for "
                                "configuration, but verify that raw env values (API keys, tokens) "
                                "are not returned directly in tool responses to the AI model."
                            ),
                            remediation=(
                                "Read required environment variables once at startup and store "
                                "them in private variables.  Never return raw env values to the "
                                "AI model as part of a tool response."
                            ),
                            file_path=rel_path,
                            line=lineno,
                            evidence=evidence,
                        )
                    )

        return findings
