"""Rule MCP004 — subprocess or shell execution in MCP server code.

MCP servers that spawn child processes — especially with user-controlled
arguments — can be exploited for remote code execution.
"""

from __future__ import annotations

import re

from mcpguard.rules.base import Finding, Rule, ScanTarget, Severity

__all__ = ["SubprocessRule"]

# Node.js: exec/spawn with method call (child_process.exec, execSync, etc.)
_NODE_EXEC_RE = re.compile(
    r"""
    (?:
        child_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)
        | (?:exec|execSync|spawn|spawnSync)\s*\(
    )
    """,
    re.VERBOSE,
)

# Node.js: bare require('child_process') import — no method call required
_NODE_REQUIRE_CP_RE = re.compile(
    r"""require\s*\(\s*['"]child_process['"]\s*\)""",
    re.VERBOSE,
)

# Python subprocess / os equivalents
_PYTHON_EXEC_RE = re.compile(
    r"""
    (?:
        subprocess\.(?:run|call|check_output|check_call|Popen)
        | os\.(?:system|popen|execv|execve|execvp)
        | commands\.getoutput
    )
    \s*\(
    """,
    re.VERBOSE,
)

# Dynamic arg construction: template literal `cmd ${var}`, f-string, or string concat
_DYNAMIC_ARG_RE = re.compile(
    r"""
    (?:exec|spawn|system|Popen|subprocess\.run)\s*\(
    \s*(?:`[^`]*\$\{|f['"][^'"]*\{|['"]\s*\+)
    """,
    re.VERBOSE,
)

# Python shell=True is especially dangerous
_SHELL_TRUE_RE = re.compile(r"shell\s*=\s*True", re.IGNORECASE)

_SOURCE_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".py"}


class SubprocessRule(Rule):
    """Detect subprocess and shell-execution calls in MCP server source files.

    Severity levels:
    - CRITICAL: dynamic argument construction in subprocess call (RCE risk)
    - HIGH: static subprocess/shell call (exec, spawn, os.system, etc.)
    - MEDIUM: bare ``require('child_process')`` import

    Rule ID: MCP004
    """

    id = "MCP004"
    title = "Subprocess or shell execution detected"
    description = (
        "The MCP server spawns child processes or executes shell commands.  "
        "If any argument is influenced by client input, this is a remote code "
        "execution (RCE) vulnerability."
    )

    def check(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []

        for source_file in target.source_files:
            suffix = source_file.suffix
            if suffix not in _SOURCE_EXTENSIONS:
                continue

            try:
                lines = source_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            rel_path = str(source_file.relative_to(target.package_dir))
            is_python = suffix == ".py"
            exec_pattern = _PYTHON_EXEC_RE if is_python else _NODE_EXEC_RE

            for idx, line in enumerate(lines):
                # --- CRITICAL: dynamic argument injection ---
                if _DYNAMIC_ARG_RE.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=Severity.CRITICAL,
                            title="Dynamic argument in subprocess call (RCE risk)",
                            description=(
                                "A subprocess call constructs its command or arguments "
                                "dynamically, potentially from client-controlled data.  "
                                "This is a critical remote code execution risk."
                            ),
                            file_path=rel_path,
                            line=idx + 1,
                            evidence=line.strip()[:120],
                            remediation=(
                                "Never pass client-supplied values directly to subprocess calls.  "
                                "Use an allowlist of permitted commands and pass arguments as a "
                                "list rather than a shell string."
                            ),
                        )
                    )
                    continue  # already the most severe result for this line

                # --- HIGH: static subprocess/exec call ---
                if exec_pattern.search(line):
                    has_shell_true = is_python and bool(_SHELL_TRUE_RE.search(line))
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=Severity.CRITICAL if has_shell_true else Severity.HIGH,
                            title=(
                                "subprocess() with shell=True (RCE risk)"
                                if has_shell_true
                                else self.title
                            ),
                            description=self.description,
                            file_path=rel_path,
                            line=idx + 1,
                            evidence=line.strip()[:120],
                            remediation=(
                                "Never pass client-supplied values directly to subprocess calls.  "
                                "Use an allowlist of permitted commands and pass arguments as a "
                                "list rather than a shell string.  Avoid shell=True in Python."
                            ),
                        )
                    )
                    continue

                # --- MEDIUM: bare require('child_process') import (JS only) ---
                if not is_python and _NODE_REQUIRE_CP_RE.search(line):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=Severity.MEDIUM,
                            title="child_process module imported",
                            description=(
                                "The package imports Node.js child_process, giving it the "
                                "ability to execute arbitrary shell commands.  Even if not "
                                "currently exploited, this capability should be justified."
                            ),
                            file_path=rel_path,
                            line=idx + 1,
                            evidence=line.strip()[:120],
                            remediation=(
                                "Remove child_process imports unless strictly necessary.  "
                                "If required, document why and ensure all exec/spawn calls "
                                "use a static allowlist of commands."
                            ),
                        )
                    )

        return findings
