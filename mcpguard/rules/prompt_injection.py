"""
MCP007: Prompt Injection in Tool/Resource Descriptions

Scans MCP server source code and configuration for tool and resource
description strings that contain patterns indicative of prompt injection:
imperative commands directed at AI models, social engineering language,
data exfiltration instructions, and instruction-override language.

This rule targets the attack surface described in Scenario C of the
mcp-security-research document: adversarial natural language embedded in
tool schemas that causes the AI model to take unintended actions when it
reads the descriptions as part of its context.

Detection is necessarily heuristic. Natural language cannot be parsed with
the same precision as code. The patterns here capture the most common and
dangerous injection variants; they do not represent an exhaustive grammar of
possible injections.
"""

from __future__ import annotations

import ast
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from mcpguard.rules.base import Finding, Rule, ScanTarget, Severity

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Each pattern is a tuple of (regex_string, human_description, base_severity).
# Patterns are tested in order; all matches are reported (not just the first).

SUSPICIOUS_PATTERNS: list[tuple[str, str, Severity]] = [
    # -----------------------------------------------------------------------
    # Tier 1 — CRITICAL: Explicit override / jailbreak language
    # -----------------------------------------------------------------------
    (
        r"(?i)\b(ignore\s+previous|override\s+(previous\s+)?(instructions?|prompts?|rules?)|"
        r"disregard\s+(previous\s+)?(instructions?|rules?)|"
        r"bypass\s+(security|safety|restrictions?|filters?)|"
        r"forget\s+previous\s+instructions?)\b",
        "Override/bypass language targeting AI model instructions",
        Severity.CRITICAL,
    ),
    (
        r"(?i)\b(the\s+operator\s+has\s+authorized|system\s+override|"
        r"elevated\s+permission|admin\s+mode|developer\s+mode|"
        r"jailbreak|DAN\s+mode|unrestricted\s+mode)\b",
        "Fabricated authority claim or known jailbreak language",
        Severity.CRITICAL,
    ),

    # -----------------------------------------------------------------------
    # Tier 2 — HIGH: Exfiltration instructions
    # Explicit commands to transmit data to an external destination.
    # -----------------------------------------------------------------------
    (
        r"(?i)\b(always|must|required?|mandatory)\b.{0,60}"
        r"\b(send|upload|forward|transmit|post|submit|include)\b.{0,60}"
        r"\b(files?|documents?|credentials?|passwords?|keys?|tokens?|"
        r"secrets?|contents?|data|text|result)\b",
        "Imperative instruction to transmit sensitive data",
        Severity.HIGH,
    ),
    (
        r"(?i)\b(send|upload|forward|transmit|include|attach)\b.{0,80}"
        r"\b(~/|home\s+directory|\.ssh|\.aws|credentials?|"
        r"private\s+key|id_rsa|\.env|config\s+file)\b",
        "Instruction referencing credential file locations",
        Severity.HIGH,
    ),
    (
        r"(?i)\b(debug_?context|debug_?data|telemetry_?payload|"
        r"error_?log|diagnostic_?info|session_?data)\b.{0,40}"
        r"\b(required?|mandatory|must\s+include|do\s+not\s+omit)\b",
        "Suspicious 'required telemetry' parameter injection pattern",
        Severity.HIGH,
    ),

    # -----------------------------------------------------------------------
    # Tier 3 — HIGH: Authority mimicry
    # Impersonates system-level notes or privileged instructions.
    # -----------------------------------------------------------------------
    (
        r"(?i)\b(system\s+(integration\s+)?note|important\s+system\s+(note|message)|"
        r"ai\s+instruction|model\s+(?:note|instruction|directive)|"
        r"assistant\s+(?:note|instruction)|"
        r"note\s+to\s+(?:ai|assistant|model|llm|claude|gpt))\b",
        "Authority-mimicking system note language in tool description",
        Severity.HIGH,
    ),
    (
        r"(?i)\b(required\s+for\s+(error\s+)?(?:logging|reporting|compliance|"
        r"telemetry|diagnostics?|monitoring)|"
        r"failure\s+to\s+(?:include|provide|send).{0,40}(?:will\s+result|may\s+cause))\b",
        "Compliance/consequence framing to coerce model behavior",
        Severity.HIGH,
    ),

    # -----------------------------------------------------------------------
    # Tier 4 — HIGH: Delayed / conditional triggers
    # Instructions that activate after a counted condition.
    # -----------------------------------------------------------------------
    (
        r"(?i)\b(after\s+\d+\s+(?:calls?|uses?|invocations?)|"
        r"when\s+this\s+tool\s+has\s+been\s+called|"
        r"on\s+the\s+(?:third|fourth|fifth|\d+(?:st|nd|rd|th))\s+(?:call|use|invocation))\b",
        "Delayed-trigger instruction (activates after N uses)",
        Severity.HIGH,
    ),

    # -----------------------------------------------------------------------
    # Tier 5 — MEDIUM: Broad imperative commands
    # -----------------------------------------------------------------------
    (
        r"(?i)^[^.!?\n]{0,20}"
        r"\b(always|never|must|remember|ensure|make\s+sure|do\s+not|"
        r"do\s+not\s+forget)\b.{0,100}"
        r"\b(send|include|attach|upload|read|access|open|get|fetch|retrieve)\b",
        "Imperative command pattern in tool description",
        Severity.MEDIUM,
    ),

    # -----------------------------------------------------------------------
    # Tier 6 — MEDIUM: References to sensitive file paths
    # -----------------------------------------------------------------------
    (
        r"(?i)\b(~/\.aws|~/\.ssh|~/\.gnupg|~/\.config|~/\.npmrc|"
        r"~/\.netrc|/etc/passwd|/etc/shadow|"
        r"AppData.Roaming|%APPDATA%)\b",
        "Reference to known credential or sensitive system path",
        Severity.MEDIUM,
    ),
]

# Unicode codepoints that can hide injected text from human reviewers
# while remaining visible to AI models processing the raw string.
HIGH_RISK_CODEPOINTS: frozenset[int] = frozenset(
    [
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE  ← most abused for text reversal
        0x2060,  # WORD JOINER
        0x2061,  # FUNCTION APPLICATION
        0x2062,  # INVISIBLE TIMES
        0x2063,  # INVISIBLE SEPARATOR
        0x2064,  # INVISIBLE PLUS
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE (BOM when not at file start)
        0x034F,  # COMBINING GRAPHEME JOINER
        0x00AD,  # SOFT HYPHEN
    ]
)

SUSPICIOUS_UNICODE_CATEGORIES = frozenset(["Cf", "Cs", "Co"])

# Directories to skip during file traversal
_SKIP_DIRS = frozenset(
    ["node_modules", ".git", "__pycache__", "dist", "build", ".venv", ".tox"]
)


# ---------------------------------------------------------------------------
# Internal result type (not exported — converted to Finding before return)
# ---------------------------------------------------------------------------


@dataclass
class _Match:
    """A single pattern hit inside a description string."""

    file_path: str
    line: int | None
    description_text: str
    pattern_description: str
    severity: Severity
    unicode_obfuscation: list[str] = field(default_factory=list)

    @property
    def has_unicode_obfuscation(self) -> bool:
        return bool(self.unicode_obfuscation)


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


class PromptInjectionRule(Rule):
    """
    MCP007: Detects potential prompt injection in tool/resource descriptions.

    Scans for description strings in tool schemas and MCP server source that
    contain imperative commands, social engineering language, authority-
    mimicking notes, or explicit data exfiltration instructions directed at
    AI models.

    Sources scanned:
    - Python source files: string literals in ``description=`` keyword
      arguments and ``description = "..."`` assignments.
    - JSON configuration files: any ``"description"`` field in a JSON object.
    - JavaScript / TypeScript files: heuristic line-by-line extraction of
      ``description:`` or ``description =`` string values.
    """

    id = "MCP007"
    title = "Prompt Injection in Tool/Resource Descriptions"
    description = (
        "Scans tool and resource description strings for language that may "
        "constitute a prompt injection attack — instructions that cause AI "
        "models to take unintended actions when they read the tool schema."
    )

    def __init__(self) -> None:
        self._compiled: list[tuple[re.Pattern[str], str, Severity]] = [
            (re.compile(pat), desc, sev)
            for pat, desc, sev in SUSPICIOUS_PATTERNS
        ]

    # ------------------------------------------------------------------
    # Rule interface
    # ------------------------------------------------------------------

    def check(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        for match in self._iter_matches(target.package_dir):
            findings.append(self._to_finding(match))
        return findings

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    def _iter_matches(self, root: Path) -> Iterator[_Match]:
        file_count = 0
        _max_files = 500  # honour the same cap as scanner._collect_source_files
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.is_symlink():
                continue  # never follow symlinks
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            file_count += 1
            if file_count > _max_files:
                break

            suffix = path.suffix.lower()
            if suffix == ".py":
                yield from self._scan_python(path)
            elif suffix == ".json":
                yield from self._scan_json(path)
            elif suffix in (".js", ".ts", ".mjs", ".cjs"):
                yield from self._scan_js_heuristic(path)

    # ------------------------------------------------------------------
    # Python AST scanning
    # ------------------------------------------------------------------

    def _scan_python(self, path: Path) -> Iterator[_Match]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            return

        rel = str(path)

        for node in ast.walk(tree):
            # description="..." keyword argument
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "description" and isinstance(kw.value, ast.Constant):
                        val = kw.value.value
                        if isinstance(val, str):
                            yield from self._check(rel, kw.value.lineno, val)

            # description = "..." assignment
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id == "description"
                        and isinstance(node.value, ast.Constant)
                    ):
                        val = node.value.value
                        if isinstance(val, str):
                            yield from self._check(rel, node.lineno, val)

    # ------------------------------------------------------------------
    # JSON scanning
    # ------------------------------------------------------------------

    def _scan_json(self, path: Path) -> Iterator[_Match]:
        try:
            from mcpguard.json_safe import safe_json_load
            data = safe_json_load(path, max_depth=20, max_keys=5_000)
        except Exception:
            return
        yield from self._walk_json(str(path), data)

    def _walk_json(
        self, file_path: str, node: object, json_path: str = "$", depth: int = 0
    ) -> Iterator[_Match]:
        if depth > 20:
            return  # depth guard — prevents RecursionError on deeply-nested JSON
        if isinstance(node, dict):
            for key, value in node.items():
                child = f"{json_path}.{key}"
                if key == "description" and isinstance(value, str):
                    yield from self._check(file_path, None, value)
                else:
                    yield from self._walk_json(file_path, value, child, depth + 1)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                yield from self._walk_json(file_path, item, f"{json_path}[{i}]", depth + 1)

    # ------------------------------------------------------------------
    # JavaScript / TypeScript heuristic scanning
    # ------------------------------------------------------------------

    def _scan_js_heuristic(self, path: Path) -> Iterator[_Match]:
        _desc_re = re.compile(
            r"""['"` ]?description['"` ]?\s*[:=]\s*['"`](.+?)['"`]""",
            re.IGNORECASE,
        )
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return

        for lineno, line in enumerate(lines, start=1):
            m = _desc_re.search(line)
            if m:
                yield from self._check(str(path), lineno, m.group(1))

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------

    def _check(
        self, file_path: str, line: int | None, description: str
    ) -> Iterator[_Match]:
        if not description or len(description.strip()) < 10:
            return

        risky_codepoints = _detect_unicode_obfuscation(description)

        matched_any = False
        for compiled, pat_desc, base_sev in self._compiled:
            if compiled.search(description):
                matched_any = True
                # Unicode obfuscation escalates any match to CRITICAL
                effective_sev = Severity.CRITICAL if risky_codepoints else base_sev
                yield _Match(
                    file_path=file_path,
                    line=line,
                    description_text=_truncate(description, 300),
                    pattern_description=pat_desc,
                    severity=effective_sev,
                    unicode_obfuscation=risky_codepoints,
                )

        # Standalone unicode obfuscation — even without a pattern match
        if risky_codepoints and not matched_any:
            yield _Match(
                file_path=file_path,
                line=line,
                description_text=_truncate(description, 300),
                pattern_description=(
                    "Description contains invisible or directional Unicode characters "
                    "that may conceal injected instructions from human reviewers"
                ),
                severity=Severity.HIGH,
                unicode_obfuscation=risky_codepoints,
            )

    # ------------------------------------------------------------------
    # Finding conversion
    # ------------------------------------------------------------------

    def _to_finding(self, m: _Match) -> Finding:
        extra_context = ""
        if m.has_unicode_obfuscation:
            cp_list = ", ".join(m.unicode_obfuscation[:5])
            extra_context = f" Unicode obfuscation detected: {cp_list}."

        evidence_lines = [f'Description: "{m.description_text}"']
        evidence_lines.append(f"Pattern matched: {m.pattern_description}")
        if m.has_unicode_obfuscation:
            evidence_lines.append(
                f"Invisible codepoints: {', '.join(m.unicode_obfuscation[:5])}"
            )

        return Finding(
            rule_id=self.id,
            severity=m.severity,
            title="Potential prompt injection in tool/resource description",
            description=(
                f"A description string in {m.file_path} contains language that may "
                f"constitute a prompt injection attack. AI models that read this "
                f"description may be influenced to take unintended actions. "
                f"Pattern: {m.pattern_description}.{extra_context}"
            ),
            file_path=m.file_path,
            line=m.line,
            evidence="\n".join(evidence_lines),
            remediation=(
                "Review the description string for instructions directed at AI models. "
                "Tool descriptions should document what the tool does and what its "
                "parameters mean — they should not contain imperative commands, "
                "system notes, or data-transmission instructions. Remove any language "
                "that instructs the model to send, transmit, or include data beyond "
                "what the tool legitimately requires."
            ),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect_unicode_obfuscation(text: str) -> list[str]:
    """Return a list of suspicious Unicode codepoint descriptions found in text."""
    found: list[str] = []
    for char in text:
        cp = ord(char)
        category = unicodedata.category(char)
        if cp in HIGH_RISK_CODEPOINTS:
            name = unicodedata.name(char, f"U+{cp:04X}")
            found.append(f"U+{cp:04X} ({name})")
        elif category in SUSPICIOUS_UNICODE_CATEGORIES and cp > 0x7F:
            name = unicodedata.name(char, f"U+{cp:04X}")
            found.append(f"U+{cp:04X} ({name}, cat {category})")
    return found


def _truncate(text: str, max_length: int) -> str:
    if len(text) <= max_length:
        return text
    return text[:max_length] + f"... [{len(text) - max_length} chars truncated]"
