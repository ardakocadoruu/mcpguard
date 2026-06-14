"""Rule MCP006 — hardcoded secrets and credentials in MCP source files.

Scans JavaScript, TypeScript, Python, and .env files for high-entropy
secret patterns such as API keys, cloud credentials, and private key
blocks.  Evidence strings are redacted before being stored in findings
so that mcpguard output never contains live credentials.
"""

from __future__ import annotations

import re
from pathlib import Path

from mcpguard.rules.base import Finding, Rule, ScanTarget, Severity
from mcpguard.safe_regex import RegexTimeout, regex_timeout

__all__ = ["SecretsRule"]

# ---------------------------------------------------------------------------
# Files / directories to skip (test fixtures, example files)
# ---------------------------------------------------------------------------

_SKIP_DIR_COMPONENTS = frozenset(
    {
        "test",
        "tests",
        "spec",
        "specs",
        "__tests__",
        "fixtures",
        "fixture",
        "mocks",
        "mock",
        "__mocks__",
        "examples",
        "example",
        "samples",
        "sample",
    }
)

_SKIP_FILENAMES = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.test",
        ".env.local.example",
    }
)

_SKIP_SUFFIXES = frozenset({".test.js", ".test.ts", ".spec.js", ".spec.ts"})


def _should_skip(path: Path, package_dir: Path) -> bool:
    try:
        rel = path.relative_to(package_dir)
    except ValueError:
        return False

    # Skip if any directory component is a test/fixture directory
    for part in rel.parts[:-1]:  # exclude filename itself
        if part.lower() in _SKIP_DIR_COMPONENTS:
            return True

    filename = rel.name.lower()

    # Skip known example/template env files
    if filename in _SKIP_FILENAMES:
        return True

    # Skip .test.js / .spec.ts etc.
    name_lower = filename
    for suffix in _SKIP_SUFFIXES:
        if name_lower.endswith(suffix):
            return True

    return False


# ---------------------------------------------------------------------------
# Secret detection patterns: (regex, label)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # OpenAI API key (new sk-proj- format and classic sk- format)
    (
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}", re.ASCII),
        "OpenAI API key",
    ),
    # AWS Access Key ID
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.ASCII),
        "AWS Access Key ID",
    ),
    # AWS Secret Access Key (40-char base64ish string after key context)
    (
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}['\"]?"),
        "AWS Secret Access Key",
    ),
    # GitHub personal access token (classic: ghp_, fine-grained: github_pat_)
    (
        re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{59})\b"),
        "GitHub personal access token",
    ),
    # Generic high-entropy token assignments
    (
        re.compile(
            r"""(?i)(?:api[_\-]?key|secret[_\-]?key|auth[_\-]?token|access[_\-]?token)"""
            r"""\s*[=:]\s*['"][A-Za-z0-9_\-\.]{32,}['"]"""
        ),
        "Hardcoded API key or token",
    ),
    # Stripe secret key
    (
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b"),
        "Stripe secret key",
    ),
    # Slack bot/app token
    (
        re.compile(r"\bxox[bpaso]-[0-9]+-[0-9]+-[A-Za-z0-9]+\b"),
        "Slack token",
    ),
    # PEM-encoded private key block header (triggers on the header line alone)
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "Private key block",
    ),
    # Base64-encoded private key (PKCS#8 / RSA DER often starts with MII)
    (
        re.compile(r"\bMIIE[A-Za-z0-9+/]{40,}"),
        "PEM-encoded private key (base64)",
    ),
]

_SCAN_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".py", ".env", ".sh", ".bash"}


def _redact(value: str, keep_start: int = 8, keep_end: int = 4) -> str:
    """Replace the middle portion of *value* with ``***``."""
    if len(value) <= keep_start + keep_end + 3:
        # Too short to meaningfully redact — show stars only
        return value[:keep_start] + "***"
    return value[:keep_start] + "***" + value[-keep_end:]


def _redact_evidence(line: str, match: re.Match[str]) -> str:
    """Return *line* with the matched secret replaced by a redacted form."""
    raw = match.group(0)
    redacted = _redact(raw)
    return (line[: match.start()] + redacted + line[match.end() :]).strip()[:120]


class SecretsRule(Rule):
    """Detect hardcoded secrets and API keys in MCP source files.

    Evidence values are always redacted: only the first 8 and last 4
    characters of a detected secret are preserved in the finding output.

    Rule ID: MCP006  Severity: CRITICAL
    """

    id = "MCP006"
    title = "Hardcoded secret or credential detected"
    description = (
        "A hardcoded secret (API key, private key, access token, etc.) was "
        "found in the package source code.  Hardcoded secrets are exposed to "
        "anyone who can read the source, including via the npm registry."
    )

    def check(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []

        for source_file in target.source_files:
            if source_file.suffix not in _SCAN_EXTENSIONS:
                continue
            if _should_skip(source_file, target.package_dir):
                continue

            try:
                lines = source_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue

            rel_path = str(source_file.relative_to(target.package_dir))

            for idx, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith(("#", "//")):
                    continue

                first_label: str | None = None
                # Redact ALL matching secrets on this line before storing evidence,
                # so that a second (or third) secret is never exposed in plain text.
                redacted_line = line
                for pattern, label in _SECRET_PATTERNS:
                    try:
                        with regex_timeout(2):
                            m = pattern.search(redacted_line)
                    except RegexTimeout:
                        continue
                    if not m:
                        continue
                    if first_label is None:
                        first_label = label
                    # Redact this match in-place; subsequent patterns search the
                    # already-redacted string so they don't re-expose earlier spans.
                    redacted_line = _redact_evidence(redacted_line, m)

                if first_label is None:
                    continue  # no secrets found on this line

                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=Severity.CRITICAL,
                        title=f"{self.title}: {first_label}",
                        description=self.description,
                        file_path=rel_path,
                        line=idx + 1,
                        evidence=redacted_line.strip()[:120],
                        remediation=(
                            "Remove the secret from source code immediately.  "
                            "Rotate the credential, store it in a secrets manager or "
                            "environment variable, and add the pattern to .gitignore."
                        ),
                    )
                )

        return findings
