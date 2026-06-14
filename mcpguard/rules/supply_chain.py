"""Rule MCP005 — supply-chain risks in MCP package metadata.

Checks lifecycle scripts for shell-injection payloads, package names for
typosquatting, package registry against a known-bad list, and dependency
version pins.
"""

from __future__ import annotations

import re

from mcpguard.db.vuln_db import VulnDB
from mcpguard.rules.base import Finding, Rule, ScanTarget, Severity
from mcpguard.typosquat import is_typosquat

__all__ = ["SupplyChainRule", "VulnDB"]

# ---------------------------------------------------------------------------
# Patterns for malicious lifecycle scripts
# ---------------------------------------------------------------------------

# Commands that download and execute arbitrary code
_MALICIOUS_SCRIPT_RE = re.compile(
    r"""
    (?:
        curl\s+.+\|\s*(?:ba)?sh    # curl ... | sh / bash
        | wget\s+.+\|\s*(?:ba)?sh  # wget ... | sh / bash
        | python\s+-c\s*['"]\s*import\s+(?:os|subprocess|socket)
        | nc\s+-[el]               # netcat listen/execute
        | /dev/tcp/                # bash reverse shell
        | base64\s+-d\s*\|         # base64-decode-then-pipe
        | eval\s*\$\(curl          # eval $(curl ...)
        | sh\s+-i\s*>&?            # interactive shell redirect
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Lifecycle script hook names that run automatically on npm install / publish
_AUTO_HOOKS = frozenset(
    {
        "preinstall",
        "install",
        "postinstall",
        "prepublish",
        "prepare",
        "prepack",
        "postpack",
    }
)

# Unpinned / wildcard version specifiers
_UNPINNED_RE = re.compile(
    r"""
    ^(?:
        \*
        | latest
        | next
        | x
        |               # empty string
        | >.*           # open-ended range
    )$
    """,
    re.VERBOSE,
)


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------


class SupplyChainRule(Rule):
    """Detect supply-chain risks in MCP package metadata.

    Checks:
    - CRITICAL: lifecycle scripts that download and execute arbitrary code
    - HIGH: any lifecycle script present (postinstall, preinstall, prepare, …)
    - CRITICAL: package name is in the known-bad registry
    - HIGH: package name is a likely typosquat of a well-known MCP package
    - MEDIUM: unpinned / wildcard dependency versions

    Rule ID: MCP005
    """

    id = "MCP005"
    title = "Supply chain risk detected"
    description = (
        "The package metadata contains indicators of supply-chain compromise: "
        "dangerous lifecycle scripts, a known-bad name, a likely typosquatted "
        "name, or unpinned dependency versions."
    )

    def __init__(self, vuln_db: VulnDB | None = None) -> None:
        self._vuln_db = vuln_db if vuln_db is not None else VulnDB()

    def check(self, target: ScanTarget) -> list[Finding]:
        findings: list[Finding] = []
        manifest = target.manifest

        # ── 1. Lifecycle scripts ──────────────────────────────────────────
        scripts: dict[str, str] = {}
        raw = manifest.get("scripts")
        if isinstance(raw, dict):
            scripts = {str(k): str(v) for k, v in raw.items()}

        for hook, cmd in scripts.items():
            if hook not in _AUTO_HOOKS:
                continue
            if _MALICIOUS_SCRIPT_RE.search(cmd):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=Severity.CRITICAL,
                        title=f"Malicious lifecycle script: {hook}",
                        description=(
                            f"The '{hook}' script contains a pattern consistent with "
                            f"remote code execution or data exfiltration: `{cmd[:80]}`."
                        ),
                        file_path="package.json",
                        evidence=f'"{hook}": "{cmd[:80]}"',
                        remediation=(
                            "Remove the lifecycle script immediately.  Do not install this "
                            "package unless you trust the source completely."
                        ),
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        severity=Severity.HIGH,
                        title=f"Lifecycle script present: {hook}",
                        description=(
                            f"The package defines a '{hook}' script that runs automatically "
                            f"during npm install: `{cmd[:80]}`.  Any code run at install time "
                            f"executes with the privileges of the installing user."
                        ),
                        file_path="package.json",
                        evidence=f'"{hook}": "{cmd[:80]}"',
                        remediation=(
                            "Audit the script carefully.  If it is not strictly required, "
                            "remove it.  Prefer explicit post-install documentation over "
                            "automated hooks."
                        ),
                    )
                )

        # ── 2. Known-bad registry ─────────────────────────────────────────
        pkg_name: str = str(manifest.get("name", target.name))
        bad_entry = self._vuln_db.is_known_bad(pkg_name)
        if bad_entry:
            reason = (
                bad_entry.get("reason", "Listed in vulnerability database")
                if isinstance(bad_entry, dict)
                else str(bad_entry)
            )
            findings.append(
                Finding(
                    rule_id=self.id,
                    severity=Severity.CRITICAL,
                    title="Package is in the known-bad registry",
                    description=(
                        f"'{pkg_name}' is listed in the mcpguard known-bad database.  "
                        f"Reason: {reason}"
                    ),
                    file_path="package.json",
                    evidence=f'"name": "{pkg_name}"',
                    remediation="Do not install or use this package.",
                )
            )

        # ── 3. Typosquatting ──────────────────────────────────────────────
        is_squatter, victim, _dist = is_typosquat(pkg_name)
        if is_squatter and victim:
            findings.append(
                Finding(
                    rule_id=self.id,
                    severity=Severity.HIGH,
                    title="Likely typosquat of a well-known MCP package",
                    description=(
                        f"'{pkg_name}' closely resembles '{victim}' (edit distance ≤ 1).  "
                        f"Typosquatting is a common technique for distributing malicious code."
                    ),
                    file_path="package.json",
                    evidence=f'"name": "{pkg_name}"',
                    remediation=(
                        f"Verify you intended to install '{victim}', not '{pkg_name}'.  "
                        f"Check the registry for the correct package name."
                    ),
                )
            )

        # ── 4. Unpinned dependencies ──────────────────────────────────────
        dep_sections = ["dependencies", "devDependencies", "peerDependencies"]
        for section in dep_sections:
            deps = manifest.get(section)
            if not isinstance(deps, dict):
                continue
            for dep_name, version_spec in deps.items():
                spec = str(version_spec).strip()
                if _UNPINNED_RE.match(spec):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            severity=Severity.MEDIUM,
                            title=f"Unpinned dependency: {dep_name}",
                            description=(
                                f"The dependency '{dep_name}' uses an unpinned version "
                                f"specifier '{spec}' in {section}.  This allows any future "
                                f"version — including malicious ones — to be installed."
                            ),
                            file_path="package.json",
                            evidence=f'"{dep_name}": "{spec}"',
                            remediation=(
                                f"Pin '{dep_name}' to a specific version or a narrow range "
                                f"(e.g. '^1.2.3').  Consider using a lock file."
                            ),
                        )
                    )

        return findings
