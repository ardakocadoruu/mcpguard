"""Shared pytest fixtures for mcpguard tests."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from mcpguard.db.vuln_db import VulnDB
from mcpguard.rules.base import ScanTarget

# ---------------------------------------------------------------------------
# Minimal valid MCP package fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_pkg(tmp_path: Path) -> Path:
    """Create a minimal, clean MCP package directory.

    Contains:
    - package.json with name, version, description
    - index.js with a stub MCP server (no tools, no network calls)

    Returns the package directory path.
    """
    pkg_dir = tmp_path / "mcp-test-pkg"
    pkg_dir.mkdir()

    manifest = {
        "name": "mcp-test-pkg",
        "version": "1.0.0",
        "description": "A minimal test MCP package",
        "main": "index.js",
        "dependencies": {
            "@modelcontextprotocol/sdk": "^1.0.0",
        },
    }
    (pkg_dir / "package.json").write_text(json.dumps(manifest, indent=2))

    # Clean index.js — no tools, no network, no subprocess
    (pkg_dir / "index.js").write_text(
        "const { Server } = require('@modelcontextprotocol/sdk');\n"
        "const server = new Server({ name: 'test', version: '1.0.0' });\n"
        "server.connect();\n"
    )

    return pkg_dir


# ---------------------------------------------------------------------------
# Package factory fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def make_pkg(tmp_path: Path) -> Callable[..., Path]:
    """Return a factory that creates configurable MCP package directories.

    Usage::

        def test_something(make_pkg):
            pkg = make_pkg(
                name="my-pkg",
                scripts={"postinstall": "node setup.js"},
                source_files={"index.js": "server.tool('x', async () => {})"},
                dependencies={"lodash": "^4.0.0"},
                extra_manifest={"mcpPermissions": ["filesystem:write"]},
            )
    """
    counter = [0]

    def _factory(
        name: str = "mcp-test",
        version: str = "1.0.0",
        scripts: dict[str, str] | None = None,
        source_files: dict[str, str] | None = None,
        dependencies: dict[str, str] | None = None,
        extra_manifest: dict | None = None,
    ) -> Path:
        counter[0] += 1
        pkg_dir = tmp_path / f"pkg-{counter[0]}"
        pkg_dir.mkdir()

        manifest: dict = {
            "name": name,
            "version": version,
            "main": "index.js",
        }
        if scripts:
            manifest["scripts"] = scripts
        if dependencies:
            manifest["dependencies"] = dependencies
        if extra_manifest:
            manifest.update(extra_manifest)

        (pkg_dir / "package.json").write_text(json.dumps(manifest, indent=2))

        if source_files:
            for filename, content in source_files.items():
                target = pkg_dir / filename
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
        else:
            # Write a blank index.js so there's always a source file
            (pkg_dir / "index.js").write_text("// empty\n")

        return pkg_dir

    return _factory


# ---------------------------------------------------------------------------
# VulnDB fixture with test entries
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_vuln_db(tmp_path: Path) -> VulnDB:
    """Return a VulnDB pre-populated with a few test entries."""
    db_file = tmp_path / "test_known_bad.json"
    db_file.write_text(json.dumps({
        "test-malware": {
            "reason": "Known test malware package used in unit tests.",
            "severity": "CRITICAL",
            "cve": None,
            "reported_date": "2026-01-01",
            "source": "community_report",
            "safe_alternative": None,
        },
        "mcp-stealer": {
            "reason": "Known credential harvesting package.",
            "severity": "CRITICAL",
            "cve": None,
            "reported_date": "2026-01-01",
            "source": "community_report",
            "safe_alternative": None,
        },
        "evil-mcp-tool": {
            "reason": "Exfiltrates environment variables.",
            "severity": "HIGH",
            "cve": None,
            "reported_date": "2026-01-01",
            "source": "automated_scan",
            "safe_alternative": None,
        },
    }), encoding="utf-8")
    return VulnDB(db_path=db_file)


# ---------------------------------------------------------------------------
# ScanTarget builder helper (not a fixture — call directly in tests)
# ---------------------------------------------------------------------------

def make_target(
    pkg_dir: Path,
    source_files: list[Path] | None = None,
    manifest: dict | None = None,
) -> ScanTarget:
    """Build a :class:`ScanTarget` from a package directory."""
    manifest_path = pkg_dir / "package.json"
    if manifest is None:
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
        else:
            manifest = {"name": pkg_dir.name, "version": "0.0.0"}

    if source_files is None:
        source_files = sorted(
            p for p in pkg_dir.rglob("*")
            if p.is_file() and p.suffix in {".js", ".ts", ".mjs", ".cjs", ".py"}
        )

    return ScanTarget(
        name=str(manifest.get("name", pkg_dir.name)),
        version=str(manifest.get("version", "0.0.0")),
        package_dir=pkg_dir,
        manifest=manifest,
        source_files=source_files,
    )
