"""Comprehensive security tests for mcpguard's hardening modules.

Every test here exercises a specific *attack class* from the threat model.
Tests are grouped by module:

    TestSafeExtractor  — path traversal, zip bomb, symlinks, hardlinks,
                         special files, depth, file count, size per member
    TestSafeRegex      — pattern matching, timeout/ReDoS protection
    TestSSRFGuard      — private IPs, schemes, credentials, ports, DNS
    TestJSONSafe       — size gate, depth bomb, key flood, valid parsing

Run with::

    pytest tests/test_security.py -v
"""

from __future__ import annotations

import io
import ipaddress
import json
import re
import tarfile
import time
from pathlib import Path
from unittest import mock

import pytest

from mcpguard.json_safe import (
    JSONSafeError,
    check_json_depth,
    count_json_keys,
    safe_json_load,
    safe_json_loads,
)
from mcpguard.safe_extract import ExtractionError, SafeExtractor
from mcpguard.safe_regex import RegexTimeout, SafeRegex, regex_timeout
from mcpguard.ssrf_guard import BLOCKED_RANGES, SSRFError, SSRFGuard

# ===========================================================================
# Helpers — tarball builders
# ===========================================================================


def _make_tgz(members: list[dict]) -> bytes:
    """Build an in-memory .tgz from a list of member descriptors.

    Each descriptor is a dict with:
        name      — archive member path (required)
        content   — bytes content (default b"")
        type      — tarfile type constant (default REGTYPE)
        linkname  — link target for SYM/LNKTYPE members (default "")
        size_lie  — if set, overrides TarInfo.size in the header (zip bomb test)
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for spec in members:
            info = tarfile.TarInfo(name=spec["name"])
            info.type = spec.get("type", tarfile.REGTYPE)
            info.linkname = spec.get("linkname", "")
            content: bytes = spec.get("content", b"")
            info.size = spec.get("size_lie", len(content))
            tf.addfile(info, io.BytesIO(content))
    buf.seek(0)
    return buf.read()


def _make_tgz_file(tmp_path: Path, members: list[dict]) -> Path:
    """Write a .tgz to *tmp_path* and return the Path."""
    tgz = tmp_path / "test.tgz"
    tgz.write_bytes(_make_tgz(members))
    return tgz


# ===========================================================================
# SafeExtractor tests
# ===========================================================================


class TestSafeExtractor:
    """Tests for mcpguard.safe_extract.SafeExtractor."""

    # -----------------------------------------------------------------------
    # Happy path
    # -----------------------------------------------------------------------

    def test_normal_package_extracts(self, tmp_path: Path) -> None:
        """A well-formed npm tarball extracts cleanly."""
        tgz = _make_tgz_file(
            tmp_path,
            [
                {"name": "package/package.json", "content": b'{"name":"test"}'},
                {"name": "package/index.js", "content": b"module.exports = {};"},
                {"name": "package/lib/utils.js", "content": b"// util"},
            ],
        )
        dest = tmp_path / "out"
        SafeExtractor().extract(tgz, dest)

        assert (dest / "package.json").exists()
        assert (dest / "index.js").exists()
        assert (dest / "lib" / "utils.js").exists()

    def test_strips_npm_package_prefix(self, tmp_path: Path) -> None:
        """The leading 'package/' component is stripped from all paths."""
        tgz = _make_tgz_file(
            tmp_path,
            [{"name": "package/src/main.ts", "content": b"export {}"}],
        )
        dest = tmp_path / "out"
        SafeExtractor().extract(tgz, dest)
        assert (dest / "src" / "main.ts").exists()

    def test_no_package_prefix_still_extracts(self, tmp_path: Path) -> None:
        """Tarballs without a 'package/' prefix also work."""
        tgz = _make_tgz_file(
            tmp_path,
            [{"name": "my-lib/index.js", "content": b"// hi"}],
        )
        dest = tmp_path / "out"
        SafeExtractor().extract(tgz, dest)
        assert (dest / "index.js").exists()

    # -----------------------------------------------------------------------
    # Path traversal attacks
    # -----------------------------------------------------------------------

    def test_path_traversal_dotdot(self, tmp_path: Path) -> None:
        """``../escape`` member is rejected."""
        tgz = _make_tgz_file(
            tmp_path,
            [{"name": "package/../../../tmp/evil", "content": b"pwned"}],
        )
        with pytest.raises(ExtractionError, match="[Pp]ath traversal"):
            SafeExtractor().extract(tgz, tmp_path / "out")

    def test_path_traversal_absolute_path(self, tmp_path: Path) -> None:
        """An absolute path member ``/etc/passwd`` is rejected."""
        # tarfile normally strips leading slashes; we force a TarInfo directly.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo(name="/etc/passwd")
            info.size = 5
            tf.addfile(info, io.BytesIO(b"root:"))
        buf.seek(0)
        tgz = tmp_path / "abs.tgz"
        tgz.write_bytes(buf.read())
        with pytest.raises(ExtractionError, match="[Pp]ath traversal|absolute"):
            SafeExtractor().extract(tgz, tmp_path / "out")

    def test_path_traversal_encoded_dotdot(self, tmp_path: Path) -> None:
        """Deep path that resolves outside dest after normalization is rejected."""
        # Craft a name that looks innocent but resolves outside via symlink
        # or normalization: "package/a/../../evil"
        tgz = _make_tgz_file(
            tmp_path,
            [{"name": "package/a/../../evil.sh", "content": b"rm -rf /"}],
        )
        # After stripping "package/" we get "a/../../evil.sh" which resolves
        # outside dest.
        with pytest.raises(ExtractionError, match="[Pp]ath traversal"):
            SafeExtractor().extract(tgz, tmp_path / "out")

    # -----------------------------------------------------------------------
    # Symlink / hardlink attacks
    # -----------------------------------------------------------------------

    def test_symlink_rejected(self, tmp_path: Path) -> None:
        """A symlink member (even pointing inward) is rejected."""
        tgz = _make_tgz_file(
            tmp_path,
            [
                {"name": "package/real.js", "content": b"// ok"},
                {
                    "name": "package/link.js",
                    "type": tarfile.SYMTYPE,
                    "linkname": "real.js",
                },
            ],
        )
        with pytest.raises(ExtractionError, match="[Ss]ymlink"):
            SafeExtractor().extract(tgz, tmp_path / "out")

    def test_symlink_escape_rejected(self, tmp_path: Path) -> None:
        """A symlink pointing outside the dest directory is rejected."""
        tgz = _make_tgz_file(
            tmp_path,
            [
                {
                    "name": "package/evil_link",
                    "type": tarfile.SYMTYPE,
                    "linkname": "../../../../etc/passwd",
                }
            ],
        )
        with pytest.raises(ExtractionError, match="[Ss]ymlink"):
            SafeExtractor().extract(tgz, tmp_path / "out")

    def test_hardlink_rejected(self, tmp_path: Path) -> None:
        """A hard link member is rejected."""
        tgz = _make_tgz_file(
            tmp_path,
            [
                {"name": "package/index.js", "content": b"// ok"},
                {
                    "name": "package/link.js",
                    "type": tarfile.LNKTYPE,
                    "linkname": "package/index.js",
                },
            ],
        )
        with pytest.raises(ExtractionError, match="[Hh]ard.?link|hardlink"):
            SafeExtractor().extract(tgz, tmp_path / "out")

    # -----------------------------------------------------------------------
    # Zip bomb / resource exhaustion
    # -----------------------------------------------------------------------

    def test_single_file_size_limit(self, tmp_path: Path) -> None:
        """A single file exceeding MAX_SINGLE_FILE is rejected before extraction."""
        ex = SafeExtractor()
        ex.MAX_SINGLE_FILE = 100  # override for test speed
        # Claim 101 bytes in header (actual content can be smaller — we test
        # the header-claim check).
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo(name="package/big.bin")
            info.size = 101
            tf.addfile(info, io.BytesIO(b"x" * 101))
        buf.seek(0)
        tgz = tmp_path / "big.tgz"
        tgz.write_bytes(buf.read())
        with pytest.raises(ExtractionError, match="[Ss]ize|limit"):
            ex.extract(tgz, tmp_path / "out")

    def test_cumulative_size_limit(self, tmp_path: Path) -> None:
        """Total extracted size exceeding MAX_EXTRACTED_SIZE is rejected."""
        ex = SafeExtractor()
        ex.MAX_EXTRACTED_SIZE = 500  # 500 bytes total
        ex.MAX_SINGLE_FILE = 300  # each file is fine individually
        members = [
            {"name": f"package/f{i}.bin", "content": b"x" * 200}
            for i in range(3)  # 3 × 200 = 600 > 500
        ]
        tgz = _make_tgz_file(tmp_path, members)
        with pytest.raises(ExtractionError, match="[Ss]ize|limit|bomb"):
            ex.extract(tgz, tmp_path / "out")

    def test_zip_bomb_actual_size_caught(self, tmp_path: Path) -> None:
        """Actual decompressed bytes exceeding limit abort mid-stream.

        Python's tarfile enforces the declared size when reading from the
        archive, so we cannot create a real header lie via the standard API.
        Instead we patch ``extractfile`` to return more bytes than the header
        declares — this directly exercises the streaming counter in
        ``_extract_members`` independent of the validation pass.
        """
        ex = SafeExtractor()
        ex.MAX_EXTRACTED_SIZE = 50  # streaming limit
        ex.MAX_SINGLE_FILE = 80  # per-file limit (header claims 40 → passes)

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo(name="package/bomb.bin")
            info.size = 40  # declared size passes validation (40 < 50 and 40 < 80)
            tf.addfile(info, io.BytesIO(b"A" * 40))
        buf.seek(0)
        tgz = tmp_path / "bomb.tgz"
        tgz.write_bytes(buf.read())

        # Patch extractfile to return 51 bytes — more than MAX_EXTRACTED_SIZE.
        # This simulates a tarball whose header lied about the uncompressed size.
        bomb_payload = io.BytesIO(b"A" * 51)
        with mock.patch.object(tarfile.TarFile, "extractfile", return_value=bomb_payload):
            with pytest.raises(ExtractionError, match="[Bb]omb|[Ss]ize|[Ll]imit"):
                ex.extract(tgz, tmp_path / "out")

    def test_file_count_limit(self, tmp_path: Path) -> None:
        """Exceeding MAX_FILE_COUNT is rejected during validation."""
        ex = SafeExtractor()
        ex.MAX_FILE_COUNT = 5
        members = [{"name": f"package/f{i}.txt", "content": b"hi"} for i in range(6)]
        tgz = _make_tgz_file(tmp_path, members)
        with pytest.raises(ExtractionError, match="[Cc]ount|[Ll]imit|members"):
            ex.extract(tgz, tmp_path / "out")

    # -----------------------------------------------------------------------
    # Nesting depth
    # -----------------------------------------------------------------------

    def test_nesting_depth_limit(self, tmp_path: Path) -> None:
        """Paths deeper than MAX_NESTING_DEPTH are rejected."""
        ex = SafeExtractor()
        ex.MAX_NESTING_DEPTH = 3
        deep = "package/" + "/".join(["d"] * 5) + "/file.js"
        tgz = _make_tgz_file(tmp_path, [{"name": deep, "content": b"x"}])
        with pytest.raises(ExtractionError, match="[Dd]epth|[Ll]imit"):
            ex.extract(tgz, tmp_path / "out")

    # -----------------------------------------------------------------------
    # Static helpers
    # -----------------------------------------------------------------------

    def test_strip_package_prefix(self) -> None:
        assert SafeExtractor._strip_package_prefix("package/lib/index.js") == "lib/index.js"
        assert SafeExtractor._strip_package_prefix("package/") == ""
        assert SafeExtractor._strip_package_prefix("index.js") == ""
        assert SafeExtractor._strip_package_prefix("") == ""
        assert SafeExtractor._strip_package_prefix("my-pkg/src/a.ts") == "src/a.ts"

    def test_path_depth(self) -> None:
        assert SafeExtractor._path_depth("package/lib/utils/index.js") == 4
        assert SafeExtractor._path_depth("package/index.js") == 2
        assert SafeExtractor._path_depth("") == 0
        assert SafeExtractor._path_depth("single") == 1


# ===========================================================================
# SafeRegex tests
# ===========================================================================


class TestSafeRegex:
    """Tests for mcpguard.safe_regex.SafeRegex."""

    sr = SafeRegex()

    # -----------------------------------------------------------------------
    # Pattern matching — true positives
    # -----------------------------------------------------------------------

    @pytest.mark.parametrize(
        "line",
        [
            'const key = "sk-proj-AbCdEfGhIjKlMnOpQrStUv";',
            "OPENAI_API_KEY=sk-aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678",
            "sk-o1-AAAAAAAAAAAAAAAAAAAAAA",
        ],
    )
    def test_openai_key_detected(self, line: str) -> None:
        assert self.sr.search_line(SafeRegex.OPENAI_KEY, line) is not None

    @pytest.mark.parametrize(
        "line",
        [
            "sk-ant-api03-AAAAAAAAAAAAAAAAAAAA",
            'const k = "sk-ant-BBBBBBBBBBBBBBBBBBBBBBBBB"',
        ],
    )
    def test_anthropic_key_detected(self, line: str) -> None:
        assert self.sr.search_line(SafeRegex.ANTHROPIC_KEY, line) is not None

    @pytest.mark.parametrize(
        "line",
        [
            "AKIAIOSFODNN7EXAMPLE",
            "ASIAIOSFODNN7EXAMPLEXX",
        ],
    )
    def test_aws_access_key_detected(self, line: str) -> None:
        assert self.sr.search_line(SafeRegex.AWS_ACCESS_KEY, line) is not None

    @pytest.mark.parametrize(
        "line",
        [
            # Each token has exactly 36 chars after the prefix (real GitHub PAT length)
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            "gho_123456789012345678901234567890123456ab",
            "ghu_abcdefghijklmnopqrstuvwxyz0123456789ab",
        ],
    )
    def test_github_pat_detected(self, line: str) -> None:
        assert self.sr.search_line(SafeRegex.GITHUB_PAT, line) is not None

    def test_private_key_detected(self) -> None:
        assert (
            self.sr.search_line(SafeRegex.PRIVATE_KEY_BLOCK, "-----BEGIN RSA PRIVATE KEY-----")
            is not None
        )
        assert (
            self.sr.search_line(SafeRegex.PRIVATE_KEY_BLOCK, "-----BEGIN PRIVATE KEY-----")
            is not None
        )

    def test_generic_api_key_detected(self) -> None:
        assert (
            self.sr.search_line(SafeRegex.GENERIC_API_KEY, 'api_key = "ABCDEF1234567890ABCDEF"')
            is not None
        )

    # -----------------------------------------------------------------------
    # Pattern matching — true negatives
    # -----------------------------------------------------------------------

    def test_no_false_positive_on_placeholder(self) -> None:
        # Patterns should not match random short strings.
        assert self.sr.search_line(SafeRegex.OPENAI_KEY, "// set your api key here") is None
        assert self.sr.search_line(SafeRegex.AWS_ACCESS_KEY, "AKIAI") is None  # too short

    # -----------------------------------------------------------------------
    # ALL_PATTERNS convenience method
    # -----------------------------------------------------------------------

    def test_all_patterns_returns_results(self) -> None:
        line = "AKIAIOSFODNN7EXAMPLE"
        results = self.sr.search_all(line)
        assert any("AWS" in desc for _, _, desc in results)

    def test_all_patterns_empty_on_clean_line(self) -> None:
        assert self.sr.search_all("console.log('hello world');") == []

    # -----------------------------------------------------------------------
    # Timeout protection
    # -----------------------------------------------------------------------

    def test_regex_timeout_context_manager_fires(self) -> None:
        """regex_timeout raises RegexTimeout when the body takes too long."""
        with pytest.raises(RegexTimeout):
            with regex_timeout(1):
                # Simulate a slow operation by mocking time.sleep inside a
                # real SIGALRM context — we just block long enough.
                time.sleep(3)

    def test_search_line_returns_none_on_timeout(self) -> None:
        """search_line catches RegexTimeout and returns None (safe-fail).

        We patch SafeRegex._do_search (a plain Python instance method) to raise
        RegexTimeout directly — this avoids trying to monkeypatch the read-only
        C-level ``re.Pattern.search`` attribute, which CPython disallows.
        """
        crafted_pattern = re.compile(r"(a+)+b")
        evil_input = "a" * 40 + "c"

        with mock.patch.object(
            self.sr, "_do_search", side_effect=RegexTimeout("simulated timeout")
        ):
            result = self.sr.search_line(crafted_pattern, evil_input)
            assert result is None

    # -----------------------------------------------------------------------
    # Pattern attributes populated on class
    # -----------------------------------------------------------------------

    def test_all_pattern_attributes_are_compiled(self) -> None:
        for attr in [
            "OPENAI_KEY",
            "ANTHROPIC_KEY",
            "AWS_ACCESS_KEY",
            "GITHUB_PAT",
            "PRIVATE_KEY_BLOCK",
            "GENERIC_API_KEY",
            "DB_PASSWORD",
            "SLACK_TOKEN",
            "STRIPE_KEY",
        ]:
            val = getattr(SafeRegex, attr)
            assert isinstance(val, re.Pattern), f"{attr} is not a compiled Pattern"

    def test_all_patterns_list_populated(self) -> None:
        assert len(SafeRegex.ALL_PATTERNS) >= 9


# ===========================================================================
# SSRFGuard tests
# ===========================================================================


class TestSSRFGuard:
    """Tests for mcpguard.ssrf_guard.SSRFGuard."""

    guard = SSRFGuard()

    # -----------------------------------------------------------------------
    # Allowed URLs
    # -----------------------------------------------------------------------

    def test_valid_https_url_passes(self) -> None:
        """A plain public HTTPS URL should not raise."""
        # We mock DNS resolution so tests don't hit the network.
        public_ip = "104.16.1.1"
        with mock.patch(
            "socket.getaddrinfo", return_value=[(None, None, None, None, (public_ip, 0))]
        ):
            self.guard.validate_url("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")

    def test_valid_http_url_passes(self) -> None:
        public_ip = "8.8.8.8"
        with mock.patch(
            "socket.getaddrinfo", return_value=[(None, None, None, None, (public_ip, 0))]
        ):
            self.guard.validate_url("http://example.com/package.tgz")

    # -----------------------------------------------------------------------
    # Scheme checks
    # -----------------------------------------------------------------------

    @pytest.mark.parametrize("scheme", ["ftp", "file", "gopher", "javascript", "data"])
    def test_non_http_scheme_rejected(self, scheme: str) -> None:
        with pytest.raises(SSRFError, match="[Ss]cheme"):
            self.guard.validate_url(f"{scheme}://example.com/evil")

    # -----------------------------------------------------------------------
    # Embedded credentials
    # -----------------------------------------------------------------------

    def test_credentials_in_url_rejected(self) -> None:
        with pytest.raises(SSRFError, match="[Cc]redential"):
            self.guard.validate_url("https://user:pass@registry.npmjs.org/pkg")

    def test_username_only_rejected(self) -> None:
        with pytest.raises(SSRFError, match="[Cc]redential"):
            self.guard.validate_url("https://admin@internal.example.com/")

    # -----------------------------------------------------------------------
    # Port checks
    # -----------------------------------------------------------------------

    @pytest.mark.parametrize("port", [22, 23, 25, 53, 3306, 6379])
    def test_privileged_non_web_port_rejected(self, port: int) -> None:
        with pytest.raises(SSRFError, match="[Pp]ort"):
            self.guard.validate_url(f"https://example.com:{port}/pkg")

    def test_port_80_allowed(self) -> None:
        public_ip = "1.2.3.4"
        with mock.patch(
            "socket.getaddrinfo", return_value=[(None, None, None, None, (public_ip, 0))]
        ):
            self.guard.validate_url("http://example.com:80/pkg")

    def test_port_443_allowed(self) -> None:
        public_ip = "1.2.3.4"
        with mock.patch(
            "socket.getaddrinfo", return_value=[(None, None, None, None, (public_ip, 0))]
        ):
            self.guard.validate_url("https://example.com:443/pkg")

    def test_high_port_allowed(self) -> None:
        public_ip = "1.2.3.4"
        with mock.patch(
            "socket.getaddrinfo", return_value=[(None, None, None, None, (public_ip, 0))]
        ):
            self.guard.validate_url("https://example.com:8080/pkg")

    # -----------------------------------------------------------------------
    # Private / internal IP blocking (direct IP literals)
    # -----------------------------------------------------------------------

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/admin",
            "http://127.0.0.2/etc/passwd",
            "http://10.0.0.1/secret",
            "http://10.255.255.255/secret",
            "http://172.16.0.1/secret",
            "http://172.31.255.255/secret",
            "http://192.168.1.100/secret",
            "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
            "http://169.254.169.254/computeMetadata/v1/",  # GCP metadata
            "http://0.0.0.0/secret",
        ],
    )
    def test_private_ip_literal_rejected(self, url: str) -> None:
        with pytest.raises(SSRFError, match="[Bb]lock|[Pp]rivate|[Ii]nternal"):
            self.guard.validate_url(url)

    # -----------------------------------------------------------------------
    # BLOCKED_RANGES coverage
    # -----------------------------------------------------------------------

    def test_all_blocked_ranges_are_ip_networks(self) -> None:
        for net in BLOCKED_RANGES:
            assert isinstance(net, ipaddress.IPv4Network | ipaddress.IPv6Network)

    def test_ipv6_loopback_blocked(self) -> None:
        with pytest.raises(SSRFError):
            self.guard.validate_url("http://[::1]/admin")

    # -----------------------------------------------------------------------
    # DNS rebinding / resolved-IP check
    # -----------------------------------------------------------------------

    def test_hostname_resolving_to_private_ip_rejected(self) -> None:
        """A hostname that DNS-resolves to a private IP is rejected."""
        with mock.patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("10.0.0.1", 0))],
        ):
            with pytest.raises(SSRFError, match="[Bb]lock|[Pp]rivate"):
                self.guard.validate_url("https://evil-internal.example.com/pkg")

    def test_hostname_resolving_to_link_local_rejected(self) -> None:
        """A hostname resolving to 169.254.x.x (AWS IMDS) is rejected."""
        with mock.patch(
            "socket.getaddrinfo",
            return_value=[(None, None, None, None, ("169.254.169.254", 0))],
        ):
            with pytest.raises(SSRFError, match="[Bb]lock|[Pp]rivate"):
                self.guard.validate_url("https://metadata.internal/pkg")

    def test_dns_failure_raises_ssrf_error(self) -> None:
        """DNS resolution failure raises SSRFError."""
        with mock.patch("socket.getaddrinfo", side_effect=OSError("NXDOMAIN")):
            with pytest.raises(SSRFError, match="[Dd]NS|resol"):
                self.guard.validate_url("https://nonexistent.invalid/pkg")

    # -----------------------------------------------------------------------
    # httpx event hook
    # -----------------------------------------------------------------------

    def test_event_hook_dict_structure(self) -> None:
        hooks = self.guard.safe_httpx_event_hook()
        assert "request" in hooks
        assert isinstance(hooks["request"], list)
        assert len(hooks["request"]) >= 1

    @pytest.mark.asyncio
    async def test_async_event_hook_blocks_private_ip(self) -> None:
        """The async hook raises SSRFError for a private-IP request."""
        hooks = self.guard.safe_httpx_event_hook()
        async_hook = hooks["request"][0]

        # Simulate a redirect to AWS IMDS
        req = mock.MagicMock(spec=["url"])
        req.url = mock.MagicMock()
        req.url.__str__ = mock.Mock(return_value="http://169.254.169.254/meta-data/")

        with pytest.raises(SSRFError):
            await async_hook(req)


# ===========================================================================
# JSONSafe tests
# ===========================================================================


class TestJSONSafe:
    """Tests for mcpguard.json_safe.*"""

    # -----------------------------------------------------------------------
    # safe_json_load — happy path
    # -----------------------------------------------------------------------

    def test_normal_package_json_loads(self, tmp_path: Path) -> None:
        f = tmp_path / "package.json"
        data = {"name": "my-pkg", "version": "1.0.0", "dependencies": {"lodash": "^4.0.0"}}
        f.write_text(json.dumps(data))
        result = safe_json_load(f)
        assert result["name"] == "my-pkg"

    def test_nested_within_limit_loads(self, tmp_path: Path) -> None:
        nested = {"a": {"b": {"c": {"d": 1}}}}
        f = tmp_path / "p.json"
        f.write_text(json.dumps(nested))
        result = safe_json_load(f, max_depth=10)
        assert result["a"]["b"]["c"]["d"] == 1

    # -----------------------------------------------------------------------
    # Size gate
    # -----------------------------------------------------------------------

    def test_oversized_file_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "big.json"
        f.write_bytes(b'{"k": "' + b"x" * 200 + b'"}')
        with pytest.raises(JSONSafeError, match="[Ss]ize|bytes"):
            safe_json_load(f, max_size_bytes=100)

    def test_file_exactly_at_limit_passes(self, tmp_path: Path) -> None:
        payload = b'{"k": 1}'
        f = tmp_path / "exact.json"
        f.write_bytes(payload)
        result = safe_json_load(f, max_size_bytes=len(payload))
        assert result == {"k": 1}

    # -----------------------------------------------------------------------
    # Depth bomb
    # -----------------------------------------------------------------------

    def test_depth_bomb_rejected(self, tmp_path: Path) -> None:
        """A deeply nested JSON raises JSONSafeError."""
        depth = 30
        obj: dict = {}
        cur = obj
        for _ in range(depth):
            cur["x"] = {}
            cur = cur["x"]
        f = tmp_path / "deep.json"
        f.write_text(json.dumps(obj))
        with pytest.raises(JSONSafeError, match="[Dd]epth"):
            safe_json_load(f, max_depth=20)

    def test_depth_within_limit_passes(self, tmp_path: Path) -> None:
        obj: dict = {}
        cur = obj
        for _ in range(5):
            cur["x"] = {}
            cur = cur["x"]
        f = tmp_path / "shallow.json"
        f.write_text(json.dumps(obj))
        safe_json_load(f, max_depth=20)  # should not raise

    # -----------------------------------------------------------------------
    # Key flood
    # -----------------------------------------------------------------------

    def test_key_flood_rejected(self, tmp_path: Path) -> None:
        """A JSON with too many total keys raises JSONSafeError."""
        big = {f"key_{i}": i for i in range(1000)}
        f = tmp_path / "flood.json"
        f.write_text(json.dumps(big))
        with pytest.raises(JSONSafeError, match="[Kk]ey"):
            safe_json_load(f, max_keys=500)

    def test_key_count_within_limit_passes(self, tmp_path: Path) -> None:
        obj = {f"k{i}": i for i in range(10)}
        f = tmp_path / "small.json"
        f.write_text(json.dumps(obj))
        safe_json_load(f, max_keys=100)

    # -----------------------------------------------------------------------
    # check_json_depth
    # -----------------------------------------------------------------------

    def test_check_depth_correct_value(self) -> None:
        assert check_json_depth({}) == 0
        assert check_json_depth({"a": 1}) == 1
        assert check_json_depth({"a": {"b": {"c": 1}}}) == 3
        assert check_json_depth([1, 2, [3, [4]]]) == 3
        assert check_json_depth("scalar") == 0

    def test_check_depth_raises_on_excess(self) -> None:
        obj: dict = {}
        cur = obj
        for _ in range(25):
            cur["x"] = {}
            cur = cur["x"]
        with pytest.raises(JSONSafeError, match="[Dd]epth"):
            check_json_depth(obj, max_depth=20)

    # -----------------------------------------------------------------------
    # count_json_keys
    # -----------------------------------------------------------------------

    def test_count_keys_flat(self) -> None:
        assert count_json_keys({"a": 1, "b": 2, "c": 3}) == 3

    def test_count_keys_nested(self) -> None:
        assert count_json_keys({"a": 1, "b": {"c": 2, "d": {"e": 3}}}) == 5

    def test_count_keys_in_list(self) -> None:
        assert count_json_keys([{"x": 1}, {"y": 2}]) == 2

    def test_count_keys_scalar(self) -> None:
        assert count_json_keys("hello") == 0
        assert count_json_keys(42) == 0
        assert count_json_keys(None) == 0

    def test_count_keys_empty(self) -> None:
        assert count_json_keys({}) == 0
        assert count_json_keys([]) == 0

    # -----------------------------------------------------------------------
    # safe_json_loads (in-memory variant)
    # -----------------------------------------------------------------------

    def test_safe_json_loads_valid(self) -> None:
        result = safe_json_loads('{"hello": "world"}')
        assert result == {"hello": "world"}

    def test_safe_json_loads_size_gate(self) -> None:
        with pytest.raises(JSONSafeError, match="[Ss]ize|bytes"):
            safe_json_loads("x" * 200, max_size_bytes=100)

    def test_safe_json_loads_invalid_json(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            safe_json_loads("{not valid json}")

    # -----------------------------------------------------------------------
    # Invalid JSON file
    # -----------------------------------------------------------------------

    def test_invalid_json_propagates(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text("{ this is not valid json }")
        with pytest.raises(json.JSONDecodeError):
            safe_json_load(f)


# ===========================================================================
# Integration: ExtractionError is not a subclass of generic exceptions
# ===========================================================================


class TestExceptionHierarchy:
    """Verify exceptions are correctly typed so callers can catch precisely."""

    def test_extraction_error_is_exception(self) -> None:
        exc = ExtractionError("test reason")
        assert isinstance(exc, Exception)
        assert exc.reason == "test reason"

    def test_ssrf_error_carries_url(self) -> None:
        exc = SSRFError("http://10.0.0.1/", "private IP")
        assert exc.url == "http://10.0.0.1/"
        assert exc.reason == "private IP"

    def test_json_safe_error_carries_path(self, tmp_path: Path) -> None:
        p = tmp_path / "x.json"
        exc = JSONSafeError("too deep", path=p)
        assert exc.path == p
        assert "too deep" in str(exc)

    def test_regex_timeout_is_exception(self) -> None:
        assert issubclass(RegexTimeout, Exception)
