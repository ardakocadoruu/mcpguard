# mcpguard Security Hardening

> **Audience**: contributors, security reviewers, and anyone integrating mcpguard into a CI pipeline.

## Why mcpguard itself needs hardening

mcpguard is a security scanner — but it is also a program that ingests **fully untrusted data from the internet**. Every npm package it scans could have been authored by an adversary specifically to exploit the scanner.

The attack surface is real: tools like `npm audit`, `snyk`, and `trivy` have all had CVEs where a malicious package could achieve code execution on the scanning host. mcpguard treats this as a first-class threat.

---

## Threat model

The following attack classes are in scope. Each is implemented by a real-world attacker who has published (or poisoned) a package to the npm registry and wants to compromise whoever runs `mcpguard scan <their-package>`.

| # | Attack | Module defending |
|---|--------|-----------------|
| T1 | **Path traversal** in tarball member names | `safe_extract.py` |
| T2 | **Zip bomb** / compressed resource exhaustion | `safe_extract.py` |
| T3 | **Symlink / hard-link escape** from extraction dir | `safe_extract.py` |
| T4 | **Special file injection** (devices, FIFOs) | `safe_extract.py` |
| T5 | **File count / depth exhaustion** | `safe_extract.py` |
| T6 | **Billion-laughs via package.json** | `json_safe.py` |
| T7 | **Key-flood DoS in JSON** | `json_safe.py` |
| T8 | **ReDoS** against secret-detection regexes | `safe_regex.py` |
| T9 | **SSRF** via crafted `dist.tarball` URL | `ssrf_guard.py` |
| T10 | **SSRF via redirect chain** | `ssrf_guard.py` |

---

## Defence details

### T1 — Path traversal (`safe_extract.py`)

**Attack**: a tarball member named `../../etc/passwd` or `/etc/shadow` extracts outside the intended destination directory when the scanner calls `tarfile.extractall()` naively.

**Defence**: `SafeExtractor._validate_all()` resolves every member's destination path *before* extraction using `Path.resolve()` and checks strict containment:

```python
dest_str = str(dest_resolved)
if not (str(dest_path) == dest_str or str(dest_path).startswith(dest_str + "/")):
    raise ExtractionError(...)
```

The trailing `/` in the prefix check is critical — without it, `/tmp/safe` would incorrectly match `/tmp/safe-evil`.

Note that Python's built-in `tarfile` module has supported a `filter='data'` parameter since 3.11.4 (CVE-2007-4559 fix), but we do *not* rely on it because (a) it did not exist in earlier patch releases, and (b) our validation is more restrictive.

---

### T2 — Zip bomb (`safe_extract.py`)

**Attack**: a tiny compressed tarball expands to gigabytes on disk, exhausting storage and potentially causing an OOM kill or disk-full that cascades to other services.

**Defence** (two layers):

1. **Header-claim check** during validation: if `member.size` (the declared size in the tar header) exceeds `MAX_SINGLE_FILE` (10 MiB) or the running total exceeds `MAX_EXTRACTED_SIZE` (100 MiB), extraction is aborted before any bytes are written to disk.

2. **Streaming byte count** during extraction: headers can lie. `_extract_members()` reads each file in 64 KiB chunks and tracks actual bytes written. If the running total exceeds `MAX_EXTRACTED_SIZE`, the partial file is deleted and `ExtractionError` is raised immediately.

---

### T3 — Symlink / hard-link escape (`safe_extract.py`)

**Attack**: a package contains `link -> ../../../../etc/passwd`. After extraction, any code that opens `link` dereferences through to the host path.

**Defence**: symlinks (`SYMTYPE`) and hard links (`LNKTYPE`) are rejected unconditionally during the member type check in `_validate_all()`. npm packages have no legitimate need for either.

```python
if member.issym() or member.islnk():
    raise ExtractionError(f"Archive contains a symlink/hardlink: {member.name!r}")
```

---

### T4 — Special file injection (`safe_extract.py`)

**Attack**: block devices (`/dev/sda`), character devices, FIFOs, or Unix sockets in the archive. On extraction these create real device nodes on the host (requires root, but defence-in-depth applies).

**Defence**: `_SAFE_TYPES` is an explicit allowlist of `REGTYPE`, `AREGTYPE`, and `DIRTYPE`. Any member with a type outside this set raises `ExtractionError`.

---

### T5 — File count and depth exhaustion (`safe_extract.py`)

**Attack**: a package with 100,000 tiny files forces the scanner to open and process each one, consuming CPU and inode quota. A deeply nested directory tree (1000 levels) can overflow path buffers or scanner recursion limits.

**Defence**:
- `MAX_FILE_COUNT = 10_000`: the archive is rejected if `len(members)` exceeds this before any extraction.
- `MAX_NESTING_DEPTH = 10`: each member's path depth is counted with `_path_depth()` (number of `PurePosixPath` parts). Members exceeding the limit are rejected.

---

### T6 — Billion-laughs / deeply nested JSON (`json_safe.py`)

**Attack**: a `package.json` like `{"a": {"a": {"a": ...}}}` with thousands of levels. Python's C-level `json.loads` is iterative (not recursive) so this does not stack-overflow, but deeply nested structures consume memory and can cause O(n²) behaviour in dict-walking code elsewhere in the scanner.

**Defence**: `check_json_depth()` walks the parsed tree and raises `JSONSafeError` if any path exceeds `max_depth` (default 20). The check is iterative (not recursive) to avoid stack issues in the checker itself.

---

### T7 — Key flood (`json_safe.py`)

**Attack**: a `package.json` with `{"k0": 1, "k1": 1, ..., "k999999": 1}` forces a 1 000 000-entry dict allocation.

**Defence** (two layers):
1. **File size gate**: `safe_json_load()` calls `stat()` before reading. Files over `max_size_bytes` (default 5 MiB) are rejected without reading any content — the cheapest possible check.
2. **Key count**: `count_json_keys()` iteratively counts all keys across the entire parsed tree. If the total exceeds `max_keys` (default 10,000) a `JSONSafeError` is raised.

---

### T8 — ReDoS (`safe_regex.py`)

**Attack**: a source file line crafted to trigger exponential backtracking in a secret-detection regex. For example, a pattern like `(a+)+b` on input `"aaa...ac"` causes the engine to explore 2^n paths. The scanner hangs indefinitely, achieving CPU DoS.

**Defence** (two layers):

1. **Pattern hardening**: every pattern in `SafeRegex` is annotated with its worst-case complexity and authored to avoid overlapping alternation, unbounded nested quantifiers, or ambiguous prefixes. See the module docstring for per-pattern analysis.

2. **Per-match timeout**: `SafeRegex.search_line()` wraps every match attempt in `regex_timeout()`. On POSIX main thread: `signal.SIGALRM` (precise, zero overhead). On Windows or non-main thread: `ctypes.pythonapi.PyThreadState_SetAsyncExc` injects a `RegexTimeout` exception into the running thread. If the timeout fires, the method returns `None` (miss the finding) rather than hanging. A warning is logged so operators know something was skipped.

The accepted risk here is that a ReDoS attempt also silently skips the finding it was covering. This is the correct trade-off: DoS prevention takes priority over completeness on a single crafted line.

---

### T9 & T10 — SSRF (`ssrf_guard.py`)

**Attack (T9)**: a malicious package's registry metadata contains `"dist": {"tarball": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}`. The scanner fetches this URL, and the attacker reads the AWS instance credentials from the HTTP response (in CI/CD environments this is catastrophic).

**Attack (T10)**: the initial tarball URL is legitimate, but the server returns a `301 Redirect` to `http://10.0.0.1/internal-service`. The scanner follows the redirect and hits an internal service.

**Defence**:

`SSRFGuard.validate_url()` enforces:
- **Scheme allowlist**: only `http` and `https`.
- **No embedded credentials**: `user:pass@host` is rejected.
- **Port policy**: ports < 1024 are blocked except 80 and 443 (which are the only ports registries legitimately use).
- **IP check**: if the hostname is a raw IP literal, it is checked directly against `BLOCKED_RANGES`. If it is a hostname, all DNS-resolved addresses are checked — including cases where DNS returns a mix of public and private addresses (DNS rebinding).

`SSRFGuard.safe_httpx_event_hook()` registers a `request` event hook on the `httpx.AsyncClient`. This hook fires on the initial request *and on every redirect*, so T10 is closed automatically.

The full list of blocked networks is in `ssrf_guard.BLOCKED_RANGES` and covers all RFC 1918 ranges, loopback, link-local (including AWS/GCP/Azure IMDS endpoints), documentation ranges, and IPv6 private/loopback addresses.

---

## What is NOT protected against (accepted risk / out of scope)

| Gap | Rationale |
|-----|-----------|
| **CPU quota for rule analysis** | Individual rules iterate over source lines. A package with 500 files × 50,000 lines each could be slow. Mitigation: `ScanTarget.source_files` is capped at 500 files and 5 MiB each (enforced in the scanner, not in this module). |
| **Signal-based timeout on non-main threads** | `SIGALRM` only fires on the main thread. Worker threads use the `ctypes` injection fallback, which is CPython-specific and best-effort. A true fix would require switching to a subprocess-based regex engine (e.g. Google's `re2` via `google-re2`). |
| **DNS rebinding at request time** | `SSRFGuard` validates the IP at request-build time. A fast DNS TTL could rebind between validation and the actual TCP connect. Mitigation: most httpx transports connect immediately after resolution, making the window tiny. A hardened production deployment should use a DNS resolver that does not honour sub-second TTLs. |
| **Malicious `__import__` or `eval` in scanned source** | mcpguard reads source files as text — it never `exec`s or `import`s them. This is safe by design. |
| **Tarball delivery over HTTP (not HTTPS)** | `SSRFGuard` allows `http://` for compatibility with private registries. Production deployments should set `registry = "https://..."` and enforce TLS. |
| **Archive formats other than .tgz** | npm packages are always `.tgz`. Zip files and other formats are not extracted. If support for `.zip` is added in future, `SafeExtractor` must be extended. |
| **Windows NTFS stream attacks** (`file:stream`) | mcpguard is primarily tested on POSIX. Windows alternate data streams in tarball names are rejected by the path-traversal check because the resolved path will not contain the stream suffix. |

---

## Limits reference

| Constant | Default | Where enforced |
|----------|---------|----------------|
| `SafeExtractor.MAX_EXTRACTED_SIZE` | 100 MiB | `safe_extract.py` |
| `SafeExtractor.MAX_FILE_COUNT` | 10,000 | `safe_extract.py` |
| `SafeExtractor.MAX_SINGLE_FILE` | 10 MiB | `safe_extract.py` |
| `SafeExtractor.MAX_NESTING_DEPTH` | 10 | `safe_extract.py` |
| `safe_json_load` `max_size_bytes` | 5 MiB | `json_safe.py` |
| `safe_json_load` `max_depth` | 20 | `json_safe.py` |
| `safe_json_load` `max_keys` | 10,000 | `json_safe.py` |
| `SafeRegex.search_line` `timeout_secs` | 2 s | `safe_regex.py` |
| Source files per scan | 500 | `scanner.py` (pre-existing) |
| Source file size | 5 MiB | `scanner.py` (pre-existing) |

---

## Reporting a vulnerability in mcpguard

If you discover a security issue in mcpguard itself — including any bypass of the controls described in this document — please **do not open a public GitHub issue**.

**Responsible disclosure process**:

1. Email `security@mcpguard.dev` (or open a [GitHub Security Advisory](https://github.com/yourusername/mcpguard/security/advisories/new) as a draft).
2. Include a minimal reproduction: a crafted `.tgz` or `package.json` that demonstrates the issue, plus the mcpguard version and OS.
3. You will receive an acknowledgement within **48 hours** and a patch timeline within **7 days**.
4. We follow a **90-day coordinated disclosure** window. We will credit you in the release notes unless you prefer to remain anonymous.

**Scope**: issues in `safe_extract.py`, `safe_regex.py`, `ssrf_guard.py`, `json_safe.py`, and the fetcher's SSRF surface are highest priority. Findings in scan rules (false positives / false negatives) are bugs, not vulnerabilities — open a regular issue for those.

---

## Developer checklist

When adding code that processes package contents:

- [ ] Never call `subprocess` with data derived from package files or metadata. If you must shell out, use a fixed command with arguments passed as a list (never interpolated into a shell string).
- [ ] Never `eval()`, `exec()`, or `importlib.import_module()` on scanned content.
- [ ] Use `safe_json_load()` instead of `json.loads()` / `json.load()` for any file from the package.
- [ ] Use `SafeRegex.search_line()` instead of bare `pattern.search()` for patterns applied to source file lines.
- [ ] If you add a new HTTP request, wrap the client with `SSRFGuard.safe_httpx_event_hook()`.
- [ ] If you extract any archive, use `SafeExtractor`, not `tarfile.extractall()` directly.
- [ ] Add a test in `tests/test_security.py` for any new security-sensitive path.
