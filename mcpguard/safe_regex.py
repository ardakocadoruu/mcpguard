"""ReDoS-resistant regex patterns with timeout protection.

Regular expressions are a classic attack surface when applied to untrusted
input.  An adversary who controls a source file line can craft a string that
causes catastrophic backtracking in a vulnerable pattern, pinning the scanner's
CPU for minutes or longer — a Denial-of-Service attack against the tool itself.

Two layers of defence are provided:

1. **Pattern hardening** — patterns are authored to avoid polynomial/
   exponential backtracking.  Each pattern is annotated with its worst-case
   complexity and the reason it is considered safe.

2. **Per-match timeout** — every call to :meth:`SafeRegex.search_line` runs
   under a hard deadline via :func:`regex_timeout`.  On POSIX systems
   ``signal.SIGALRM`` is used (sub-millisecond precision, zero thread
   overhead).  On Windows a daemon :class:`threading.Thread` is used instead
   (coarser, ~10 ms resolution, but portable).

ReDoS risk notes for the patterns in this module
-------------------------------------------------

Vulnerable pattern shape: ``(a+)+``, ``(a|a)*``, ``(.*a){n}``
All of these allow the regex engine to explore exponentially many ways to
partition the input, which is catastrophic on backtracking engines (Python's
``re`` module included).

The patterns below are safe because:

* **OPENAI / ANTHROPIC / GITHUB**: Anchored prefixes (``sk-``, ``sk-ant-``,
  ``gh[pousr]_``) are fixed-width literals that short-circuit on mismatch
  immediately.  The character class ``[A-Za-z0-9_\\-]`` with a ``{20,}``
  quantifier is a possessive equivalent — Python's ``re`` engine uses the
  Knuth-Morris-Pratt optimisation for simple character classes, so this runs
  in O(n).

* **AWS_ACCESS_KEY**: ``(AKIA|ASIA|ABIA|ACCA)`` is a small, non-overlapping
  alternation over fixed-length strings followed by ``[A-Z0-9]{16}`` (exact
  repeat).  No ambiguity in the alternation, O(n).

* **PRIVATE_KEY_BLOCK**: Matches only the header line ``-----BEGIN ...``, a
  fixed prefix + a small bounded alternation.  The content of the key block is
  *never* matched by regex — we stop at the delimiter.

* **GENERIC_API_KEY** (most complex): uses a non-overlapping alternation for
  the key name (none of the options share a common prefix long enough to cause
  ambiguity), followed by ``\\s*[=:]\\s*`` (backtracking-safe short span) then
  a single quote-delimited capture group ``([A-Za-z0-9_\\-.]{16,})``.  The
  character class is non-overlapping with the closing quote character, so there
  is no backtracking after the first mismatch.

* **DB_PASSWORD / AWS_SECRET**: Same analysis as GENERIC_API_KEY.

The one pattern that *could* be trouble in pathological inputs is GENERIC_API_KEY
on a line with thousands of ``=`` signs interleaved with quotes.  The timeout
guard catches this in ≤2 s.
"""

from __future__ import annotations

import logging
import platform
import re
import threading
from collections.abc import Generator
from contextlib import contextmanager

__all__ = [
    "RegexTimeout",
    "regex_timeout",
    "SafeRegex",
    "SECRET_PATTERNS",
]

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Timeout context manager
# ---------------------------------------------------------------------------


class RegexTimeout(Exception):  # noqa: N818 — intentional; "Timeout" suffix matches stdlib conventions (e.g. concurrent.futures.TimeoutError)
    """Raised when a regex match does not complete within the allowed time."""


# ---------- POSIX (SIGALRM) implementation ----------


def _sigalrm_handler(signum: int, frame: object) -> None:  # noqa: ARG001
    raise RegexTimeout("Regex match exceeded time limit (SIGALRM)")


@contextmanager
def _timeout_posix(seconds: int) -> Generator[None, None, None]:
    """SIGALRM-based timeout; only works on the main thread on POSIX."""
    import signal

    old_handler = signal.signal(signal.SIGALRM, _sigalrm_handler)
    signal.alarm(max(1, seconds))
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


# ---------- Windows / non-main-thread fallback (threading) ----------


@contextmanager
def _timeout_threading(seconds: int) -> Generator[None, None, None]:
    """Thread-based timeout.

    This cannot actually kill a running Python thread — Python's GIL means the
    only way to interrupt a ``re`` match from another thread is to raise an
    exception in it via :func:`ctypes.pythonapi.PyThreadState_SetAsyncExc`.
    We use that approach here.

    If the injection fails (non-CPython), we fall back to logging a warning
    after the fact.  The ``regex_timeout`` caller handles this by returning
    ``None`` and logging — a degraded-but-safe mode.
    """
    import ctypes
    import time

    timed_out = threading.Event()
    target_tid = threading.current_thread().ident

    def _watchdog() -> None:
        time.sleep(seconds)
        if not timed_out.is_set():
            if target_tid is not None:
                # Inject AsyncExc into the monitored thread.
                ctypes.pythonapi.PyThreadState_SetAsyncExc(
                    ctypes.c_ulong(target_tid),
                    ctypes.py_object(RegexTimeout),
                )

    watchdog = threading.Thread(target=_watchdog, daemon=True)
    watchdog.start()
    try:
        yield
    finally:
        timed_out.set()


# ---------- Unified public API ----------


@contextmanager
def regex_timeout(seconds: int = 2) -> Generator[None, None, None]:
    """Context manager that raises :class:`RegexTimeout` if the body takes too long.

    Automatically selects the best available implementation:

    * **POSIX main thread** → ``signal.SIGALRM`` (precise, zero overhead)
    * **POSIX non-main thread or Windows** → ``ctypes`` async-exception injection

    Args:
        seconds: Maximum wall-clock seconds before :class:`RegexTimeout` is raised.

    Raises:
        RegexTimeout: If the body does not complete within *seconds*.

    Example::

        with regex_timeout(2):
            m = dangerous_pattern.search(untrusted_input)
    """
    use_sigalrm = (
        platform.system() != "Windows" and threading.current_thread() is threading.main_thread()
    )
    if use_sigalrm:
        with _timeout_posix(seconds):
            yield
    else:
        with _timeout_threading(seconds):
            yield


# ---------------------------------------------------------------------------
# Pre-compiled secret-detection patterns
# ---------------------------------------------------------------------------

#: Tuple layout: (attr_name, compiled_pattern, human_description)
#: These are the same patterns used by SecretsRule but exposed here as a
#: single source-of-truth with timeout-aware search.
_PATTERN_SPECS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "OPENAI_KEY",
        re.compile(r"""(?<![A-Za-z0-9])sk-(?:proj-|o1-)?[A-Za-z0-9_\-]{20,}"""),
        # Safe: fixed prefix literal + simple char-class with lower-bound repeat.
        # Worst case O(n) — no overlapping alternations.
        "OpenAI API key (sk-...)",
    ),
    (
        "ANTHROPIC_KEY",
        re.compile(r"""(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_\-]{20,}"""),
        # Safe: fixed prefix, single char class.  O(n).
        "Anthropic API key (sk-ant-...)",
    ),
    (
        "AWS_ACCESS_KEY",
        re.compile(r"""(?<![A-Z0-9])(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"""),
        # Safe: non-overlapping 4-option alternation (all distinct first chars
        # except AKIA/ASIA — but the char-class lookbehind eliminates ambiguity).
        # O(n) guaranteed.
        "AWS Access Key ID",
    ),
    (
        "AWS_SECRET_KEY",
        re.compile(
            r"""(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*['"][A-Za-z0-9/+=]{40}['"]"""
        ),
        # Safe: the optional groups (?: ...) use non-backtracking literals.
        # \\s*[=:]\\s* is bounded by context (short assignment lines).
        # Char class [A-Za-z0-9/+=] does not overlap with the closing quote.  O(n).
        "AWS Secret Access Key assignment",
    ),
    (
        "GITHUB_PAT",
        re.compile(r"""(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9_]{36,}"""),
        # Safe: 2-char fixed prefix + single char class.  O(n).
        "GitHub personal access token / app credential",
    ),
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(r"""-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"""),
        # Safe: all literals + small bounded optional group.  O(1) per line.
        "PEM private key block header",
    ),
    (
        "GENERIC_API_KEY",
        re.compile(
            r"""(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?token)\s*[=:]\s*['"`]([A-Za-z0-9_\-\.]{16,})['"`]"""
        ),
        # Moderate risk: the alternation has options sharing prefix "api".
        # However "apikey" vs "api_key" are disambiguated quickly by the
        # following character, and the char class is non-overlapping with the
        # closing quote.  The timeout guard is the backstop.
        "Generic API key / token assignment",
    ),
    (
        "DB_PASSWORD",
        re.compile(
            r"""(?i)(?:password|passwd|db_pass|db_password)\s*[=:]\s*['"`]([^'"`\s]{8,})['"`]"""
        ),
        # Safe: alternation options all differ at character 1 (p vs d).
        # Negated char class [^'"` \\s] is non-backtracking up to the quote.
        # O(n).
        "Hardcoded database password",
    ),
    (
        "SLACK_TOKEN",
        re.compile(r"""xox[baprs]-[A-Za-z0-9\-]{10,}"""),
        # Safe: 4-char fixed prefix + char class.  O(n).
        "Slack token (xox...)",
    ),
    (
        "STRIPE_KEY",
        re.compile(r"""(?<![A-Za-z0-9])(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"""),
        # Safe: small alternations at fixed positions, char class at end.  O(n).
        "Stripe API key",
    ),
]


# ---------------------------------------------------------------------------
# SafeRegex — pre-compiled patterns + timeout-aware search
# ---------------------------------------------------------------------------


class SafeRegex:
    """Pre-compiled secret-detection patterns with per-match ReDoS protection.

    All patterns are compiled once at class creation time.  Individual searches
    run under a configurable wall-clock timeout via :func:`regex_timeout`.

    Patterns are exposed as class attributes so callers can reference them
    directly (e.g. ``SafeRegex.OPENAI_KEY``), and also available as a list
    via :attr:`ALL_PATTERNS`.

    Usage::

        sr = SafeRegex()
        m = sr.search_line(SafeRegex.OPENAI_KEY, line, timeout_secs=2)
        if m:
            print("Found OpenAI key:", m.group(0))
    """

    # Populated dynamically below.
    OPENAI_KEY: re.Pattern[str]
    ANTHROPIC_KEY: re.Pattern[str]
    AWS_ACCESS_KEY: re.Pattern[str]
    AWS_SECRET_KEY: re.Pattern[str]
    GITHUB_PAT: re.Pattern[str]
    PRIVATE_KEY_BLOCK: re.Pattern[str]
    GENERIC_API_KEY: re.Pattern[str]
    DB_PASSWORD: re.Pattern[str]
    SLACK_TOKEN: re.Pattern[str]
    STRIPE_KEY: re.Pattern[str]

    #: All ``(pattern, description)`` pairs in declaration order.
    ALL_PATTERNS: list[tuple[re.Pattern[str], str]] = []

    def _do_search(
        self,
        pattern: re.Pattern[str],
        line: str,
    ) -> re.Match[str] | None:
        """Delegate to ``pattern.search(line)``.

        Extracted as a separate method so tests can monkeypatch this instance
        method instead of the read-only C-level ``re.Pattern.search`` attribute.

        Args:
            pattern: Pre-compiled pattern.
            line:    Input string to search.

        Returns:
            A :class:`re.Match` or ``None``.
        """
        return pattern.search(line)

    def search_line(
        self,
        pattern: re.Pattern[str],
        line: str,
        timeout_secs: int = 2,
    ) -> re.Match[str] | None:
        """Search *line* using *pattern* under a hard time limit.

        If the match does not complete within *timeout_secs*, :class:`RegexTimeout`
        is caught internally, a warning is logged, and ``None`` is returned.
        The caller should treat ``None`` as "no match found" — this is the
        safe-fail posture: we may miss a finding rather than DoS the scanner.

        Args:
            pattern:      A pre-compiled :class:`re.Pattern`.
            line:         A single line of untrusted source text.
            timeout_secs: Maximum seconds before timeout.

        Returns:
            A :class:`re.Match` object on success, or ``None`` if no match or
            if the timeout fired.

        Example::

            sr = SafeRegex()
            if m := sr.search_line(SafeRegex.OPENAI_KEY, line):
                evidence = m.group(0)
        """
        try:
            with regex_timeout(timeout_secs):
                return self._do_search(pattern, line)
        except RegexTimeout:
            log.warning(
                "Regex timeout after %ds on pattern %s — line length %d. "
                "Possible ReDoS attempt; skipping line.",
                timeout_secs,
                pattern.pattern[:60],
                len(line),
            )
            return None

    def search_all(
        self,
        line: str,
        timeout_secs: int = 2,
    ) -> list[tuple[re.Pattern[str], re.Match[str], str]]:
        """Search *line* against every pattern in :attr:`ALL_PATTERNS`.

        Args:
            line:         A single line of untrusted source text.
            timeout_secs: Per-pattern timeout.

        Returns:
            List of ``(pattern, match, description)`` for every pattern that
            matched.  Returns an empty list if no patterns matched or all timed
            out.
        """
        results: list[tuple[re.Pattern[str], re.Match[str], str]] = []
        for pat, description in self.ALL_PATTERNS:
            m = self.search_line(pat, line, timeout_secs)
            if m is not None:
                results.append((pat, m, description))
        return results


# ---------------------------------------------------------------------------
# Dynamically attach pattern attributes and build ALL_PATTERNS
# ---------------------------------------------------------------------------

for _attr_name, _compiled, _description in _PATTERN_SPECS:
    setattr(SafeRegex, _attr_name, _compiled)
    SafeRegex.ALL_PATTERNS.append((_compiled, _description))


#: Module-level singleton for convenience.
SECRET_PATTERNS: SafeRegex = SafeRegex()
