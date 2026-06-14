"""Typosquatting detection for MCP packages.

Uses Levenshtein edit distance to identify package names that closely resemble
known-legitimate MCP packages, and applies heuristic pattern checks for common
naming tricks used by malicious packages (brand-name abuse, vanity suffixes,
etc.).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Canonical list of known-legitimate MCP packages that are high-value targets.
# Keep this list in sync with the typosquat targets in supply_chain.py.
# ---------------------------------------------------------------------------
KNOWN_LEGITIMATE_PACKAGES: list[str] = [
    "mcp-filesystem",
    "mcp-server-sqlite",
    "mcp-server-github",
    "mcp-server-postgres",
    "mcp-server-brave-search",
    "mcp-server-google-maps",
    "mcp-server-memory",
    "mcp-server-puppeteer",
    "mcp-server-slack",
    "mcp-server-filesystem",
    "mcp-server-fetch",
    "mcp-server-sequential-thinking",
    "mcp-server-aws",
    "mcp-server-azure",
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-google-maps",
    "@anthropic/claude-code",
]

# ---------------------------------------------------------------------------
# Patterns that are inherently suspicious regardless of edit distance.
# ---------------------------------------------------------------------------

#: Suffixes appended to legitimate names to create fake "premium" variants.
_VANITY_SUFFIXES: re.Pattern[str] = re.compile(
    r"[-_](pro|plus|premium|enterprise|official|free|cracked|lite|max|ultra)$",
    re.IGNORECASE,
)

#: Brand names whose presence in an unknown package name warrants a warning.
_BRAND_NAMES: re.Pattern[str] = re.compile(
    r"\b(claude|anthropic|openai|cursor|copilot|chatgpt|gemini|mistral|cohere)\b",
    re.IGNORECASE,
)

#: Packages that start with "mcp-" but are not in the known-legitimate list
#  are worth flagging as potentially novel/unknown.
_MCP_PREFIX: re.Pattern[str] = re.compile(r"^mcp-", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Levenshtein distance
# ---------------------------------------------------------------------------


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings.

    Uses the standard dynamic-programming algorithm with O(min(|s1|, |s2|))
    space.  Runs in O(|s1| * |s2|) time.

    Args:
        s1: First string.
        s2: Second string.

    Returns:
        Non-negative integer edit distance.

    Examples::

        levenshtein_distance("kitten", "sitting")  # 3
        levenshtein_distance("mcp-filesytem", "mcp-filesystem")  # 1
    """
    # Ensure s1 is the longer string to minimise memory for the rolling row.
    if len(s1) < len(s2):
        s1, s2 = s2, s1

    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))

    for i, char_s1 in enumerate(s1, start=1):
        curr_row = [i]
        for j, char_s2 in enumerate(s2, start=1):
            insertions = prev_row[j] + 1
            deletions = curr_row[j - 1] + 1
            substitutions = prev_row[j - 1] + (char_s1 != char_s2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


# ---------------------------------------------------------------------------
# Typosquat detector
# ---------------------------------------------------------------------------


def is_typosquat(
    package_name: str,
    threshold: int = 2,
    known_packages: list[str] | None = None,
) -> tuple[bool, str | None, int]:
    """Determine whether *package_name* is a likely typosquat.

    Strips npm scope prefixes before comparison so that ``@evil/mcp-sdk`` is
    compared against ``mcp-sdk``.  An exact match (distance == 0) is never
    flagged because the package *is* the legitimate one.

    Args:
        package_name: The npm package name to evaluate.
        threshold:    Maximum edit distance to consider a potential typosquat.
                      Default is 2 (catches single-character substitutions,
                      transpositions, and most common misspellings).
        known_packages: Override the built-in :data:`KNOWN_LEGITIMATE_PACKAGES`
                        list.  Useful in tests.

    Returns:
        A 3-tuple ``(is_typosquat, closest_match, distance)`` where:

        - ``is_typosquat`` is ``True`` when a close-enough legitimate package
          was found and the name is not an exact match.
        - ``closest_match`` is the name of the nearest legitimate package, or
          ``None`` if no candidate was within the threshold.
        - ``distance`` is the edit distance to *closest_match* (0 means the
          provided name *is* that legitimate package).
    """
    reference = known_packages if known_packages is not None else KNOWN_LEGITIMATE_PACKAGES

    # Normalise: strip leading/trailing whitespace; lowercase for comparison.
    normalised = _strip_scope(package_name.strip().lower())

    best_match: str | None = None
    best_dist = threshold + 1  # Sentinel: one above the acceptance threshold.

    for legit in reference:
        legit_norm = _strip_scope(legit.lower())
        dist = levenshtein_distance(normalised, legit_norm)
        if dist < best_dist:
            best_dist = dist
            best_match = legit

    if best_dist == 0:
        # Exact match — this is the legitimate package itself.
        return False, best_match, 0

    if best_dist <= threshold:
        return True, best_match, best_dist

    return False, best_match, best_dist


# ---------------------------------------------------------------------------
# Suspicious name pattern checks
# ---------------------------------------------------------------------------


def check_suspicious_name_patterns(package_name: str) -> list[str]:
    """Identify suspicious naming conventions that warrant manual review.

    This check is independent of edit distance; it catches packages that may
    not closely resemble any known-legitimate name but still exhibit well-known
    attack patterns.

    Checks performed:

    - **Vanity suffixes** — names ending in ``-pro``, ``-plus``, ``-premium``,
      ``-enterprise``, ``-official``, ``-free``, ``-cracked``, etc.
    - **Brand-name abuse** — names containing ``claude``, ``anthropic``,
      ``openai``, ``cursor``, ``copilot``, and similar brand terms.
    - **Unknown mcp- prefix** — names that start with ``mcp-`` but do not
      appear in :data:`KNOWN_LEGITIMATE_PACKAGES`, suggesting a novel or
      unvetted package.

    Args:
        package_name: The npm package name to evaluate.

    Returns:
        A list of human-readable warning strings.  Empty list means the name
        passed all heuristic checks.
    """
    warnings: list[str] = []
    bare = _strip_scope(package_name.strip())

    # 1. Vanity / social-engineering suffix.
    if _VANITY_SUFFIXES.search(bare):
        suffix = _VANITY_SUFFIXES.search(bare)
        assert suffix is not None  # narrowing only; the pattern matched above
        warnings.append(
            f"Suspicious suffix '{suffix.group(0)}' detected — legitimate packages rarely "
            "append marketing terms like '-pro', '-official', or '-enterprise' to their name."
        )

    # 2. Embedded brand name.
    brand_match = _BRAND_NAMES.search(bare)
    if brand_match:
        warnings.append(
            f"Package name contains the brand term '{brand_match.group(0)}'. "
            "Packages using AI vendor or IDE brand names in their npm name are a common "
            "social-engineering vector; verify the publisher is the official vendor."
        )

    # 3. Unknown mcp- prefixed package.
    if _MCP_PREFIX.match(bare):
        known_bare = {_strip_scope(p.lower()) for p in KNOWN_LEGITIMATE_PACKAGES}
        if bare.lower() not in known_bare:
            warnings.append(
                f"'{package_name}' starts with 'mcp-' but is not in the known-legitimate "
                "package list. This may be a legitimate new package or an attempted squat; "
                "verify the author and publication date before installing."
            )

    return warnings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _strip_scope(package_name: str) -> str:
    """Remove the npm scope prefix from *package_name* if present.

    ``@scope/name`` → ``name``.  Names without a scope are returned unchanged.

    Args:
        package_name: Raw package name, possibly with ``@scope/`` prefix.

    Returns:
        The bare package name without the scope prefix.
    """
    if package_name.startswith("@") and "/" in package_name:
        return package_name.split("/", 1)[1]
    return package_name
