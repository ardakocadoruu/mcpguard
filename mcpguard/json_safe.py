"""Safe JSON parsing with size, depth, and key-count limits.

A malicious ``package.json`` can be weaponised against the scanner in two ways:

1. **Billion-laughs / deeply nested JSON** — a structure like
   ``{"a": {"a": {"a": ...}}}`` with thousands of levels causes Python's
   recursive JSON decoder to blow the call stack, or a specially crafted
   repeated-reference structure causes O(n²) memory expansion during parsing.

2. **Key flooding** — a ``package.json`` with millions of top-level keys
   forces the scanner to allocate a huge dict, potentially exhausting memory.

Defence strategy
----------------
* **Pre-parse size gate** — reject the file before parsing if it exceeds
  ``max_size_bytes`` (default 5 MiB).  This is the cheapest check.
* **Depth check** — after parsing, walk the resulting object tree and raise
  if nesting exceeds ``max_depth`` (default 20 levels).
* **Key count check** — count all keys across all dicts in the tree; raise if
  the total exceeds ``max_keys`` (default 10 000).

Why we check *after* parsing
------------------------------
Python's ``json`` module is implemented in C and is not vulnerable to stack
overflow from nested JSON (it uses an iterative parser since Python 3.8).
The depth and key checks are therefore post-parse, which is fine — the size
gate ensures we never hand more than 5 MiB to the parser.

If Python ever regresses to a recursive parser, switching to a streaming
parser (e.g. ``ijson``) would be the correct fix; that change can be made
without altering this module's public API.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

__all__ = [
    "JSONSafeError",
    "safe_json_load",
    "safe_json_loads",
    "check_json_depth",
    "count_json_keys",
]

log = logging.getLogger(__name__)

#: Default limits — override via function parameters, not by mutating these.
_DEFAULT_MAX_SIZE: int = 5 * 1024 * 1024   # 5 MiB
_DEFAULT_MAX_DEPTH: int = 20
_DEFAULT_MAX_KEYS: int = 10_000


class JSONSafeError(Exception):
    """Raised when a JSON file violates a safety constraint.

    Attributes:
        path:   File that triggered the error (may be ``None`` for in-memory
                parsing via :func:`safe_json_loads`).
        reason: Human-readable explanation of which limit was exceeded.
    """

    def __init__(self, reason: str, path: Path | None = None) -> None:
        self.reason = reason
        self.path = path
        loc = f" ({path})" if path else ""
        super().__init__(f"Unsafe JSON{loc}: {reason}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def safe_json_load(
    path: Path,
    *,
    max_size_bytes: int = _DEFAULT_MAX_SIZE,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_keys: int = _DEFAULT_MAX_KEYS,
) -> Any:
    """Load and validate a JSON file from *path*.

    All three safety checks are applied: size, depth, and key count.

    Args:
        path:           Absolute or relative path to a ``.json`` file.
        max_size_bytes: Reject files larger than this many bytes before parsing.
                        Defaults to 5 MiB.
        max_depth:      Maximum nesting depth of the parsed structure.
                        Defaults to 20.
        max_keys:       Maximum total number of dict keys across the entire
                        structure.  Defaults to 10 000.

    Returns:
        The parsed JSON value (usually a :class:`dict` or :class:`list`).

    Raises:
        JSONSafeError:   If any safety limit is exceeded.
        OSError:         If the file cannot be read.
        json.JSONDecodeError: If the file is not valid JSON.

    Example::

        manifest = safe_json_load(package_dir / "package.json")
    """
    # 1. Size gate — stat() before open() to avoid reading data we'll reject.
    try:
        file_size = path.stat().st_size
    except OSError as exc:
        raise OSError(f"Cannot stat {path}: {exc}") from exc

    if file_size > max_size_bytes:
        raise JSONSafeError(
            f"File size {file_size:,} bytes exceeds limit of {max_size_bytes:,} bytes",
            path=path,
        )

    raw = path.read_bytes()

    return safe_json_loads(
        raw.decode("utf-8", errors="replace"),
        max_size_bytes=max_size_bytes,
        max_depth=max_depth,
        max_keys=max_keys,
        _path=path,
    )


def safe_json_loads(
    text: str,
    *,
    max_size_bytes: int = _DEFAULT_MAX_SIZE,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_keys: int = _DEFAULT_MAX_KEYS,
    _path: Path | None = None,
) -> Any:
    """Parse a JSON *string* with safety limits.

    Useful when the JSON is already in memory (e.g. from a registry API
    response) and you want the same depth/key-count protections without a
    file-size check.  The ``max_size_bytes`` limit is still applied against the
    byte length of *text*.

    Args:
        text:           JSON text to parse.
        max_size_bytes: Reject inputs whose UTF-8 encoding exceeds this size.
        max_depth:      Maximum nesting depth.
        max_keys:       Maximum total key count.
        _path:          Optional path for error messages (internal use).

    Returns:
        Parsed JSON value.

    Raises:
        JSONSafeError:       If any safety limit is exceeded.
        json.JSONDecodeError: If *text* is not valid JSON.
    """
    encoded_len = len(text.encode("utf-8"))
    if encoded_len > max_size_bytes:
        raise JSONSafeError(
            f"JSON string {encoded_len:,} bytes exceeds limit of {max_size_bytes:,} bytes",
            path=_path,
        )

    obj = json.loads(text)

    # 2. Depth check.
    actual_depth = check_json_depth(obj, max_depth=max_depth)
    log.debug("JSON depth: %d (limit %d)", actual_depth, max_depth)

    # 3. Key count check.
    actual_keys = count_json_keys(obj)
    if actual_keys > max_keys:
        raise JSONSafeError(
            f"JSON contains {actual_keys:,} total keys, limit is {max_keys:,}",
            path=_path,
        )
    log.debug("JSON key count: %d (limit %d)", actual_keys, max_keys)

    return obj


# ---------------------------------------------------------------------------
# Helper: depth checker
# ---------------------------------------------------------------------------

def check_json_depth(
    obj: Any,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    current: int = 0,
) -> int:
    """Recursively verify *obj* does not exceed *max_depth* nesting levels.

    The function walks the entire parsed structure.  It raises immediately on
    the first violation rather than computing the full maximum — this keeps
    adversarially deep structures from consuming excessive CPU.

    Args:
        obj:       Any Python value produced by :func:`json.loads`.
        max_depth: Hard limit on nesting depth.
        current:   Current recursion depth (callers should leave this at 0).

    Returns:
        The actual maximum depth found in the subtree rooted at *obj*.

    Raises:
        JSONSafeError: If the nesting level exceeds *max_depth*.

    Example::

        check_json_depth({"a": {"b": {"c": 1}}}, max_depth=5)   # → 3
        check_json_depth({"a": {"b": {"c": 1}}}, max_depth=2)   # → raises
    """
    if current > max_depth:
        raise JSONSafeError(
            f"JSON nesting depth exceeds limit of {max_depth} levels"
        )

    if isinstance(obj, dict):
        if not obj:
            return current
        child_depth = current + 1
        max_child = current
        for value in obj.values():
            d = check_json_depth(value, max_depth=max_depth, current=child_depth)
            if d > max_child:
                max_child = d
        return max_child

    if isinstance(obj, list):
        if not obj:
            return current
        child_depth = current + 1
        max_child = current
        for item in obj:
            d = check_json_depth(item, max_depth=max_depth, current=child_depth)
            if d > max_child:
                max_child = d
        return max_child

    # Scalar value — depth is just the current level.
    return current


# ---------------------------------------------------------------------------
# Helper: key counter
# ---------------------------------------------------------------------------

def count_json_keys(obj: Any) -> int:
    """Count the total number of dict keys across the entire *obj* tree.

    This is an iterative (stack-based) traversal to avoid Python's recursion
    limit on deeply nested structures.

    Args:
        obj: Any Python value produced by :func:`json.loads`.

    Returns:
        Total number of dict keys found at all levels of nesting.

    Example::

        count_json_keys({"a": 1, "b": {"c": 2}})   # → 3
        count_json_keys([{"x": 1}, {"y": 2}])       # → 2
        count_json_keys("string")                    # → 0
    """
    total = 0
    stack: list[Any] = [obj]

    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            total += len(node)
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        # Scalars contribute no keys.

    return total
