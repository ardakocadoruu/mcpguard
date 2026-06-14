"""Known-bad MCP package vulnerability database.

Loads ``known_bad.json`` from disk and exposes lookup, search, and filtering
helpers used by the scanner rules and CLI commands.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_RESERVED_KEYS = frozenset(["_meta"])


class VulnDB:
    """Known-bad MCP package database.

    Wraps a ``known_bad.json`` file and provides case-insensitive lookup,
    severity filtering, and full-text search across entry names and reasons.

    Example::

        db = VulnDB()
        entry = db.is_known_bad("mcp-filesytem")
        if entry:
            print(entry["severity"], entry["reason"])
    """

    #: Default path to the bundled known_bad.json.
    DEFAULT_DB_PATH: Path = Path(__file__).parent / "known_bad.json"

    def __init__(self, db_path: Path | None = None) -> None:
        """Load the vulnerability database from disk.

        Args:
            db_path: Path to a ``known_bad.json`` file.  Defaults to
                     :attr:`DEFAULT_DB_PATH` (the bundled database).

        Raises:
            FileNotFoundError: If the resolved path does not exist.
            json.JSONDecodeError: If the file is not valid JSON.
        """
        resolved = db_path or self.DEFAULT_DB_PATH
        try:
            raw: dict[str, object] = json.loads(resolved.read_text(encoding="utf-8"))
        except FileNotFoundError:
            logger.warning("VulnDB: database file not found at %s; using empty DB.", resolved)
            raw = {}
        except json.JSONDecodeError as exc:
            logger.error("VulnDB: failed to parse %s: %s; using empty DB.", resolved, exc)
            raw = {}

        # Strip internal metadata key(s) so they don't appear as package entries.
        self._db: dict[str, dict[str, object]] = {
            k: v for k, v in raw.items() if k not in _RESERVED_KEYS and isinstance(v, dict)
        }
        # Build a normalised lookup index: lowercase name → original key.
        self._index: dict[str, str] = {k.lower(): k for k in self._db}

    # ------------------------------------------------------------------
    # Core lookup
    # ------------------------------------------------------------------

    def is_known_bad(self, package_name: str) -> dict[str, object] | None:
        """Check whether *package_name* is in the known-bad list.

        The comparison is **case-insensitive**.  Additionally, if the name
        carries an npm scope prefix (``@scope/name``), the bare name is also
        checked so that ``@evil/mcp-sdk`` hits an entry for ``mcp-sdk``.

        Args:
            package_name: The npm package name to look up.

        Returns:
            The entry dictionary (with keys such as ``reason``, ``severity``,
            ``cve``, etc.) or ``None`` if the package is not listed.
        """
        candidates = self._scope_variants(package_name)
        for candidate in candidates:
            original_key = self._index.get(candidate)
            if original_key is not None:
                return dict(self._db[original_key])
        return None

    # ------------------------------------------------------------------
    # Bulk accessors
    # ------------------------------------------------------------------

    def get_all(self) -> dict[str, dict[str, object]]:
        """Return a shallow copy of the full database dictionary.

        Returns:
            Mapping of package name → entry dict for every known-bad package.
        """
        return dict(self._db)

    def count(self) -> int:
        """Return the total number of known-bad package entries.

        Returns:
            Integer count of entries (metadata keys excluded).
        """
        return len(self._db)

    def get_by_severity(self, severity: str) -> dict[str, dict[str, object]]:
        """Return all entries whose severity matches *severity*.

        The comparison is case-insensitive, so ``"critical"`` and
        ``"CRITICAL"`` are equivalent.

        Args:
            severity: One of ``"CRITICAL"``, ``"HIGH"``, or ``"MEDIUM"``.

        Returns:
            Filtered mapping of package name → entry dict.
        """
        target = severity.upper()
        return {
            name: entry
            for name, entry in self._db.items()
            if str(entry.get("severity", "")).upper() == target
        }

    def search(self, query: str) -> dict[str, dict[str, object]]:
        """Full-text search across package names and ``reason`` fields.

        The search is case-insensitive and uses simple substring matching.

        Args:
            query: Search string.

        Returns:
            Matching entries as a mapping of package name → entry dict.
        """
        needle = query.lower()
        results: dict[str, dict[str, object]] = {}
        for name, entry in self._db.items():
            reason = str(entry.get("reason", "")).lower()
            if needle in name.lower() or needle in reason:
                results[name] = entry
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _scope_variants(package_name: str) -> list[str]:
        """Return the set of normalised names to look up for *package_name*.

        For a scoped package such as ``@evil/mcp-sdk`` this yields both
        ``@evil/mcp-sdk`` (exact) and ``mcp-sdk`` (stripped) so that a
        known-bad entry for the bare name also fires.

        Args:
            package_name: Raw package name, possibly with ``@scope/`` prefix.

        Returns:
            List of lowercase candidate strings (1 or 2 elements).
        """
        name = package_name.strip().lower()
        candidates = [name]
        if name.startswith("@") and "/" in name:
            bare = name.split("/", 1)[1]
            candidates.append(bare)
        return candidates
