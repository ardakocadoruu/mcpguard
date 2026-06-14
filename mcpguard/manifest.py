"""Manifest parser for npm-based MCP packages.

Reads and normalises ``package.json``, resolves entry points, and
enumerates source files for static analysis.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

__all__ = ["ManifestError", "ManifestParser"]

log = logging.getLogger(__name__)

#: Source-file extensions considered for analysis.
DEFAULT_EXTENSIONS: tuple[str, ...] = (".js", ".mjs", ".cjs", ".ts")

#: Directories always excluded when walking source trees.
_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".git",
        ".hg",
        ".svn",
        "dist",
        "build",
        "coverage",
        "__pycache__",
        ".nyc_output",
    }
)


class ManifestError(Exception):
    """Raised when a package manifest cannot be read or is malformed.

    Attributes:
        package_dir: Directory that was searched for a manifest.
        reason:      Human-readable explanation.
    """

    def __init__(self, package_dir: Path, reason: str) -> None:
        self.package_dir = package_dir
        self.reason = reason
        super().__init__(f"Manifest error in '{package_dir}': {reason}")


class ManifestParser:
    """Parses package manifests (``package.json``) for npm MCP packages.

    All methods are synchronous and stateless — instantiate once and call
    freely from multiple coroutines without locking.
    """

    def parse(self, package_dir: Path) -> dict:  # type: ignore[type-arg]
        """Read and normalise the ``package.json`` in *package_dir*.

        The returned dict is a shallow copy of the parsed JSON, augmented
        with a ``"_package_dir"`` key (a :class:`~pathlib.Path`) so that
        downstream code can resolve relative paths without needing to pass
        the directory separately.

        Args:
            package_dir: Root directory of the unpacked package.

        Returns:
            Normalised manifest dictionary.

        Raises:
            :class:`ManifestError`: If ``package.json`` is absent or cannot
                                    be parsed as valid JSON.
        """
        manifest_path = package_dir / "package.json"

        if not manifest_path.exists():
            raise ManifestError(package_dir, "package.json not found")
        if not manifest_path.is_file():
            raise ManifestError(package_dir, "package.json is not a regular file")

        try:
            raw = manifest_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ManifestError(package_dir, f"Cannot read package.json: {exc}") from exc

        try:
            data: dict = json.loads(raw)  # type: ignore[type-arg]
        except json.JSONDecodeError as exc:
            raise ManifestError(package_dir, f"Invalid JSON in package.json: {exc}") from exc

        if not isinstance(data, dict):
            raise ManifestError(package_dir, "package.json root must be a JSON object")

        # Inject resolved directory for downstream helpers.
        data["_package_dir"] = package_dir
        return data

    def get_entry_points(self, manifest: dict) -> list[Path]:  # type: ignore[type-arg]
        """Resolve JS entry-point paths declared in *manifest*.

        Inspects the following fields (in order):

        * ``main``    — primary entry-point string
        * ``bin``     — either a single path string or a ``{name: path}`` dict
        * ``exports`` — string shorthand only (object exports are skipped)

        Only paths that exist on disk and are regular files are included.
        Paths are resolved relative to the ``"_package_dir"`` stored in the
        manifest by :meth:`parse`.

        Args:
            manifest: Normalised manifest as returned by :meth:`parse`.

        Returns:
            Deduplicated list of existing entry-point :class:`~pathlib.Path`
            objects.  Empty list if none are found.
        """
        package_dir: Path | None = manifest.get("_package_dir")

        candidates: list[str] = []

        main = manifest.get("main")
        if isinstance(main, str) and main:
            candidates.append(main)

        bin_field = manifest.get("bin")
        if isinstance(bin_field, str) and bin_field:
            candidates.append(bin_field)
        elif isinstance(bin_field, dict):
            for v in bin_field.values():
                if isinstance(v, str) and v:
                    candidates.append(v)

        exports = manifest.get("exports")
        if isinstance(exports, str) and exports:
            candidates.append(exports)

        if package_dir is None:
            log.warning("manifest missing '_package_dir'; cannot resolve entry points")
            return []

        seen: set[Path] = set()
        result: list[Path] = []
        for rel in candidates:
            # Normalise: strip leading "./" so Path joining works cleanly.
            clean = rel.lstrip("./") if rel.startswith("./") else rel.lstrip("/")
            resolved = (package_dir / clean).resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            if resolved.is_file():
                result.append(resolved)
            else:
                log.debug("Entry point not found on disk, skipping: %s", resolved)

        return result

    def get_source_files(
        self,
        package_dir: Path,
        extensions: tuple[str, ...] = DEFAULT_EXTENSIONS,
    ) -> list[Path]:
        """Recursively list source files under *package_dir*.

        Walk rules:

        * Directories in :data:`_EXCLUDED_DIRS` (e.g. ``node_modules``,
          ``dist``, ``build``) are never descended into.
        * Symbolic links are **never** followed — at both directory and file
          level.
        * Only files whose suffix (case-insensitive) matches *extensions* are
          returned.

        Args:
            package_dir: Root of the package to walk.
            extensions:  Tuple of file extensions to include (with leading
                         dot, e.g. ``".js"``).

        Returns:
            Unsorted list of :class:`~pathlib.Path` objects for every
            matching source file found.
        """
        lower_exts = {ext.lower() for ext in extensions}
        results: list[Path] = []
        stack: list[Path] = [package_dir]

        while stack:
            current_dir = stack.pop()

            try:
                children = list(current_dir.iterdir())
            except OSError as exc:
                log.warning("Cannot list directory %s: %s", current_dir, exc)
                continue

            for child in children:
                # Never follow symlinks.
                if child.is_symlink():
                    log.debug("Skipping symlink: %s", child)
                    continue

                if child.is_dir():
                    if child.name in _EXCLUDED_DIRS:
                        log.debug("Skipping excluded directory: %s", child)
                        continue
                    stack.append(child)
                elif child.is_file():
                    if child.suffix.lower() in lower_exts:
                        results.append(child)

        return results
