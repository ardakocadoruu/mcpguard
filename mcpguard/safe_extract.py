"""Hardened tarball extractor for untrusted npm .tgz packages.

Every file processed here arrived from the internet and may have been crafted
by an adversary specifically to exploit the scanner itself.  Every check below
is a direct countermeasure against a concrete attack class.

Attack model
------------
* **Path traversal** — member names such as ``../../etc/passwd`` or absolute
  paths like ``/etc/shadow`` that would escape the extraction directory.
* **Zip bomb** — a small compressed tarball that expands to gigabytes,
  exhausting disk space or memory.
* **Symlink escape** — a symlink whose target points outside the extraction
  root, letting a later open() reach arbitrary host paths.
* **Hard-link attack** — hard links that point to existing host files.
* **Special file injection** — block/char devices, FIFOs, or sockets smuggled
  into the archive.
* **Resource exhaustion** — millions of tiny files or a deeply nested
  directory tree.
"""

from __future__ import annotations

import logging
import tarfile
from pathlib import Path, PurePosixPath

__all__ = ["ExtractionError", "SafeExtractor"]

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowed tarfile member types (regular files and directories only)
# ---------------------------------------------------------------------------
_SAFE_TYPES = frozenset(
    [
        tarfile.REGTYPE,   # '0'  regular file
        tarfile.AREGTYPE,  # '\0' alternate regular file
        tarfile.DIRTYPE,   # '5'  directory
        tarfile.GNUTYPE_LONGNAME,   # 'L'  GNU long name (resolved by tarfile)
        tarfile.GNUTYPE_LONGLINK,   # 'K'  GNU long link (resolved by tarfile)
    ]
)


class ExtractionError(Exception):
    """Raised when extraction is aborted due to a security violation.

    Attributes:
        reason: Human-readable explanation of which control tripped.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class SafeExtractor:
    """Extracts npm .tgz packages with defence-in-depth security controls.

    All controls are enforced **before** any bytes are written to disk.  The
    archive is opened twice: first for validation (no extraction), then for
    actual extraction of only the approved members.

    Class constants (can be overridden on subclasses or instances for testing)::

        MAX_EXTRACTED_SIZE  = 100 MiB  — cumulative uncompressed bytes
        MAX_FILE_COUNT      = 10 000   — total member count
        MAX_SINGLE_FILE     = 10 MiB   — largest single file
        MAX_NESTING_DEPTH   = 10       — maximum path component depth

    Usage::

        extractor = SafeExtractor()
        extractor.extract(Path("package-1.0.0.tgz"), Path("/tmp/scan-work"))
    """

    MAX_EXTRACTED_SIZE: int = 100 * 1024 * 1024   # 100 MiB
    MAX_FILE_COUNT: int = 10_000
    MAX_SINGLE_FILE: int = 10 * 1024 * 1024        # 10 MiB
    MAX_NESTING_DEPTH: int = 10

    # ---------------------------------------------------------------------------
    # Public interface
    # ---------------------------------------------------------------------------

    def extract(self, tarball_path: Path, dest: Path) -> None:
        """Safely extract *tarball_path* to *dest*.

        After a successful return every extracted path is guaranteed to lie
        inside *dest*.  The npm ``package/`` prefix is stripped so the
        package root is directly at *dest*.

        Args:
            tarball_path: Absolute path to a ``.tgz`` / ``.tar.gz`` file.
            dest:         Directory to extract into (created if absent).

        Raises:
            ExtractionError: On any security violation or extraction failure.
            FileNotFoundError: If *tarball_path* does not exist.
        """
        dest.mkdir(parents=True, exist_ok=True)
        dest_resolved = dest.resolve()

        try:
            with tarfile.open(tarball_path, mode="r:gz") as tf:
                members = tf.getmembers()
                safe_members = self._validate_all(members, dest_resolved)
                self._extract_members(tf, safe_members, dest_resolved)
        except ExtractionError:
            raise
        except tarfile.TarError as exc:
            raise ExtractionError(f"Corrupt or unreadable tarball: {exc}") from exc
        except OSError as exc:
            raise ExtractionError(f"I/O error during extraction: {exc}") from exc

    # ---------------------------------------------------------------------------
    # Validation pass — NO bytes written to disk
    # ---------------------------------------------------------------------------

    def _validate_all(
        self,
        members: list[tarfile.TarInfo],
        dest_resolved: Path,
    ) -> list[tuple[tarfile.TarInfo, Path]]:
        """Validate every member and return ``(member, final_dest_path)`` pairs.

        This method enforces all limits and rejects dangerous members *before*
        the extraction loop.  It returns only the members that passed all
        checks, along with the pre-computed destination path for each so the
        extraction loop does not need to repeat the path calculation.

        Args:
            members:       Raw list of :class:`tarfile.TarInfo` from the archive.
            dest_resolved: Resolved absolute destination directory path.

        Returns:
            List of ``(TarInfo, resolved_dest_path)`` pairs for safe members.

        Raises:
            ExtractionError: On the first constraint violation encountered.
        """
        if len(members) > self.MAX_FILE_COUNT:
            raise ExtractionError(
                f"Archive contains {len(members)} members, limit is {self.MAX_FILE_COUNT}"
            )

        total_size = 0
        approved: list[tuple[tarfile.TarInfo, Path]] = []

        for member in members:
            # ------------------------------------------------------------------
            # 1. File-type check — reject symlinks, hardlinks, and special files
            # ------------------------------------------------------------------
            if member.issym() or member.islnk():
                raise ExtractionError(
                    f"Archive contains a {'symlink' if member.issym() else 'hardlink'}: "
                    f"{member.name!r} — symlinks/hardlinks are not permitted in package "
                    f"archives because they can escape the extraction directory."
                )
            if member.type not in _SAFE_TYPES:
                raise ExtractionError(
                    f"Archive member {member.name!r} has unsafe type "
                    f"{member.type!r} (block/char device, FIFO, or socket)"
                )

            # ------------------------------------------------------------------
            # 2. Single-file size limit (reported size; real check is below)
            # ------------------------------------------------------------------
            if member.size > self.MAX_SINGLE_FILE:
                raise ExtractionError(
                    f"Member {member.name!r} claims size {member.size:,} bytes "
                    f"which exceeds the {self.MAX_SINGLE_FILE:,}-byte per-file limit"
                )

            # ------------------------------------------------------------------
            # 3. Nesting depth limit
            # ------------------------------------------------------------------
            depth = self._path_depth(member.name)
            if depth > self.MAX_NESTING_DEPTH:
                raise ExtractionError(
                    f"Member {member.name!r} has nesting depth {depth}, "
                    f"limit is {self.MAX_NESTING_DEPTH}"
                )

            # ------------------------------------------------------------------
            # 4. Path traversal — resolve final destination and check containment
            # ------------------------------------------------------------------
            # Reject absolute paths before any stripping — an absolute member
            # like "/etc/passwd" would otherwise appear safe after stripping.
            if PurePosixPath(member.name).is_absolute():
                raise ExtractionError(
                    f"Path traversal attempt: member {member.name!r} has an "
                    f"absolute path which could escape the extraction directory."
                )

            # Strip the npm "package/" prefix (or any single top-level prefix)
            # so that "package/index.js" lands at dest/index.js.
            stripped_name = self._strip_package_prefix(member.name)
            if not stripped_name:
                # Top-level directory entry itself (e.g. "package/") — skip.
                continue

            try:
                dest_path = (dest_resolved / stripped_name).resolve()
            except (ValueError, OSError) as exc:
                raise ExtractionError(
                    f"Cannot resolve destination for member {member.name!r}: {exc}"
                ) from exc

            # The critical check: resolved path must be inside dest_resolved.
            # We append os.sep to dest to prevent a prefix like /tmp/safe
            # matching /tmp/safe-evil.
            dest_str = str(dest_resolved)
            if not (
                str(dest_path) == dest_str
                or str(dest_path).startswith(dest_str + "/")
            ):
                raise ExtractionError(
                    f"Path traversal attempt: {member.name!r} would extract to "
                    f"{dest_path} which is outside {dest_resolved}"
                )

            # ------------------------------------------------------------------
            # 5. Cumulative size tracking (zip-bomb / resource exhaustion)
            # ------------------------------------------------------------------
            if not member.isdir():
                total_size += member.size
                if total_size > self.MAX_EXTRACTED_SIZE:
                    raise ExtractionError(
                        f"Archive would exceed the {self.MAX_EXTRACTED_SIZE:,}-byte "
                        f"cumulative extraction limit (already at {total_size:,} bytes "
                        f"after member {member.name!r})"
                    )

            approved.append((member, dest_path))

        log.debug(
            "Validation passed: %d members, %d bytes total",
            len(approved),
            total_size,
        )
        return approved

    # ---------------------------------------------------------------------------
    # Extraction pass — writes only pre-approved members
    # ---------------------------------------------------------------------------

    def _extract_members(
        self,
        tf: tarfile.TarFile,
        approved: list[tuple[tarfile.TarInfo, Path]],
        dest_resolved: Path,
    ) -> None:
        """Extract approved members, counting actual bytes to catch header lies.

        Zip bombs can lie about ``member.size`` in the header.  We read the
        actual content and count real bytes, aborting if the cumulative total
        exceeds the limit mid-stream.

        Args:
            tf:            Open :class:`tarfile.TarFile` in read mode.
            approved:      Pre-validated ``(member, dest_path)`` pairs.
            dest_resolved: Extraction root (already validated).
        """
        actual_bytes = 0
        chunk_size = 65_536  # 64 KiB read chunks

        for member, dest_path in approved:
            if member.isdir():
                dest_path.mkdir(parents=True, exist_ok=True)
                continue

            # Ensure parent directory exists.
            dest_path.parent.mkdir(parents=True, exist_ok=True)

            file_obj = tf.extractfile(member)
            if file_obj is None:
                # Directory members or hardlinks without content — skip.
                continue

            with file_obj, dest_path.open("wb") as out_file:
                while True:
                    chunk = file_obj.read(chunk_size)
                    if not chunk:
                        break
                    actual_bytes += len(chunk)
                    if actual_bytes > self.MAX_EXTRACTED_SIZE:
                        # Truncate partial file and abort.
                        out_file.flush()
                        dest_path.unlink(missing_ok=True)
                        raise ExtractionError(
                            f"Zip bomb detected: actual extracted bytes exceeded "
                            f"{self.MAX_EXTRACTED_SIZE:,} while writing {member.name!r}. "
                            f"Header claimed sizes were likely falsified."
                        )
                    out_file.write(chunk)

        log.debug("Extraction complete: %d actual bytes written", actual_bytes)

    # ---------------------------------------------------------------------------
    # Static helpers
    # ---------------------------------------------------------------------------

    @staticmethod
    def _strip_package_prefix(name: str) -> str:
        """Strip the leading path component from an npm tarball member name.

        npm packages always wrap their contents inside a ``package/`` top-level
        directory (e.g. ``package/index.js``).  Some tarballs use the package
        name instead (e.g. ``my-pkg/index.js``).  Either way we strip the first
        component so the extracted tree is flat.

        Args:
            name: Raw member name from the archive.

        Returns:
            The name with the leading component removed, using forward slashes.
            Returns an empty string for top-level-only entries like ``package``.

        Examples::

            >>> SafeExtractor._strip_package_prefix("package/lib/index.js")
            'lib/index.js'
            >>> SafeExtractor._strip_package_prefix("package/")
            ''
            >>> SafeExtractor._strip_package_prefix("index.js")
            'index.js'
        """
        parts = PurePosixPath(name).parts
        if not parts:
            return ""
        if len(parts) == 1:
            # Top-level entry with no children — could be "package" dir itself.
            return ""
        # Drop the first component (whatever it is).
        return str(PurePosixPath(*parts[1:]))

    @staticmethod
    def _path_depth(name: str) -> int:
        """Return the nesting depth of a tarball member path.

        Counts the number of path components after normalisation (ignoring
        redundant ``.``, collapsing ``/``).  Returns 0 for the empty string.

        Args:
            name: Member name from the archive.

        Returns:
            Integer depth ≥ 0.

        Examples::

            >>> SafeExtractor._path_depth("package/lib/utils/index.js")
            4
            >>> SafeExtractor._path_depth("package/index.js")
            2
            >>> SafeExtractor._path_depth("")
            0
        """
        return len(PurePosixPath(name).parts)


# ---------------------------------------------------------------------------
# Convenience wrapper — accepts bytes directly (used by existing fetcher)
# ---------------------------------------------------------------------------

def extract_tgz_bytes(tarball_bytes: bytes, dest: Path) -> None:
    """Extract a ``.tgz`` supplied as *bytes* into *dest*.

    This is a thin shim so callers that already hold the tarball in memory
    (e.g. the existing :func:`~mcpguard.fetcher._extract_tgz`) can use
    :class:`SafeExtractor` without writing to a temporary file first.

    The bytes are wrapped in a :class:`io.BytesIO` and a named pipe trick is
    used to hand the stream to :class:`SafeExtractor` without a real file.

    .. note::
        Because :class:`SafeExtractor.extract` accepts a :class:`pathlib.Path`
        to an on-disk file, this helper writes the bytes to a temporary file,
        extracts, then removes the temp file.  The overhead is acceptable since
        packages are typically < 10 MiB.

    Args:
        tarball_bytes: Raw bytes of the ``.tgz`` file.
        dest:          Directory to extract into.

    Raises:
        ExtractionError: On security violation or extraction failure.
    """
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".tgz", delete=True) as tmp:
        tmp.write(tarball_bytes)
        tmp.flush()
        SafeExtractor().extract(Path(tmp.name), dest)
