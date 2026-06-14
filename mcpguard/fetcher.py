"""Package fetcher — downloads and unpacks MCP packages.

Supports three source types:

* **npm registry** — ``"package-name"`` or ``"package-name@1.2.3"``
* **Scoped npm** — ``"@scope/package"`` or ``"@scope/package@1.2.3"``
* **Local path** — ``"/absolute/path"`` or ``"./relative/path"``
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from urllib.parse import quote

import httpx

from mcpguard.safe_extract import ExtractionError, extract_tgz_bytes
from mcpguard.ssrf_guard import SSRFError, ssrf_guard

__all__ = ["PackageFetchError", "PackageFetcher"]

log = logging.getLogger(__name__)

#: Default registry base URL.
NPM_REGISTRY = "https://registry.npmjs.org"

#: Network timeout for a single HTTP request (seconds).
_REQUEST_TIMEOUT = 30.0

#: Number of attempts before giving up.
_MAX_RETRIES = 3

#: Initial back-off delay in seconds (doubles each retry).
_BACKOFF_BASE = 1.0


class PackageFetchError(Exception):
    """Raised when a package cannot be fetched or unpacked.

    Attributes:
        package: The original package spec that was requested.
        reason:  Human-readable explanation of the failure.
    """

    def __init__(self, package: str, reason: str) -> None:
        self.package = package
        self.reason = reason
        super().__init__(f"Failed to fetch '{package}': {reason}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _encode_package_name(name: str) -> str:
    """URL-encode a (possibly scoped) npm package name for registry paths.

    Scoped names like ``@scope/pkg`` become ``%40scope%2Fpkg``.
    Unscoped names are returned unchanged.

    Args:
        name: Raw package name.

    Returns:
        URL-safe encoded name.
    """
    if name.startswith("@"):
        return quote(name, safe="")
    return name


def _parse_package_spec(spec: str) -> tuple[str, str]:
    """Split a package spec into *(name, version)*.

    Examples::

        "react"            -> ("react", "latest")
        "react@18.2.0"     -> ("react", "18.2.0")
        "@scope/pkg"       -> ("@scope/pkg", "latest")
        "@scope/pkg@1.0.0" -> ("@scope/pkg", "1.0.0")

    Args:
        spec: Raw package specifier from the user.

    Returns:
        2-tuple of ``(name, version)``.
    """
    if spec.startswith("@"):
        # Scoped: @scope/name  or  @scope/name@version
        # The version separator is the *second* '@'.
        at_idx = spec.find("@", 1)
        if at_idx == -1:
            return spec, "latest"
        return spec[:at_idx], spec[at_idx + 1 :]

    at_idx = spec.find("@")
    if at_idx == -1:
        return spec, "latest"
    return spec[:at_idx], spec[at_idx + 1 :]


def _is_local_path(spec: str) -> bool:
    """Return ``True`` when *spec* is a filesystem path rather than an npm name."""
    return spec.startswith("/") or spec.startswith("./") or spec.startswith("../")


async def _retry_request(
    client: httpx.AsyncClient,
    url: str,
    package: str,
) -> httpx.Response:
    """GET *url* with exponential back-off retry.

    Args:
        client:  Shared :class:`httpx.AsyncClient` to use.
        url:     Target URL.
        package: Original package spec (used in error messages only).

    Returns:
        Successful :class:`httpx.Response` (status 200).

    Raises:
        :class:`PackageFetchError` after all retries are exhausted.
    """
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response
        except httpx.TimeoutException as exc:
            last_exc = exc
            log.warning(
                "Timeout fetching %s (attempt %d/%d)", url, attempt + 1, _MAX_RETRIES
            )
        except httpx.HTTPStatusError as exc:
            # 4xx errors are permanent — never retry.
            if exc.response.status_code < 500:
                raise PackageFetchError(
                    package,
                    f"HTTP {exc.response.status_code} from registry: {url}",
                ) from exc
            last_exc = exc
            log.warning(
                "HTTP %d from %s (attempt %d/%d)",
                exc.response.status_code,
                url,
                attempt + 1,
                _MAX_RETRIES,
            )
        except httpx.RequestError as exc:
            last_exc = exc
            log.warning(
                "Request error for %s (attempt %d/%d): %s",
                url,
                attempt + 1,
                _MAX_RETRIES,
                exc,
            )

        if attempt < _MAX_RETRIES - 1:
            delay = _BACKOFF_BASE * (2**attempt)
            log.debug("Retrying in %.1fs…", delay)
            await asyncio.sleep(delay)

    raise PackageFetchError(
        package, f"All {_MAX_RETRIES} attempts failed: {last_exc}"
    ) from last_exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class PackageFetcher:
    """Downloads and unpacks MCP packages from the npm registry or local path.

    Usage::

        fetcher = PackageFetcher()
        pkg_dir = await fetcher.fetch("@modelcontextprotocol/server-filesystem", dest)
    """

    def __init__(self, registry: str = NPM_REGISTRY) -> None:
        """
        Args:
            registry: Base URL of the npm-compatible registry to use.
        """
        self._registry = registry.rstrip("/")

    async def fetch(self, package_spec: str, dest: Path) -> Path:
        """Resolve *package_spec* to an unpacked directory under *dest*.

        Accepts:

        * ``"package-name"``         — latest version from npm registry
        * ``"package-name@1.2.3"``   — specific version from npm registry
        * ``"/absolute/path"``       — local directory (returned as-is)
        * ``"./relative/path"``      — local directory (resolved, returned as-is)

        Args:
            package_spec: Package identifier or filesystem path.
            dest:         Directory where the unpacked package will be placed.
                          Created if it does not exist.

        Returns:
            Absolute path to the unpacked package directory.

        Raises:
            :class:`PackageFetchError`: When the package cannot be obtained.
        """
        if _is_local_path(package_spec):
            return self._resolve_local(package_spec)

        name, version = _parse_package_spec(package_spec)
        return await self._fetch_from_registry(name, version, dest, package_spec)

    async def get_npm_metadata(self, name: str, version: str = "latest") -> dict:  # type: ignore[type-arg]
        """Fetch registry metadata for an npm package.

        Args:
            name:    Package name (scoped names like ``@scope/pkg`` accepted).
            version: Version string or dist-tag (default ``"latest"``).

        Returns:
            Parsed JSON dict from ``{registry}/{name}/{version}``.

        Raises:
            :class:`PackageFetchError`: On network or registry errors.
        """
        encoded = _encode_package_name(name)
        url = f"{self._registry}/{encoded}/{version}"

        # Validate registry URL against SSRF policy (covers custom registry URIs).
        try:
            ssrf_guard.validate_url(url)
        except SSRFError as exc:
            raise PackageFetchError(f"{name}@{version}", str(exc)) from exc

        async with httpx.AsyncClient(
            timeout=_REQUEST_TIMEOUT,
            event_hooks=ssrf_guard.safe_httpx_event_hook(),
            follow_redirects=True,
        ) as client:
            response = await _retry_request(client, url, f"{name}@{version}")

        try:
            from mcpguard.json_safe import safe_json_loads
            return safe_json_loads(response.text)  # type: ignore[no-any-return]
        except Exception as exc:
            raise PackageFetchError(
                name, f"Invalid JSON in registry response: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_local(self, spec: str) -> Path:
        """Return the resolved absolute path for a local package spec.

        Args:
            spec: A path string starting with ``/``, ``./``, or ``../``.

        Returns:
            Resolved :class:`~pathlib.Path`.

        Raises:
            :class:`PackageFetchError`: If the path does not exist or is not a directory.
        """
        path = Path(spec).resolve()
        if not path.exists():
            raise PackageFetchError(spec, f"Local path does not exist: {path}")
        if not path.is_dir():
            raise PackageFetchError(spec, f"Local path is not a directory: {path}")
        return path

    async def _fetch_from_registry(
        self, name: str, version: str, dest: Path, original_spec: str
    ) -> Path:
        """Download *name@version* from the registry and extract it under *dest*.

        Args:
            name:          Unencoded package name.
            version:       Version string or dist-tag.
            dest:          Parent directory for extraction.
            original_spec: Original user-supplied spec (for error messages).

        Returns:
            Path to the extracted package directory.

        Raises:
            :class:`PackageFetchError`: On any download or extraction failure.
        """
        metadata = await self.get_npm_metadata(name, version)

        try:
            tarball_url: str = metadata["dist"]["tarball"]
            resolved_version: str = metadata.get("version", version)
        except (KeyError, TypeError) as exc:
            raise PackageFetchError(
                original_spec,
                f"Unexpected registry metadata — missing dist.tarball: {exc}",
            ) from exc

        # Validate tarball URL against SSRF policy before issuing any request.
        # Registry metadata is untrusted — dist.tarball could point at internal infra.
        try:
            ssrf_guard.validate_url(tarball_url)
        except SSRFError as exc:
            raise PackageFetchError(original_spec, str(exc)) from exc

        log.info("Downloading %s@%s from %s", name, resolved_version, tarball_url)

        async with httpx.AsyncClient(
            timeout=_REQUEST_TIMEOUT,
            event_hooks=ssrf_guard.safe_httpx_event_hook(),
            follow_redirects=True,
        ) as client:
            tarball_response = await _retry_request(client, tarball_url, original_spec)

        tarball_bytes = tarball_response.content
        log.debug(
            "Downloaded %d bytes for %s@%s", len(tarball_bytes), name, resolved_version
        )

        pkg_name_safe = name.lstrip("@").replace("/", "__").replace("\\", "__")
        extract_dest = dest / f"{pkg_name_safe}-{resolved_version}"

        # Use SafeExtractor for defense-in-depth: path traversal, zip bomb,
        # symlink escape, special file injection, and nesting depth checks.
        try:
            extract_tgz_bytes(tarball_bytes, extract_dest)
        except ExtractionError as exc:
            raise PackageFetchError(
                original_spec, f"Unsafe archive content: {exc.reason}"
            ) from exc
        except Exception as exc:
            raise PackageFetchError(
                original_spec, f"Unexpected extraction error: {exc}"
            ) from exc

        # npm tarballs conventionally unpack into a "package/" subdirectory.
        package_subdir = extract_dest / "package"
        if package_subdir.is_dir():
            return package_subdir
        return extract_dest
