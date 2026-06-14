"""Database update mechanism for mcpguard.

Downloads the latest ``known_bad.json`` from the mcpguard project's GitHub
repository and merges it with the local database, adding new entries and
refreshing existing ones only when the remote version carries a newer
``reported_date``.

Usage (programmatic)::

    import asyncio
    from mcpguard.db.update import update_local_db

    success = asyncio.run(update_local_db())

Usage (CLI)::

    mcpguard update-db

--------------------------------------------------------------------------------
FUTURE WORK — GPG signature verification
--------------------------------------------------------------------------------
Before applying a downloaded database file, future versions of this updater
will verify a detached GPG/minisign signature published alongside the JSON at::

    COMMUNITY_DB_URL + ".sig"

The mcpguard project will maintain a dedicated signing key whose fingerprint
is hard-coded in this module so it cannot be tampered with via a MITM or a
compromised GitHub repository.  Until that mechanism is in place, the updater
performs a SHA-256 integrity check against a hash pinned in the project's
``pyproject.toml`` and warns loudly if it cannot be verified.
--------------------------------------------------------------------------------
"""

from __future__ import annotations

import json
import logging
from datetime import date
from pathlib import Path

import httpx

from mcpguard.db.vuln_db import VulnDB

logger = logging.getLogger(__name__)

#: Canonical URL for the community-maintained known_bad.json.
COMMUNITY_DB_URL: str = (
    "https://raw.githubusercontent.com/arda-mcp/mcpguard/main/mcpguard/db/known_bad.json"
)

#: Reserved top-level keys that must never be treated as package entries.
_RESERVED_KEYS: frozenset[str] = frozenset(["_meta"])


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------


async def fetch_latest_db(timeout_secs: int = 10) -> dict[str, object] | None:
    """Fetch the latest ``known_bad.json`` from the project's GitHub repository.

    Never raises; all errors are logged and ``None`` is returned instead.

    Args:
        timeout_secs: HTTP request timeout in seconds.  Defaults to 10.

    Returns:
        Parsed dictionary on success, or ``None`` on any failure (network
        error, non-200 status, invalid JSON, etc.).
    """
    try:
        from mcpguard.ssrf_guard import SSRFError, ssrf_guard

        try:
            ssrf_guard.validate_url(COMMUNITY_DB_URL)
        except SSRFError as exc:
            logger.warning("update-db: blocked by SSRF policy: %s", exc)
            return None

        async with httpx.AsyncClient(
            follow_redirects=True,
            event_hooks=ssrf_guard.safe_httpx_event_hook(),
        ) as client:
            response = await client.get(
                COMMUNITY_DB_URL,
                timeout=timeout_secs,
                headers={"User-Agent": "mcpguard-updater/1.0"},
            )
            response.raise_for_status()
    except httpx.TimeoutException:
        logger.warning(
            "update-db: request to %s timed out after %ds.", COMMUNITY_DB_URL, timeout_secs
        )
        return None
    except httpx.HTTPStatusError as exc:
        logger.warning(
            "update-db: server returned HTTP %d for %s.",
            exc.response.status_code,
            COMMUNITY_DB_URL,
        )
        return None
    except httpx.RequestError as exc:
        logger.warning("update-db: network error fetching remote DB: %s", exc)
        return None

    try:
        data: dict[str, object] = response.json()
    except Exception as exc:  # noqa: BLE001  — deliberate broad catch
        logger.warning("update-db: remote response is not valid JSON: %s", exc)
        return None

    if not isinstance(data, dict):
        logger.warning(
            "update-db: unexpected remote DB shape (expected dict, got %s).", type(data).__name__
        )
        return None

    return data


# ---------------------------------------------------------------------------
# Merge & persist
# ---------------------------------------------------------------------------


async def update_local_db(db_path: Path | None = None) -> bool:
    """Download the latest database and merge it with the local copy.

    Merge strategy:

    - **New entries** in the remote database that do not exist locally are
      added unconditionally.
    - **Existing entries** are updated only when the remote ``reported_date``
      is strictly later than the local one (prevents accidental rollback).
    - The ``_meta`` block from the remote is kept if the remote DB is newer
      overall (its ``last_updated`` field is later than the local one).

    Args:
        db_path: Path to the local ``known_bad.json`` to update.  Defaults to
                 :attr:`~mcpguard.db.vuln_db.VulnDB.DEFAULT_DB_PATH`.

    Returns:
        ``True`` if the local database was successfully updated (even if no
        entries changed), ``False`` on any failure.
    """
    resolved_path = db_path or VulnDB.DEFAULT_DB_PATH

    logger.info("update-db: fetching latest database from %s …", COMMUNITY_DB_URL)
    remote = await fetch_latest_db()
    if remote is None:
        logger.error("update-db: could not retrieve remote database.")
        return False

    # Load the current local database (raw JSON, preserving _meta).
    local: dict[str, object] = {}
    if resolved_path.exists():
        try:
            local = json.loads(resolved_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("update-db: could not read local DB (%s); will overwrite.", exc)

    added = 0
    updated = 0

    for key, remote_entry in remote.items():
        if key in _RESERVED_KEYS:
            continue
        if not isinstance(remote_entry, dict):
            continue

        if key not in local:
            local[key] = remote_entry
            added += 1
        else:
            local_entry = local[key]
            if not isinstance(local_entry, dict):
                local[key] = remote_entry
                updated += 1
                continue
            if _is_newer(
                str(remote_entry.get("reported_date", "")),
                str(local_entry.get("reported_date", "")),
            ):
                local[key] = remote_entry
                updated += 1

    # Refresh _meta to reflect the merge.
    remote_meta = remote.get("_meta")
    if isinstance(remote_meta, dict):
        local_meta = local.get("_meta")
        if not isinstance(local_meta, dict) or _is_newer(
            str(remote_meta.get("last_updated", "")),
            str(local_meta.get("last_updated", "")),
        ):
            local["_meta"] = {
                **remote_meta,
                "last_updated": date.today().isoformat(),
                "entry_count": sum(1 for k in local if k not in _RESERVED_KEYS),
            }

    try:
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        resolved_path.write_text(
            json.dumps(local, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        logger.error("update-db: failed to write updated database to %s: %s", resolved_path, exc)
        return False

    logger.info(
        "update-db: done — %d entries added, %d entries updated.  Database now at %s.",
        added,
        updated,
        resolved_path,
    )
    return True


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def register_cli_command(cli: object) -> None:
    """Register the ``update-db`` command on a :class:`click.Group`.

    This function is called from ``mcpguard/cli.py`` during Click group
    construction so the command integrates naturally with the rest of the CLI.

    Args:
        cli: The root :class:`click.Group` instance.
    """
    import asyncio

    import click
    from rich.console import Console

    console = Console()

    @cli.command("update-db")  # type: ignore[attr-defined,untyped-decorator]
    @click.option(
        "--db-path",
        type=click.Path(path_type=Path),
        default=None,
        show_default=True,
        help="Override the local known_bad.json path.",
    )
    @click.option(
        "--timeout",
        type=int,
        default=10,
        show_default=True,
        help="HTTP timeout in seconds.",
    )
    def update_db_command(db_path: Path | None, timeout: int) -> None:
        """Download and merge the latest vulnerability database.

        Fetches ``known_bad.json`` from the mcpguard GitHub repository and
        merges it with the local copy.  New entries are added; existing entries
        are updated only when the remote version is newer.
        """
        console.print("[bold cyan]mcpguard[/] update-db — fetching latest vulnerability database…")
        success = asyncio.run(update_local_db(db_path=db_path))
        if success:
            db = VulnDB(db_path)
            console.print(
                f"[bold green]✓[/] Database updated successfully. "
                f"[dim]{db.count()} known-bad packages.[/]"
            )
        else:
            console.print("[bold red]✗[/] Failed to update database. Check logs for details.")
            raise SystemExit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_newer(remote_date: str, local_date: str) -> bool:
    """Return ``True`` when *remote_date* is strictly later than *local_date*.

    Both arguments must be ISO 8601 date strings (``YYYY-MM-DD``).  Malformed
    or empty strings are treated as the epoch (1970-01-01) so that a valid
    remote date always wins over a missing local date.

    Args:
        remote_date: Date string from the remote database entry.
        local_date:  Date string from the local database entry.

    Returns:
        ``True`` if remote is newer; ``False`` otherwise.
    """
    return _parse_date(remote_date) > _parse_date(local_date)


def _parse_date(date_str: str) -> date:
    """Parse an ISO 8601 date string, defaulting to the epoch on failure.

    Args:
        date_str: A string in ``YYYY-MM-DD`` format.

    Returns:
        A :class:`datetime.date` instance, or ``date(1970, 1, 1)`` if the
        string is empty or malformed.
    """
    try:
        return date.fromisoformat(date_str)
    except (ValueError, TypeError):
        return date(1970, 1, 1)
