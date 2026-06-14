"""mcpguard vulnerability database package.

Provides access to the known-bad package registry and the async update
mechanism for keeping the local database current.
"""

from mcpguard.db.vuln_db import VulnDB

__all__ = ["VulnDB"]
