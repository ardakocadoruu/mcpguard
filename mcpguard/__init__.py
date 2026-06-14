"""mcpguard — CLI security scanner for MCP (Model Context Protocol) packages.

Inspired by ``npm audit``, mcpguard analyses MCP packages for common
security issues including missing authentication, hardcoded secrets,
dangerous subprocess usage, over-broad network permissions, and known-bad
supply-chain packages.
"""

__version__ = "0.1.0"
__author__ = "mcpguard contributors"

__all__ = ["__version__", "__author__"]
