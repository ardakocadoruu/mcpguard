"""mcpguard built-in security rules.

Rule authors register their rules by appending to ALL_RULES.
The Scanner imports this list when no explicit rules are supplied.
"""

from __future__ import annotations

from mcpguard.rules.auth import AuthRule
from mcpguard.rules.base import Finding, Rule, ScanTarget, Severity
from mcpguard.rules.network import NetworkRule
from mcpguard.rules.permissions import PermissionsRule
from mcpguard.rules.prompt_injection import PromptInjectionRule
from mcpguard.rules.secrets import SecretsRule
from mcpguard.rules.subprocess_rule import SubprocessRule
from mcpguard.rules.supply_chain import SupplyChainRule

__all__ = [
    "ALL_RULES",
    "AuthRule",
    "Finding",
    "NetworkRule",
    "PermissionsRule",
    "PromptInjectionRule",
    "Rule",
    "SecretsRule",
    "Severity",
    "ScanTarget",
    "SubprocessRule",
    "SupplyChainRule",
]

#: Default rule set, ordered by rule ID.
ALL_RULES: list[Rule] = [
    AuthRule(),              # MCP001
    PermissionsRule(),       # MCP002
    NetworkRule(),           # MCP003
    SubprocessRule(),        # MCP004
    SupplyChainRule(),       # MCP005
    SecretsRule(),           # MCP006
    PromptInjectionRule(),   # MCP007
]
