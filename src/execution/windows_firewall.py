"""
Windows Firewall Enforcement (Execution subsystem proxy).

Proxies to src.enforcement.windows_firewall to ensure backwards compatibility
with execution subsystem callers.
"""

from src.enforcement.windows_firewall import (
    DEFAULT_RULE_GROUP,
    DEFAULT_RULE_PREFIX,
    DEFAULT_TIMEOUT_SECONDS,
    FirewallEnforcementResult,
    FirewallRuleRecord,
    FirewallRuleScope,
    WindowsFirewallAdapter,
    WindowsFirewallEnforcer,
    is_administrator,
    is_windows_os,
)

__all__ = [
    "DEFAULT_RULE_GROUP",
    "DEFAULT_RULE_PREFIX",
    "DEFAULT_TIMEOUT_SECONDS",
    "FirewallEnforcementResult",
    "FirewallRuleRecord",
    "FirewallRuleScope",
    "WindowsFirewallAdapter",
    "WindowsFirewallEnforcer",
    "is_administrator",
    "is_windows_os",
]
