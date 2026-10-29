"""
Enforcement Subsystem Package.

Provides host security enforcement adapters, including native Windows Firewall
rule management, scoped blocking, and policy-driven remediation.
"""

from src.enforcement.windows_firewall import (
    DEFAULT_RULE_GROUP,
    DEFAULT_RULE_PREFIX,
    FirewallEnforcementResult,
    FirewallRuleRecord,
    FirewallRuleScope,
    WindowsFirewallAdapter,
    WindowsFirewallEnforcer,
)

__all__ = [
    "DEFAULT_RULE_GROUP",
    "DEFAULT_RULE_PREFIX",
    "FirewallEnforcementResult",
    "FirewallRuleRecord",
    "FirewallRuleScope",
    "WindowsFirewallAdapter",
    "WindowsFirewallEnforcer",
]
