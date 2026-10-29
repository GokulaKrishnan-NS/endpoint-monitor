"""
Unit and Integration Tests for Native Windows Firewall Enforcement.

Tests cover:
- Parameter validation: executable paths, IP addresses, ports, protocols
- Argument safety: command construction without shell expansion
- Dry-run behavior: simulation without OS modification
- Enforcement disabled behavior: passive monitoring preserved
- Missing administrator privileges: safe detection and non-crashing handling
- Command failures and timeouts: graceful error handling and status recording
- Rule ownership and cleanup: prefix enforcement, preventing deletion of unrelated rules
- Idempotent cleanup: repeated deletion safety, handling 'No rules match'
- Policy pipeline integration: separation of detection/risk scoring from enforcement
- Allowlist enforcement and missing executable path handling
- Sysmon Event ID 3 telemetry handling (prospective rule creation)
- Uninterrupted monitoring when firewall enforcement fails
"""

import os
import subprocess
import unittest
from unittest.mock import MagicMock, patch

from src.enforcement.windows_firewall import (
    DEFAULT_RULE_GROUP,
    DEFAULT_RULE_PREFIX,
    FirewallEnforcementResult,
    FirewallRuleRecord,
    FirewallRuleScope,
    WindowsFirewallAdapter,
    WindowsFirewallEnforcer,
    is_administrator,
    is_windows_os,
)
from src.models.event import Event
from src.monitors.network_monitor import NetworkMonitor
from src.ui.engine import MonitoringEngine


class TestWindowsFirewallAdapterValidation(unittest.TestCase):
    """Test strict parameter validation in WindowsFirewallAdapter."""

    def setUp(self):
        self.adapter = WindowsFirewallAdapter()

    def test_valid_executable_paths(self):
        """Standard Windows drive-letter paths and UNC paths must be accepted."""
        valid_paths = [
            r"C:\Windows\System32\cmd.exe",
            r"D:\Tools\malware_sim.exe",
            r"C:\Program Files\App\app.exe",
            r"\\server\share\tool.exe",
        ]
        for path in valid_paths:
            ok, err = self.adapter.validate_scope(executable=path)
            self.assertTrue(ok, f"Expected {path} to be valid, got error: {err}")
            self.assertIsNone(err)

    def test_invalid_executable_paths(self):
        """Relative paths, empty strings, and paths with control chars must be rejected."""
        invalid_paths = [
            "",
            "   ",
            "cmd.exe",  # Relative path
            r"subdir\app.exe",  # Relative path
            "C:\\bad\0path.exe",  # Null byte
            "C:\\bad\npath.exe",  # Newline
            None,
            123,
        ]
        for path in invalid_paths:
            ok, err = self.adapter.validate_scope(executable=path)
            self.assertFalse(ok, f"Expected {path!r} to be rejected")
            self.assertIsNotNone(err)

    def test_valid_remote_ips(self):
        """Valid IPv4 and IPv6 unicast addresses must be accepted."""
        valid_ips = [
            "192.168.1.50",
            "10.0.0.1",
            "172.16.0.1",
            "203.0.113.195",
            "2001:db8::1",
            "::1",  # Loopback
            "127.0.0.1",  # Loopback
        ]
        for ip in valid_ips:
            ok, err = self.adapter.validate_scope(
                executable=r"C:\Windows\notepad.exe", remote_ip=ip
            )
            self.assertTrue(ok, f"Expected IP {ip} to be valid, got: {err}")

    def test_invalid_remote_ips(self):
        """Broadcast, multicast, wildcards, and malformed strings must be rejected."""
        invalid_ips = [
            "*",  # Broad wildcard
            "0.0.0.0",  # Unspecified
            "::",  # Unspecified IPv6
            "255.255.255.255",  # Broadcast
            "224.0.0.1",  # Multicast
            "239.255.255.250",  # Multicast
            "999.999.999.999",  # Invalid format
            "not-an-ip",  # Not an IP
            "192.168.1.1/24",  # Subnet CIDR (adapter requires explicit IP address)
            "",
        ]
        for ip in invalid_ips:
            ok, err = self.adapter.validate_scope(
                executable=r"C:\Windows\notepad.exe", remote_ip=ip
            )
            self.assertFalse(ok, f"Expected IP {ip!r} to be rejected")
            self.assertIsNotNone(err)

    def test_valid_ports(self):
        """Integer ports between 1 and 65535 must be accepted."""
        for port in [1, 80, 443, 8080, 65535]:
            ok, err = self.adapter.validate_scope(
                executable=r"C:\Windows\notepad.exe", remote_port=port
            )
            self.assertTrue(ok, f"Expected port {port} to be valid, got: {err}")

    def test_invalid_ports(self):
        """Ports out of range or non-integers must be rejected."""
        for port in [0, -1, 65536, 100000, "80", True, False, 3.14]:
            ok, err = self.adapter.validate_scope(
                executable=r"C:\Windows\notepad.exe", remote_port=port
            )
            self.assertFalse(ok, f"Expected port {port!r} to be rejected")
            self.assertIsNotNone(err)

    def test_valid_protocols(self):
        """TCP and UDP (case-insensitive) must be accepted."""
        for proto in ["TCP", "UDP", "tcp", "udp", "Tcp", "Udp"]:
            ok, err = self.adapter.validate_scope(
                executable=r"C:\Windows\notepad.exe", protocol=proto
            )
            self.assertTrue(ok, f"Expected protocol {proto} to be valid, got: {err}")

    def test_invalid_protocols(self):
        """Protocols other than TCP/UDP must be rejected."""
        for proto in ["ICMP", "HTTP", "GRE", "raw", "", 6]:
            ok, err = self.adapter.validate_scope(
                executable=r"C:\Windows\notepad.exe", protocol=proto
            )
            self.assertFalse(ok, f"Expected protocol {proto!r} to be rejected")
            self.assertIsNotNone(err)


class TestWindowsFirewallAdapterExecution(unittest.TestCase):
    """Test argument-safe execution, dry-run, failure modes, and cleanup."""

    def test_add_rule_command_construction(self):
        """Command lists must be properly formed without shell interpolation."""
        adapter = WindowsFirewallAdapter()
        cmd = adapter.build_add_rule_command(
            rule_name="EndpointMonitor_Block_test_1",
            executable=r"C:\Tools\nc.exe",
            remote_ip="203.0.113.5",
            remote_port=4444,
            protocol="TCP",
        )
        self.assertIsInstance(cmd, list)
        self.assertEqual(cmd[0], "netsh.exe")
        self.assertEqual(cmd[1], "advfirewall")
        self.assertEqual(cmd[2], "firewall")
        self.assertEqual(cmd[3], "add")
        self.assertEqual(cmd[4], "rule")
        self.assertIn("name=EndpointMonitor_Block_test_1", cmd)
        self.assertIn("dir=out", cmd)
        self.assertIn("action=block", cmd)
        self.assertIn(r"program=C:\Tools\nc.exe", cmd)
        self.assertIn("remoteip=203.0.113.5", cmd)
        self.assertIn("protocol=tcp", cmd)
        self.assertIn("remoteport=4444", cmd)

    def test_delete_rule_command_construction(self):
        """Delete command must target exact rule name."""
        adapter = WindowsFirewallAdapter()
        cmd = adapter.build_delete_rule_command("EndpointMonitor_Block_test_1")
        self.assertEqual(
            cmd,
            [
                "netsh.exe",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=EndpointMonitor_Block_test_1",
            ],
        )

    def test_dry_run_rule_creation(self):
        """Dry-run mode must simulate rule creation without calling subprocess executor."""
        mock_exec = MagicMock()
        adapter = WindowsFirewallAdapter(executor=mock_exec)

        record = adapter.create_block_rule(
            executable=r"C:\Tools\attacker.exe",
            remote_ip="198.51.100.10",
            remote_port=1337,
            protocol="TCP",
            dry_run=True,
        )

        mock_exec.assert_not_called()
        self.assertEqual(record.status, "DRY_RUN")
        self.assertTrue(record.dry_run)
        self.assertTrue(record.success)
        self.assertIn("DRY-RUN", record.reasons[0])
        self.assertTrue(adapter.is_rule_active(record.rule_name))

    def test_live_rule_creation_success(self):
        """Live creation with mocked admin and successful netsh run."""
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "Ok.\r\n"
        mock_res.stderr = ""
        mock_exec = MagicMock(return_value=mock_res)

        adapter = WindowsFirewallAdapter(executor=mock_exec)

        with patch.object(adapter, "is_supported", return_value=True), \
             patch.object(adapter, "has_admin_privileges", return_value=True):
            record = adapter.create_block_rule(
                executable=r"C:\Tools\trojan.exe",
                remote_ip="203.0.113.88",
                remote_port=8080,
                protocol="TCP",
                dry_run=False,
            )

        mock_exec.assert_called_once()
        self.assertEqual(record.status, "APPLIED")
        self.assertTrue(record.success)
        self.assertFalse(record.dry_run)
        self.assertIsNone(record.error)
        self.assertTrue(adapter.is_rule_active(record.rule_name))

    def test_missing_admin_privileges_fails_safely(self):
        """Non-admin process must fail gracefully without calling netsh or crashing."""
        mock_exec = MagicMock()
        adapter = WindowsFirewallAdapter(executor=mock_exec)

        with patch.object(adapter, "is_supported", return_value=True), \
             patch.object(adapter, "has_admin_privileges", return_value=False):
            record = adapter.create_block_rule(
                executable=r"C:\Tools\trojan.exe",
                remote_ip="203.0.113.88",
                dry_run=False,
            )

        mock_exec.assert_not_called()
        self.assertEqual(record.status, "FAILED")
        self.assertFalse(record.success)
        self.assertIn("Administrator privileges required", record.error)

    def test_unsupported_os_fails_safely(self):
        """Non-Windows environment must fail gracefully."""
        mock_exec = MagicMock()
        adapter = WindowsFirewallAdapter(executor=mock_exec)

        with patch.object(adapter, "is_supported", return_value=False):
            record = adapter.create_block_rule(
                executable=r"C:\Tools\trojan.exe",
                dry_run=False,
            )

        mock_exec.assert_not_called()
        self.assertEqual(record.status, "FAILED")
        self.assertFalse(record.success)
        self.assertIn("only supported on Windows", record.error)

    def test_netsh_command_failure_captured(self):
        """Non-zero netsh exit code must result in FAILED status with error details."""
        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stdout = ""
        mock_res.stderr = "An invalid parameter was specified."
        mock_exec = MagicMock(return_value=mock_res)

        adapter = WindowsFirewallAdapter(executor=mock_exec)

        with patch.object(adapter, "is_supported", return_value=True), \
             patch.object(adapter, "has_admin_privileges", return_value=True):
            record = adapter.create_block_rule(
                executable=r"C:\Tools\trojan.exe",
                dry_run=False,
            )

        self.assertEqual(record.status, "FAILED")
        self.assertFalse(record.success)
        self.assertIn("invalid parameter", record.error)

    def test_netsh_timeout_handled_gracefully(self):
        """TimeoutExpired exception must be caught and recorded as FAILED."""
        mock_exec = MagicMock(side_effect=subprocess.TimeoutExpired(cmd="netsh", timeout=5.0))
        adapter = WindowsFirewallAdapter(executor=mock_exec)

        with patch.object(adapter, "is_supported", return_value=True), \
             patch.object(adapter, "has_admin_privileges", return_value=True):
            record = adapter.create_block_rule(
                executable=r"C:\Tools\trojan.exe",
                dry_run=False,
            )

        self.assertEqual(record.status, "FAILED")
        self.assertFalse(record.success)
        self.assertIn("timed out", record.error)

    def test_refuse_deletion_of_unrelated_rules(self):
        """Adapter must refuse to delete rules not starting with application prefix."""
        mock_exec = MagicMock()
        adapter = WindowsFirewallAdapter(executor=mock_exec)

        unrelated_rules = [
            "Core Networking - DNS (UDP-Out)",
            "Windows Defender Firewall Remote Management",
            "all",  # Dangerous broad wildcard
            "*",
            "CustomRule123",
        ]
        for rule_name in unrelated_rules:
            with self.assertRaises(ValueError):
                adapter.delete_rule(rule_name)

        mock_exec.assert_not_called()

    def test_idempotent_delete_rule_success(self):
        """Deleting an owned rule calls netsh and succeeds."""
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "Deleted 1 rule(s).\r\nOk.\r\n"
        mock_res.stderr = ""
        mock_exec = MagicMock(return_value=mock_res)

        adapter = WindowsFirewallAdapter(executor=mock_exec)
        # Manually register rule in active list
        rule_name = f"{DEFAULT_RULE_PREFIX}test_target"
        adapter._active_rules[rule_name] = FirewallRuleRecord(rule_name=rule_name, status="APPLIED")

        success = adapter.delete_rule(rule_name)
        self.assertTrue(success)
        mock_exec.assert_called_once()
        self.assertNotIn(rule_name, adapter._active_rules)

    def test_idempotent_delete_when_rule_already_absent(self):
        """When netsh returns 'No rules match', deletion is treated as idempotent success."""
        mock_res = MagicMock()
        mock_res.returncode = 1
        mock_res.stdout = "No rules match the specified criteria.\r\n"
        mock_res.stderr = ""
        mock_exec = MagicMock(return_value=mock_res)

        adapter = WindowsFirewallAdapter(executor=mock_exec)
        rule_name = f"{DEFAULT_RULE_PREFIX}already_gone"

        success = adapter.delete_rule(rule_name)
        self.assertTrue(success)

    def test_delete_all_owned_rules_never_calls_name_all(self):
        """delete_all_owned_rules must delete owned rules by individual name and never name=all."""
        mock_res = MagicMock()
        mock_res.returncode = 0
        mock_res.stdout = "Ok.\r\n"
        mock_res.stderr = ""
        mock_exec = MagicMock(return_value=mock_res)

        adapter = WindowsFirewallAdapter(executor=mock_exec)
        rule1 = f"{DEFAULT_RULE_PREFIX}app1"
        rule2 = f"{DEFAULT_RULE_PREFIX}app2"
        adapter._active_rules[rule1] = FirewallRuleRecord(rule_name=rule1, status="APPLIED")
        adapter._active_rules[rule2] = FirewallRuleRecord(rule_name=rule2, status="APPLIED")

        deleted = adapter.delete_all_owned_rules()
        self.assertEqual(deleted, 2)
        self.assertEqual(mock_exec.call_count, 2)

        # Ensure no call had 'name=all'
        for call_args in mock_exec.call_args_list:
            cmd = call_args[0][0]
            self.assertNotIn("name=all", cmd)
            self.assertNotIn("name=*", cmd)


class TestWindowsFirewallEnforcerPolicy(unittest.TestCase):
    """Test policy decision pipeline, thresholds, dry-run, and safe defaults."""

    def test_disabled_by_default(self):
        """Enforcer must be disabled by default and return NO_ACTION."""
        enforcer = WindowsFirewallEnforcer(config={"enabled": False})
        self.assertFalse(enforcer.enabled)

        event = Event(
            event_id="test_evt_1",
            risk_score=9,
            severity="HIGH",
            indicators=["malicious_beacon"],
        )
        result = enforcer.process_network_event(event)

        self.assertEqual(result.policy_decision, "NO_ACTION")
        self.assertEqual(result.enforcement_status, "NOT_ENFORCED")
        self.assertFalse(result.rule_applied)
        self.assertIn("disabled", result.reasons[0])

    def test_dry_run_by_default(self):
        """When enabled without dry_run=False, dry_run must default to True."""
        enforcer = WindowsFirewallEnforcer(config={"enabled": True})
        self.assertTrue(enforcer.dry_run)

        event = Event(
            event_id="test_evt_2",
            risk_score=8,
            severity="HIGH",
            indicators=["suspicious_outbound"],
            network_info={
                "exe": r"C:\Windows\System32\curl.exe",
                "remote_ip": "203.0.113.10",
                "remote_port": 4444,
                "protocol": "TCP",
            },
        )
        result = enforcer.process_network_event(event)

        self.assertEqual(result.policy_decision, "BLOCK")
        self.assertEqual(result.enforcement_status, "SIMULATED")
        self.assertFalse(result.rule_applied)
        self.assertIsNotNone(result.rule_record)
        self.assertEqual(result.rule_record.status, "DRY_RUN")

    def test_policy_separation_score_below_threshold(self):
        """Score below block_threshold must NOT trigger block unless severity or indicators match."""
        enforcer = WindowsFirewallEnforcer(
            config={
                "enabled": True,
                "block_threshold": 7,
                "blocked_severities": ["HIGH"],
                "blocked_indicators": [],
                "auto_block_suspicious": False,
            }
        )

        event = Event(
            event_id="test_evt_3",
            risk_score=5,
            severity="MEDIUM",
            indicators=["non_standard_port"],
        )
        should_block, decision, reasons = enforcer.evaluate_event_for_enforcement(event)
        self.assertFalse(should_block)
        self.assertEqual(decision, "ALLOW")

    def test_policy_separation_score_at_or_above_threshold(self):
        """Score meeting or exceeding threshold triggers block decision."""
        enforcer = WindowsFirewallEnforcer(
            config={
                "enabled": True,
                "block_threshold": 7,
            }
        )
        event = Event(
            event_id="test_evt_4",
            risk_score=7,
            severity="MEDIUM",
        )
        should_block, decision, reasons = enforcer.evaluate_event_for_enforcement(event)
        self.assertTrue(should_block)
        self.assertEqual(decision, "BLOCK")
        self.assertTrue(any("threshold" in r for r in reasons))

    def test_allowed_executables_bypass_enforcement(self):
        """Executables in allowed_executables list must not be blocked."""
        enforcer = WindowsFirewallEnforcer(
            config={
                "enabled": True,
                "block_threshold": 5,
                "allowed_executables": ["legit_tool.exe"],
            }
        )
        event = Event(
            event_id="test_evt_5",
            process_name="legit_tool.exe",
            risk_score=9,
            severity="HIGH",
        )
        should_block, decision, reasons = enforcer.evaluate_event_for_enforcement(event)
        self.assertFalse(should_block)
        self.assertEqual(decision, "ALLOW")
        self.assertIn("allowed_executables", reasons[0])

    def test_missing_executable_path_does_not_create_broad_rule(self):
        """If executable path cannot be determined, enforcer refuses to create broad rule."""
        enforcer = WindowsFirewallEnforcer(config={"enabled": True, "block_threshold": 5})
        event = Event(
            event_id="test_evt_6",
            process_name="ghost_process.exe",
            risk_score=8,
            severity="HIGH",
            network_info={"remote_ip": "198.51.100.5", "remote_port": 80},
        )
        # Running processes dictionary does not contain ghost_process
        result = enforcer.process_network_event(event, running_processes={})

        self.assertEqual(result.policy_decision, "BLOCK")
        self.assertEqual(result.enforcement_status, "SKIPPED")
        self.assertFalse(result.rule_applied)
        self.assertIn("executable path is unavailable", result.error)

    def test_sysmon_event_3_telemetry_prospective_notice(self):
        """Sysmon Event 3 events must include prospective rule notice."""
        enforcer = WindowsFirewallEnforcer(config={"enabled": True, "block_threshold": 5})
        event = Event(
            event_id="test_evt_7",
            source="sysmon",
            risk_score=8,
            severity="HIGH",
            network_info={
                "exe": r"C:\Windows\System32\powershell.exe",
                "remote_ip": "203.0.113.20",
                "remote_port": 443,
            },
            metadata={"telemetry_source": "sysmon"},
        )
        result = enforcer.process_network_event(event)

        self.assertEqual(result.policy_decision, "BLOCK")
        self.assertTrue(
            any("Sysmon Event ID 3" in r for r in result.reasons),
            "Expected prospective notice for Sysmon Event 3",
        )

    def test_startup_status_message(self):
        """Status messages accurately reflect configuration states."""
        enf_disabled = WindowsFirewallEnforcer(config={"enabled": False})
        self.assertIn("DISABLED", enf_disabled.get_startup_status_message())

        enf_dry_run = WindowsFirewallEnforcer(config={"enabled": True, "dry_run": True})
        self.assertIn("DRY-RUN", enf_dry_run.get_startup_status_message())

        enf_live = WindowsFirewallEnforcer(config={"enabled": True, "dry_run": False})
        with patch.object(enf_live.adapter, "has_admin_privileges", return_value=True):
            self.assertIn("LIVE ENABLED", enf_live.get_startup_status_message())


class TestFirewallIntegrationAndResilience(unittest.TestCase):
    """Test engine integration, fault isolation, and uninterrupted monitoring."""

    def test_monitoring_engine_has_firewall_enforcer(self):
        """MonitoringEngine must initialize firewall_enforcer with safe defaults."""
        engine = MonitoringEngine()
        try:
            self.assertIsNotNone(engine.firewall_enforcer)
            status = engine.get_firewall_enforcement_status()
            self.assertIn("enabled", status)
            self.assertIn("dry_run", status)
            self.assertIn("status_message", status)
        finally:
            engine.stop()

    def test_fault_isolation_in_engine_collection(self):
        """An unhandled error in firewall adapter must not crash the engine cycle."""
        engine = MonitoringEngine()
        try:
            # Mock firewall enforcer to raise unexpected error
            mock_enforcer = MagicMock()
            mock_enforcer.process_network_event.side_effect = RuntimeError("Firewall subsystem broke")
            engine.firewall_enforcer = mock_enforcer

            test_event = Event(
                event_id="fault_test_1",
                process_name="test.exe",
                risk_score=9,
                severity="HIGH",
            )
            # Ingesting should not raise
            engine._ingest_event(test_event)

            # Cycle execution should handle network event error safely
            mock_net_result = {
                "active_connections": [],
                "collection_status": "SUCCESS",
                "last_success_timestamp": 1000.0,
                "last_error": None,
                "suspicious_events": [test_event],
            }
            with patch.object(engine.network_monitor, "check_connections", return_value=mock_net_result):
                # Should not raise exception
                engine._cycle_execution()

            # Error was caught and recorded
            errors = list(engine._errors)
            self.assertTrue(any("Firewall enforcement error" in e for e in errors))
        finally:
            engine.stop()


if __name__ == "__main__":
    unittest.main()
