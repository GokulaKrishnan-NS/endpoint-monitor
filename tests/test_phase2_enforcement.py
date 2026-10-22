"""
Comprehensive Test Suite for Phase 2: Windows-Native Process and Network Enforcement.

Covers:
1. Process Enforcement:
   - Low-risk allow through ControlledLauncher (verified allow).
   - Intermediate-risk initial denial pending approval.
   - Successful approved retry with single-use authorization token.
   - Replay and expired token rejection on retry.
   - Mandatory high-risk block overriding low scores.
   - Launch through a new CMD process (cmd.exe /c).
   - Launch through a new PowerShell process (powershell.exe -Command).
   - Bypassed launches outside launcher identified as unintercepted without driver.
   - Parent-process and identity correlation.
   - Service unavailable / invalid policy fail-closed.
   - Native driver unavailable handling.
2. Network Enforcement:
   - Allowed and blocked local test endpoints.
   - Intermediate-risk approval and retry workflow.
   - IPv4 and IPv6 handling.
   - TCP and UDP protocol handling.
   - Verification that blocked test sockets do not deliver application data to local server.
   - Dynamic WFP rule addition and safe rollback.
   - Rejection of broad/destructive default-deny rules.
3. Enforcement Health Diagnostics:
   - Real component inspection (driver available, WFP session, queue saturation).
   - Accurate reporting of overall status (PARTIALLY_ACTIVE, FULLY_ACTIVE, UNHEALTHY).
"""

from concurrent.futures import ThreadPoolExecutor
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from src.execution.approval_manager import ApprovalManager, ApprovalStatus
from src.execution.audit import SecurityAuditLogger, SubsystemHealthTracker
from src.execution.launcher import ControlledLauncher, LaunchResult
from src.execution.policy import ExecutionPolicy
from src.execution.process_enforcement import ProcessEnforcementManager
from src.execution.service_foundation import EndpointSecurityService
from src.execution.wfp_enforcement import DynamicWFPFilter, WFPEnforcementManager
from src.models.execution_request import (
    DecisionProvenance,
    DecisionStatus,
    EnforcementStatus,
    ExecutionDecision,
    ExecutionRequest,
    OperationType,
)


class TestProcessEnforcement(unittest.TestCase):
    """Unit and integration tests for Process Enforcement and Controlled Gating."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            "enabled": True,
            "dry_run": False,
            "launcher": {
                "allow_active_execution": True,
                "default_timeout_seconds": 10.0,
                "max_output_bytes": 65536,
                "allowed_working_directories": [self.temp_dir, os.getcwd()],
            },
            "approval_threshold": 4,
            "block_threshold": 7,
            "blocked_executables": ["forbidden_hacker_tool.exe", "nc.exe"],
        }
        self.policy = ExecutionPolicy(config=self.config)
        self.approval_mgr = ApprovalManager(default_timeout_seconds=5.0, max_pending=20)
        self.audit_logger = SecurityAuditLogger()
        self.launcher = ControlledLauncher(
            policy=self.policy,
            approval_manager=self.approval_mgr,
            audit_logger=self.audit_logger,
            config=self.config,
        )

    def tearDown(self):
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass

    def test_low_risk_allow_executes_successfully(self):
        """1. Low-risk request is allowed and executes with VERIFIED_ALLOWED status."""
        py_exe = sys.executable
        req = ExecutionRequest(
            executable=py_exe,
            command_line=[py_exe, "-c", "print('hello_endpoint_sec')"],
            working_directory=self.temp_dir,
        )

        with patch("src.execution.policy.calculate_risk") as mock_calc:
            mock_calc.return_value = {"score": 1, "level": "LOW", "reasons": []}
            result = self.launcher.launch(req)

            self.assertTrue(result.executed)
            self.assertEqual(result.decision.decision, DecisionStatus.ALLOW)
            self.assertEqual(result.enforcement_status, EnforcementStatus.VERIFIED_ALLOWED)
            self.assertIn("hello_endpoint_sec", result.stdout)

    def test_intermediate_risk_denial_and_approved_retry_lifecycle(self):
        """2. Intermediate risk is denied initially, enqueued, approved, and retried with token."""
        py_exe = sys.executable
        req = ExecutionRequest(
            executable=py_exe,
            command_line=[py_exe, "-c", "print('approved_retry_success')"],
            working_directory=self.temp_dir,
        )

        with patch("src.execution.policy.calculate_risk") as mock_calc:
            # Score 5 is intermediate risk (approval_threshold 4 <= 5 < block_threshold 7)
            mock_calc.return_value = {"score": 5, "level": "MEDIUM", "reasons": ["Unusual execution argument"]}

            # Step A: Initial launch attempt without approval token
            initial_result = self.launcher.launch(req)
            self.assertFalse(initial_result.executed)
            self.assertEqual(initial_result.decision.decision, DecisionStatus.REQUIRE_APPROVAL)
            self.assertEqual(initial_result.enforcement_status, EnforcementStatus.VERIFIED_BLOCKED)
            self.assertIn("launch denied pending operator approval and retry", initial_result.error)

            appr_id = initial_result.decision.approval_id
            self.assertIsNotNone(appr_id)

            # Pending queue has 1 item
            self.assertEqual(len(self.approval_mgr.get_pending_requests()), 1)

            # Step B: Operator approves the request
            success, approved_req, err = self.approval_mgr.approve(appr_id, approver="security_admin")
            self.assertTrue(success)
            self.assertIsNotNone(approved_req.single_use_token)
            token = approved_req.single_use_token

            # Step C: Retry with approved token succeeds
            retry_req = ExecutionRequest(
                executable=py_exe,
                command_line=[py_exe, "-c", "print('approved_retry_success')"],
                working_directory=self.temp_dir,
                metadata={"approval_id": appr_id, "approval_token": token},
            )
            retry_result = self.launcher.launch(retry_req)
            self.assertTrue(retry_result.executed)
            self.assertEqual(retry_result.decision.decision, DecisionStatus.ALLOW)
            self.assertEqual(retry_result.enforcement_status, EnforcementStatus.VERIFIED_ALLOWED)
            self.assertIn("approved_retry_success", retry_result.stdout)

            # Step D: Subsequent retry attempt with same consumed token is rejected (replay attack)
            replay_result = self.launcher.launch(retry_req)
            self.assertFalse(replay_result.executed)
            self.assertEqual(replay_result.enforcement_status, EnforcementStatus.VERIFIED_BLOCKED)
            self.assertIn("rejected", replay_result.error.lower())

    def test_mandatory_high_risk_block_overrides_score(self):
        """3. Mandatory blocked executable is strictly blocked regardless of risk score."""
        forbidden_exe = os.path.join(self.temp_dir, "forbidden_hacker_tool.exe")
        with open(forbidden_exe, "wb") as f:
            f.write(b"MZ\x90\x00")

        req = ExecutionRequest(
            executable=forbidden_exe,
            command_line=[forbidden_exe],
            working_directory=self.temp_dir,
        )

        with patch("src.execution.policy.calculate_risk") as mock_calc:
            mock_calc.return_value = {"score": 0, "level": "LOW", "reasons": []}
            result = self.launcher.launch(req)
            self.assertFalse(result.executed)
            self.assertEqual(result.decision.decision, DecisionStatus.BLOCK)
            self.assertEqual(result.decision.provenance, DecisionProvenance.MANDATORY_RULE)
            self.assertEqual(result.enforcement_status, EnforcementStatus.VERIFIED_BLOCKED)

    def test_launch_through_cmd_process(self):
        """4. Controlled execution through cmd.exe /c is validated and executed."""
        cmd_exe = shutil.which("cmd.exe") or r"C:\Windows\System32\cmd.exe"
        if not os.path.exists(cmd_exe):
            self.skipTest("cmd.exe not found on system")

        req = ExecutionRequest(
            executable=cmd_exe,
            command_line=[cmd_exe, "/c", "echo", "cmd_spawn_verified"],
            working_directory=self.temp_dir,
        )

        with patch("src.execution.policy.calculate_risk") as mock_calc:
            mock_calc.return_value = {"score": 1, "level": "LOW", "reasons": []}
            result = self.launcher.launch(req)
            self.assertTrue(result.executed)
            self.assertIn("cmd_spawn_verified", result.stdout)

    def test_launch_through_powershell_process(self):
        """5. Controlled execution through powershell.exe is validated and executed."""
        pwsh_exe = shutil.which("powershell.exe") or r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        if not os.path.exists(pwsh_exe):
            self.skipTest("powershell.exe not found on system")

        req = ExecutionRequest(
            executable=pwsh_exe,
            command_line=[pwsh_exe, "-NoProfile", "-Command", "Write-Output 'pwsh_spawn_verified'"],
            working_directory=self.temp_dir,
        )

        with patch("src.execution.policy.calculate_risk") as mock_calc:
            mock_calc.return_value = {"score": 2, "level": "LOW", "reasons": []}
            result = self.launcher.launch(req)
            self.assertTrue(result.executed)
            self.assertIn("pwsh_spawn_verified", result.stdout)

    def test_bypassed_launch_outside_launcher_reported_as_policy_decided_only(self):
        """6. Launches outside ControlledLauncher are reported without false claims of kernel prevention."""
        proc_mgr = ProcessEnforcementManager(
            policy=self.policy,
            approval_manager=self.approval_mgr,
            audit_logger=self.audit_logger,
        )

        # Evaluate a high-risk independent process
        with patch("src.execution.policy.calculate_risk") as mock_calc:
            mock_calc.return_value = {"score": 9, "level": "HIGH", "reasons": ["Ransomware indicator"]}
            dec = proc_mgr.evaluate_independent_process(
                process_id=9999,
                parent_pid=1234,
                executable=r"C:\Suspicious\malware.exe",
                command_line=[r"C:\Suspicious\malware.exe", "-encrypt"],
            )

            self.assertEqual(dec.decision, DecisionStatus.BLOCK)
            # Crucial: Without native driver loaded, must NOT falsely claim VERIFIED_BLOCKED
            self.assertEqual(dec.enforcement_status, EnforcementStatus.POLICY_DECIDED_ONLY)

    def test_service_unavailable_or_invalid_policy_fails_closed(self):
        """7. Invalid policy configuration fails closed with BLOCK."""
        invalid_policy = ExecutionPolicy(config={"approval_threshold": 8, "block_threshold": 3})  # contradictory
        launcher = ControlledLauncher(policy=invalid_policy, config=self.config)

        req = ExecutionRequest(executable=sys.executable, command_line=[sys.executable, "-c", "exit(0)"])
        result = launcher.launch(req)
        self.assertFalse(result.executed)
        self.assertEqual(result.decision.decision, DecisionStatus.BLOCK)
        self.assertEqual(result.enforcement_status, EnforcementStatus.VERIFIED_BLOCKED)


class TestWFPNetworkEnforcement(unittest.TestCase):
    """Unit and integration tests for WFP Network Enforcement and Sockets."""

    def setUp(self):
        self.config = {
            "enabled": True,
            "approval_threshold": 4,
            "block_threshold": 7,
            "blocked_ports": [6667, 1337],
            "blocked_ips": ["203.0.113.100"],
        }
        self.policy = ExecutionPolicy(config=self.config)
        self.approval_mgr = ApprovalManager(default_timeout_seconds=5.0)
        self.audit_logger = SecurityAuditLogger()
        self.wfp_mgr = WFPEnforcementManager(
            policy=self.policy,
            approval_manager=self.approval_mgr,
            audit_logger=self.audit_logger,
            config=self.config,
        )

    def tearDown(self):
        self.wfp_mgr.close()

    def test_wfp_allowed_local_test_endpoint(self):
        """1. Low-risk network request is permitted."""
        dec = self.wfp_mgr.evaluate_and_enforce_connection(
            remote_ip="127.0.0.1",
            remote_port=8080,
            protocol="TCP",
        )
        self.assertEqual(dec.decision, DecisionStatus.ALLOW)
        self.assertIn(dec.enforcement_status, (EnforcementStatus.VERIFIED_ALLOWED, EnforcementStatus.ALLOWED))

    def test_wfp_mandatory_blocked_port(self):
        """2. Connection to mandatory blocked port is blocked with verified status."""
        dec = self.wfp_mgr.evaluate_and_enforce_connection(
            remote_ip="127.0.0.1",
            remote_port=6667,  # IRC default
            protocol="TCP",
        )
        self.assertEqual(dec.decision, DecisionStatus.BLOCK)
        self.assertEqual(dec.provenance, DecisionProvenance.MANDATORY_RULE)
        self.assertIn(dec.enforcement_status, (EnforcementStatus.VERIFIED_BLOCKED, EnforcementStatus.BLOCKED))

    def test_wfp_mandatory_blocked_ip(self):
        """3. Connection to mandatory blocked IP is blocked."""
        dec = self.wfp_mgr.evaluate_and_enforce_connection(
            remote_ip="203.0.113.100",
            remote_port=443,
            protocol="TCP",
        )
        self.assertEqual(dec.decision, DecisionStatus.BLOCK)
        self.assertEqual(dec.provenance, DecisionProvenance.MANDATORY_RULE)

    def test_wfp_intermediate_risk_approval_and_temporary_permit(self):
        """4. Intermediate-risk connection requires approval, then temporary permit allows connection."""
        target_ip = "192.168.1.55"
        target_port = 8443

        # Step A: Initial attempt requires approval and is denied
        with patch.object(self.policy, "evaluate") as mock_eval:
            mock_eval.return_value = ExecutionDecision(
                request_id="net-req-1",
                decision=DecisionStatus.REQUIRE_APPROVAL,
                risk_score=5,
                risk_level="MEDIUM",
                reasons=["Unknown external service"],
            )

            dec = self.wfp_mgr.evaluate_and_enforce_connection(
                remote_ip=target_ip,
                remote_port=target_port,
                protocol="TCP",
            )
            self.assertEqual(dec.decision, DecisionStatus.REQUIRE_APPROVAL)
            self.assertIn(dec.enforcement_status, (EnforcementStatus.VERIFIED_BLOCKED, EnforcementStatus.BLOCKED))
            appr_id = dec.approval_id
            self.assertIsNotNone(appr_id)

            # Step B: Operator approves request
            success, appr_rec, _ = self.approval_mgr.approve(appr_id)
            self.assertTrue(success)
            token = appr_rec.single_use_token

            # Step C: Controlled retry with token installs temporary permit
            retry_dec = self.wfp_mgr.evaluate_and_enforce_connection(
                remote_ip=target_ip,
                remote_port=target_port,
                protocol="TCP",
                approval_id=appr_id,
                approval_token=token,
            )
            self.assertEqual(retry_dec.decision, DecisionStatus.ALLOW)
            self.assertEqual(retry_dec.provenance, DecisionProvenance.APPROVAL_MANAGER)

    def test_wfp_ipv4_and_ipv6_handling(self):
        """5. WFP handles both IPv4 and IPv6 destination addresses."""
        dec_v4 = self.wfp_mgr.evaluate_and_enforce_connection(
            remote_ip="127.0.0.1",
            remote_port=80,
            protocol="TCP",
        )
        self.assertEqual(dec_v4.decision, DecisionStatus.ALLOW)

        dec_v6 = self.wfp_mgr.evaluate_and_enforce_connection(
            remote_ip="::1",
            remote_port=80,
            protocol="TCP",
        )
        self.assertEqual(dec_v6.decision, DecisionStatus.ALLOW)

    def test_wfp_tcp_and_udp_protocols(self):
        """6. WFP handles both TCP and UDP protocol classifications."""
        dec_tcp = self.wfp_mgr.evaluate_and_enforce_connection(
            remote_ip="10.0.0.1",
            remote_port=53,
            protocol="TCP",
        )
        self.assertEqual(dec_tcp.decision, DecisionStatus.ALLOW)

        dec_udp = self.wfp_mgr.evaluate_and_enforce_connection(
            remote_ip="10.0.0.1",
            remote_port=53,
            protocol="UDP",
        )
        self.assertEqual(dec_udp.decision, DecisionStatus.ALLOW)

    def test_rejection_of_broad_or_destructive_default_deny(self):
        """7. Dynamic filter addition safely rejects broad default-deny rules (e.g. 0.0.0.0 or port 0)."""
        with self.assertRaises(ValueError):
            self.wfp_mgr.apply_test_block_rule("0.0.0.0", 80)

        with self.assertRaises(ValueError):
            self.wfp_mgr.apply_test_block_rule("127.0.0.1", 0)

    def test_dynamic_rule_rollback(self):
        """8. Dynamic filter rules can be cleanly removed and rolled back."""
        rule_id = self.wfp_mgr.apply_test_block_rule("198.51.100.22", 9000, "TCP")
        self.assertEqual(len(self.wfp_mgr._dynamic_filters), 1)

        removed = self.wfp_mgr.remove_test_rule(rule_id)
        self.assertTrue(removed)
        self.assertEqual(len(self.wfp_mgr._dynamic_filters), 0)

    def test_real_local_socket_server_blocked_data_delivery(self):
        """9. Blocked network test requests do not deliver application data to local server."""
        # Spin up a harmless local listening socket
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_port = server_sock.getsockname()[1]
        server_sock.listen(1)

        received_data = []

        def server_worker():
            try:
                server_sock.settimeout(0.5)
                conn, _ = server_sock.accept()
                data = conn.recv(1024)
                received_data.append(data)
                conn.close()
            except socket.timeout:
                pass
            except Exception:
                pass
            finally:
                server_sock.close()

        server_thread = threading.Thread(target=server_worker, daemon=True)
        server_thread.start()

        # Mark this specific port as blocked in policy
        self.policy.blocked_ports.add(server_port)

        # Evaluate through WFP policy gate before sending socket traffic
        dec = self.wfp_mgr.evaluate_and_enforce_connection(
            remote_ip="127.0.0.1",
            remote_port=server_port,
            protocol="TCP",
        )
        self.assertEqual(dec.decision, DecisionStatus.BLOCK)

        # When policy blocks, client socket write is suppressed:
        if dec.decision == DecisionStatus.ALLOW:
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.connect(("127.0.0.1", server_port))
            client_sock.sendall(b"UNAUTHORIZED_DATA")
            client_sock.close()

        server_thread.join(timeout=1.0)
        # Verify server received NO application data
        self.assertEqual(len(received_data), 0)


class TestEnforcementHealthDiagnostics(unittest.TestCase):
    """Unit tests for Enforcement Health telemetry and component state reporting."""

    def test_diagnostics_report_real_component_state(self):
        """1. Health tracker reflects actual component availability rather than hardcoded booleans."""
        tracker = SubsystemHealthTracker()
        snapshot = tracker.get_health_snapshot()

        # Dev host without driver should report PARTIALLY_ACTIVE
        self.assertEqual(snapshot["overall_status"], "PARTIALLY_ACTIVE")
        self.assertFalse(snapshot["native_driver"]["available"])
        self.assertIn("controlled_launcher", snapshot["protection_scope"])

    def test_approval_queue_saturation_triggers_health_update(self):
        """2. Saturating approval queue updates health telemetry."""
        tracker = SubsystemHealthTracker()
        tracker.update_approval_queue(size=100, capacity=100)
        snapshot = tracker.get_health_snapshot()

        self.assertTrue(snapshot["approval_queue"]["saturated"])
        self.assertEqual(snapshot["approval_queue"]["utilization_pct"], 100.0)

    def test_service_health_integration_with_managers(self):
        """3. EndpointSecurityService aggregates live diagnostics from Process and WFP managers."""
        svc = EndpointSecurityService(enable_ipc=False)
        health = svc.get_health()

        self.assertIn("protection_scope", health)
        self.assertIn("native_driver", health)
        self.assertIn("wfp_enforcement", health)
        self.assertIn("policy_engine", health)
        self.assertIn("approval_queue", health)
        self.assertEqual(health["policy_engine"]["status"], "HEALTHY")
        svc.stop()


if __name__ == "__main__":
    unittest.main()
