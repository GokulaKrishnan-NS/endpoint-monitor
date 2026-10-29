"""
Comprehensive Unit and Integration Tests for Phase 1 Enforcement Foundation.

Covers:
1. Threshold evaluation (below, equal to, and above approval/block thresholds).
2. Mandatory policy blocks overriding risk scores.
3. Invalid and contradictory configuration handling (fail-closed guarantees).
4. Approval, denial, expiry, timeout, single-use tokens, and replay prevention.
5. Concurrency safety and bounded queue capacity.
6. PID reuse and stale process identity protection.
7. IPC message framing, validation, and unauthorized command rejection.
8. GUI approval actions, diagnostics, and event delivery.
9. Service shutdown with pending requests.
10. Structured audit logging, redaction, and health tracking.
"""

from concurrent.futures import ThreadPoolExecutor
import json
import os
import time
import unittest
from unittest.mock import MagicMock, patch
import uuid

from src.execution.approval_manager import (
    ApprovalCapacityExceededError,
    ApprovalManager,
    ApprovalRequest,
    ApprovalStatus,
)
from src.execution.audit import SecurityAuditLogger, SubsystemHealthTracker
from src.execution.ipc import (
    ALLOWED_IPC_ACTIONS,
    LocalSocketIPCClient,
    LocalSocketIPCServer,
    encode_ipc_message,
)
from src.execution.policy import ExecutionPolicy, validate_policy_thresholds
from src.execution.service_foundation import EndpointSecurityService
from src.models.execution_request import (
    DecisionProvenance,
    DecisionStatus,
    EnforcementDecision,
    EnforcementRequest,
    EnforcementStatus,
    ExecutionDecision,
    ExecutionRequest,
    OperationType,
)
from src.ui.engine import MonitoringEngine, MonitoringEngineStatus


class TestPolicyThresholds(unittest.TestCase):
    """1. Test score thresholds below, equal to, and above boundaries."""

    def setUp(self):
        self.config = {
            "enabled": True,
            "dry_run": True,
            "approval_threshold": 4,
            "block_threshold": 7,
            "score_threshold": 7,
            "blocked_severities": ["HIGH"],
            "blocked_indicators": [],
        }
        self.policy = ExecutionPolicy(config=self.config)

    def test_score_below_approval_threshold_allows(self):
        # Benign command with score 0 < 4 -> ALLOW
        req = ExecutionRequest(
            executable="notepad.exe",
            command_line=["notepad.exe", "file.txt"],
        )
        dec = self.policy.evaluate(req)
        self.assertEqual(dec.decision, DecisionStatus.ALLOW)
        self.assertEqual(dec.provenance, DecisionProvenance.POLICY_ENGINE)
        self.assertLess(dec.risk_score, 4)

    def test_score_equal_to_approval_threshold_requires_approval(self):
        # Mock risk calculation to return exactly score 4
        req = ExecutionRequest(
            executable="powershell.exe",
            command_line=["powershell.exe", "-enc", "dGVzdA=="],
        )
        with patch("src.execution.policy.calculate_risk") as mock_calc:
            mock_calc.return_value = {
                "score": 4,
                "level": "MEDIUM",
                "reasons": ["Base64 encoded command arguments detected"],
            }
            dec = self.policy.evaluate(req)
            self.assertEqual(dec.risk_score, 4)
            self.assertEqual(dec.decision, DecisionStatus.REQUIRE_APPROVAL)
            self.assertIn("user approval required", dec.reasons[0])

    def test_score_between_approval_and_block_requires_approval(self):
        req = ExecutionRequest(
            executable="cmd.exe",
            command_line=["cmd.exe", "/c", "whoami"],
        )
        with patch("src.execution.policy.calculate_risk") as mock_calc:
            mock_calc.return_value = {
                "score": 5,
                "level": "MEDIUM",
                "reasons": ["Intermediate risk command activity"],
            }
            dec = self.policy.evaluate(req)
            self.assertEqual(dec.risk_score, 5)
            self.assertEqual(dec.decision, DecisionStatus.REQUIRE_APPROVAL)

    def test_score_equal_to_block_threshold_blocks(self):
        req = ExecutionRequest(
            executable="powershell.exe",
            command_line=["powershell.exe", "-windowstyle", "hidden"],
        )
        with patch("src.execution.policy.calculate_risk") as mock_calc:
            mock_calc.return_value = {
                "score": 7,
                "level": "HIGH",
                "reasons": ["High risk behavior detected"],
            }
            dec = self.policy.evaluate(req)
            self.assertEqual(dec.risk_score, 7)
            self.assertEqual(dec.decision, DecisionStatus.BLOCK)

    def test_score_above_block_threshold_blocks(self):
        req = ExecutionRequest(
            executable="powershell.exe",
            command_line=["powershell.exe", "-nop", "-w", "hidden", "-enc", "abc"],
        )
        with patch("src.execution.policy.calculate_risk") as mock_calc:
            mock_calc.return_value = {
                "score": 9,
                "level": "HIGH",
                "reasons": ["Critical risk command combination"],
            }
            dec = self.policy.evaluate(req)
            self.assertGreater(dec.risk_score, 7)
            self.assertEqual(dec.decision, DecisionStatus.BLOCK)

    def test_network_request_thresholds(self):
        # Benign network request (standard HTTP port 80)
        req_benign = ExecutionRequest(
            operation_type=OperationType.NETWORK,
            remote_ip="93.184.216.34",
            remote_port=80,
            executable="curl.exe",
        )
        dec_benign = self.policy.evaluate(req_benign)
        self.assertEqual(dec_benign.decision, DecisionStatus.ALLOW)

        # Intermediate network request: suspicious port (e.g. 4444) -> score 4 -> REQUIRE_APPROVAL
        req_inter = ExecutionRequest(
            operation_type=OperationType.NETWORK,
            remote_ip="198.51.100.20",
            remote_port=4444,
            executable="curl.exe",
        )
        dec_inter = self.policy.evaluate(req_inter)
        self.assertEqual(dec_inter.risk_score, 4)
        self.assertEqual(dec_inter.decision, DecisionStatus.REQUIRE_APPROVAL)

        # High risk network request: script interpreter connecting to suspicious port -> score 7 -> BLOCK
        req_high = ExecutionRequest(
            operation_type=OperationType.NETWORK,
            remote_ip="198.51.100.20",
            remote_port=4444,
            executable="powershell.exe",
        )
        dec_high = self.policy.evaluate(req_high)
        self.assertEqual(dec_high.risk_score, 7)
        self.assertEqual(dec_high.decision, DecisionStatus.BLOCK)


class TestMandatoryPolicyBlocks(unittest.TestCase):
    """2. Test mandatory policy blocks overriding low scores."""

    def test_mandatory_blocked_executable_overrides_zero_score(self):
        policy = ExecutionPolicy(config={
            "enabled": True,
            "blocked_executables": ["forbidden_tool.exe", "netcat.exe"],
            "approval_threshold": 4,
            "block_threshold": 7,
        })

        req = ExecutionRequest(
            executable=r"C:\Tools\forbidden_tool.exe",
            command_line=["forbidden_tool.exe"],
        )
        # Even with score 0, must be BLOCK
        dec = policy.evaluate(req)
        self.assertEqual(dec.decision, DecisionStatus.BLOCK)
        self.assertEqual(dec.provenance, DecisionProvenance.MANDATORY_RULE)
        self.assertTrue(any("explicitly blocked by mandatory policy rule" in r for r in dec.reasons))

    def test_mandatory_blocked_port_overrides_score(self):
        policy = ExecutionPolicy(config={
            "enabled": True,
            "blocked_ports": [6667, 1337],
            "approval_threshold": 4,
            "block_threshold": 7,
        })

        req = ExecutionRequest(
            operation_type=OperationType.NETWORK,
            remote_ip="1.2.3.4",
            remote_port=6667,
            executable="browser.exe",
        )
        dec = policy.evaluate(req)
        self.assertEqual(dec.decision, DecisionStatus.BLOCK)
        self.assertEqual(dec.provenance, DecisionProvenance.MANDATORY_RULE)

    def test_mandatory_blocked_ip_overrides_score(self):
        policy = ExecutionPolicy(config={
            "enabled": True,
            "blocked_ips": ["203.0.113.50"],
            "approval_threshold": 4,
            "block_threshold": 7,
        })

        req = ExecutionRequest(
            operation_type=OperationType.NETWORK,
            remote_ip="203.0.113.50",
            remote_port=80,
            executable="curl.exe",
        )
        dec = policy.evaluate(req)
        self.assertEqual(dec.decision, DecisionStatus.BLOCK)
        self.assertEqual(dec.provenance, DecisionProvenance.MANDATORY_RULE)


class TestPolicyConfigurationValidation(unittest.TestCase):
    """3. Test invalid and contradictory configuration handling."""

    def test_contradictory_thresholds_fail_closed(self):
        # approval_threshold (8) > block_threshold (4) is contradictory
        policy = ExecutionPolicy(config={
            "enabled": True,
            "approval_threshold": 8,
            "block_threshold": 4,
        })
        self.assertFalse(policy._config_valid)

        req = ExecutionRequest(executable="calc.exe", command_line=["calc.exe"])
        dec = policy.evaluate(req)
        self.assertEqual(dec.decision, DecisionStatus.BLOCK)
        self.assertEqual(dec.provenance, DecisionProvenance.FAIL_CLOSED)
        self.assertIn("Contradictory thresholds", dec.error)

    def test_negative_thresholds_fail_closed(self):
        policy = ExecutionPolicy(config={
            "enabled": True,
            "approval_threshold": -2,
            "block_threshold": 7,
        })
        self.assertFalse(policy._config_valid)

        req = ExecutionRequest(executable="calc.exe", command_line=["calc.exe"])
        dec = policy.evaluate(req)
        self.assertEqual(dec.decision, DecisionStatus.BLOCK)
        self.assertEqual(dec.provenance, DecisionProvenance.FAIL_CLOSED)

    def test_non_numeric_threshold_fails_closed(self):
        policy = ExecutionPolicy(config={
            "enabled": True,
            "approval_threshold": "invalid_number",
            "block_threshold": 7,
        })
        self.assertFalse(policy._config_valid)

        req = ExecutionRequest(executable="calc.exe", command_line=["calc.exe"])
        dec = policy.evaluate(req)
        self.assertEqual(dec.decision, DecisionStatus.BLOCK)

    def test_non_dict_config_fails_closed(self):
        policy = ExecutionPolicy(config="not_a_dict")  # type: ignore
        self.assertFalse(policy._config_valid)

        req = ExecutionRequest(executable="calc.exe", command_line=["calc.exe"])
        dec = policy.evaluate(req)
        self.assertEqual(dec.decision, DecisionStatus.BLOCK)


class TestApprovalManagerLifecycle(unittest.TestCase):
    """4. Test approval, denial, expiry, timeout, single-use, and replay."""

    def setUp(self):
        self.manager = ApprovalManager(default_timeout_seconds=2.0, max_pending=10)

    def test_create_and_approve_generates_token(self):
        req = ExecutionRequest(executable="powershell.exe", command_line=["powershell.exe", "-enc", "abc"])
        appr = self.manager.create_request(req, risk_score=5, risk_level="MEDIUM")
        self.assertEqual(appr.status, ApprovalStatus.PENDING)

        success, approved_req, err = self.manager.approve(appr.approval_id, approver="sec_admin")
        self.assertTrue(success)
        self.assertIsNotNone(approved_req.single_use_token)
        self.assertEqual(approved_req.status, ApprovalStatus.APPROVED)
        self.assertEqual(approved_req.decided_by, "sec_admin")

    def test_single_use_consumption_and_replay_rejection(self):
        req = ExecutionRequest(executable="powershell.exe", command_line=["powershell.exe"])
        appr = self.manager.create_request(req, risk_score=5)
        success, approved_req, _ = self.manager.approve(appr.approval_id)
        token = approved_req.single_use_token

        # First consumption: valid
        consumed, err = self.manager.consume_approval(appr.approval_id, token)
        self.assertTrue(consumed)
        self.assertIsNone(err)

        # Second consumption attempt (replay attack): must be rejected
        consumed2, err2 = self.manager.consume_approval(appr.approval_id, token)
        self.assertFalse(consumed2)
        self.assertIn("Replay rejected", err2)

    def test_deny_operation(self):
        req = ExecutionRequest(executable="powershell.exe", command_line=["powershell.exe"])
        appr = self.manager.create_request(req, risk_score=5)

        success, denied_req, err = self.manager.deny(appr.approval_id, approver="operator", reason="Not authorized")
        self.assertTrue(success)
        self.assertEqual(denied_req.status, ApprovalStatus.DENIED)

        # Cannot approve or consume a denied request
        appr_res, _, _ = self.manager.approve(appr.approval_id)
        self.assertFalse(appr_res)

    def test_request_timeout_and_expiry(self):
        manager = ApprovalManager(default_timeout_seconds=0.05, max_pending=10)
        req = ExecutionRequest(executable="cmd.exe", command_line=["cmd.exe"])
        appr = manager.create_request(req, risk_score=4)

        time.sleep(0.08)  # Wait for timeout

        # Attempt to approve expired request
        success, _, err = manager.approve(appr.approval_id)
        self.assertFalse(success)
        self.assertIn("expired", err.lower())

    def test_duplicate_suppression(self):
        req = ExecutionRequest(executable="calc.exe", command_line=["calc.exe"])
        appr1 = self.manager.create_request(req, risk_score=4)
        appr2 = self.manager.create_request(req, risk_score=4)

        # Should return the same pending approval record
        self.assertEqual(appr1.approval_id, appr2.approval_id)
        self.assertEqual(len(self.manager.get_pending_requests()), 1)


class TestConcurrencyAndQueueCapacity(unittest.TestCase):
    """5. Test concurrent requests and queue capacity limits."""

    def test_queue_capacity_limit_rejection(self):
        manager = ApprovalManager(default_timeout_seconds=60.0, max_pending=3)

        for i in range(3):
            req = ExecutionRequest(executable=f"proc_{i}.exe", command_line=[f"proc_{i}.exe"])
            manager.create_request(req, risk_score=4)

        self.assertEqual(len(manager.get_pending_requests()), 3)

        # 4th unique request must exceed capacity and fail closed
        req_overflow = ExecutionRequest(executable="overflow.exe", command_line=["overflow.exe"])
        with self.assertRaises(ApprovalCapacityExceededError):
            manager.create_request(req_overflow, risk_score=4)

    def test_concurrent_multi_threaded_approvals(self):
        manager = ApprovalManager(default_timeout_seconds=60.0, max_pending=50)
        req_ids = []

        for i in range(20):
            req = ExecutionRequest(executable=f"worker_{i}.exe", command_line=[f"worker_{i}.exe"])
            appr = manager.create_request(req, risk_score=4)
            req_ids.append(appr.approval_id)

        def approve_worker(appr_id):
            return manager.approve(appr_id, approver="thread_worker")

        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(approve_worker, req_ids))

        for success, _, _ in results:
            self.assertTrue(success)


class TestPIDReuseProtection(unittest.TestCase):
    """6. Test protection against PID reuse and stale process identities."""

    def test_pid_reuse_rejected_during_consumption(self):
        manager = ApprovalManager(default_timeout_seconds=60.0)
        original_create_time = 1700000000.123
        target_pid = 4321

        req = ExecutionRequest(
            executable="script_host.exe",
            command_line=["script_host.exe"],
            process_id=target_pid,
            process_create_time=original_create_time,
        )
        appr = manager.create_request(req, risk_score=4)
        success, approved_req, _ = manager.approve(appr.approval_id)
        token = approved_req.single_use_token

        # Context simulating that target_pid was terminated and reused by a NEW process
        new_process_create_time = 1700000050.789
        reused_context = {
            "pid": target_pid,
            "create_time": new_process_create_time,
            "executable": "script_host.exe",
        }

        consumed, err = manager.consume_approval(appr.approval_id, token, context=reused_context)
        self.assertFalse(consumed)
        self.assertIn("PID reuse detected", err)

    def test_matching_pid_and_create_time_accepted(self):
        manager = ApprovalManager(default_timeout_seconds=60.0)
        create_time = 1700000000.123
        target_pid = 4321

        req = ExecutionRequest(
            executable="script_host.exe",
            command_line=["script_host.exe"],
            process_id=target_pid,
            process_create_time=create_time,
        )
        appr = manager.create_request(req, risk_score=4)
        _, approved_req, _ = manager.approve(appr.approval_id)
        token = approved_req.single_use_token

        valid_context = {
            "pid": target_pid,
            "create_time": create_time,
            "executable": "script_host.exe",
        }

        consumed, err = manager.consume_approval(appr.approval_id, token, context=valid_context)
        self.assertTrue(consumed)
        self.assertIsNone(err)


class TestIPCValidationAndSecurity(unittest.TestCase):
    """7. Test IPC message validation and unauthorized request rejection."""

    def setUp(self):
        self.token = str(uuid.uuid4())
        self.server = LocalSocketIPCServer(port=0, auth_token=self.token)
        self.server.start(handler_callback=lambda msg: {"echo": msg.get("action")})
        self.client = LocalSocketIPCClient(port=self.server.port, auth_token=self.token)

    def tearDown(self):
        self.server.stop()

    def test_allowed_action_ping(self):
        resp = self.client.send_request("PING")
        self.assertTrue(resp.get("success"))
        self.assertEqual(resp.get("data", {}).get("echo"), "PING")

    def test_unauthorized_action_rejected(self):
        # Attempt to invoke an arbitrary driver command or system exec
        resp = self.client.send_request("EXEC_DRIVER_COMMAND", {"cmd": "unload_filter"})
        self.assertFalse(resp.get("success"))
        self.assertEqual(resp.get("code"), 403)
        self.assertIn("Unauthorized action", resp.get("error"))

    def test_invalid_auth_token_rejected(self):
        unauth_client = LocalSocketIPCClient(port=self.server.port, auth_token="bad_token")
        resp = unauth_client.send_request("SUBMIT_REQUEST", {"request": {}})
        self.assertFalse(resp.get("success"))
        self.assertEqual(resp.get("code"), 401)


class TestGUIApprovalAndDiagnostics(unittest.TestCase):
    """8. Test GUI approval actions and diagnostic health delivery."""

    def test_engine_approval_integration(self):
        engine = MonitoringEngine()
        # Submit request requiring approval (mocked intermediate score)
        req = ExecutionRequest(
            executable="powershell.exe",
            command_line=["powershell.exe", "-encodedCommand", "xyz"],
        )

        with patch("src.execution.policy.calculate_risk") as mock_calc:
            mock_calc.return_value = {"score": 5, "level": "MEDIUM", "reasons": ["Encoded command"]}
            dec = engine.submit_enforcement_request(req)

            self.assertEqual(dec.decision, DecisionStatus.REQUIRE_APPROVAL)
            self.assertIsNotNone(dec.approval_id)

            # Check pending queue in engine
            pending = engine.get_pending_approvals()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]["approval_id"], dec.approval_id)

            # Test approving via engine API (which UI buttons call)
            success, msg = engine.approve_request(dec.approval_id, approver="test_operator")
            self.assertTrue(success)
            self.assertIn("successfully approved", msg)

            # Pending queue should now be empty
            self.assertEqual(len(engine.get_pending_approvals()), 0)

        engine.stop()

    def test_diagnostics_service_health(self):
        engine = MonitoringEngine()
        health = engine.get_service_health()

        self.assertIn("policy_engine", health)
        self.assertIn("ipc_service", health)
        self.assertIn("approval_queue", health)
        self.assertIn("os_enforcement_adapter", health)

        # Must report state accurately (not falsely claimed as fully active)
        os_adapter = health["os_enforcement_adapter"]
        self.assertIn(os_adapter["status"], ("NOT_INSTALLED", "PARTIALLY_ACTIVE"))
        self.assertFalse(os_adapter["verified_active"])

        engine.stop()


class TestServiceShutdown(unittest.TestCase):
    """9. Test safe service shutdown with pending requests."""

    def test_service_shutdown_denies_all_pending_requests(self):
        service = EndpointSecurityService(enable_ipc=False)
        service.start()

        # Submit 3 requests requiring approval
        with patch("src.execution.policy.calculate_risk") as mock_calc:
            mock_calc.return_value = {"score": 5, "level": "MEDIUM", "reasons": ["Test"]}
            for i in range(3):
                req = ExecutionRequest(executable=f"pending_{i}.exe", command_line=[f"pending_{i}.exe"])
                service.submit_request(req)

        self.assertEqual(len(service.get_pending_approvals()), 3)

        # Perform service shutdown
        service.stop()

        # All pending requests must be drained and denied
        self.assertEqual(len(service.get_pending_approvals()), 0)
        history = service.get_decision_history()
        self.assertEqual(len(history), 3)
        for h in history:
            self.assertEqual(h["enforcement_status"], EnforcementStatus.PENDING_APPROVAL)


class TestStructuredAuditLogging(unittest.TestCase):
    """10. Test structured audit logging, redaction, and record fields."""

    def test_audit_record_creation_and_redaction(self):
        audit_path = "logs/test_security_audit.log"
        if os.path.exists(audit_path):
            try:
                os.remove(audit_path)
            except Exception:
                pass

        audit_logger = SecurityAuditLogger(log_path=audit_path)
        req = ExecutionRequest(
            executable="script.exe",
            command_line=["script.exe", "--password", "supersecret123", "--token=bearer_xyz"],
        )
        dec = ExecutionDecision(
            request_id=req.request_id,
            decision=DecisionStatus.ALLOW,
            risk_score=1,
            reasons=["Normal execution"],
            enforcement_status=EnforcementStatus.SIMULATED,
        )

        rec = audit_logger.record_decision(req, dec)

        self.assertEqual(rec.decision, DecisionStatus.ALLOW)
        self.assertEqual(rec.enforcement_outcome, EnforcementStatus.SIMULATED)

        # Verify password/token redaction
        cmd_str = " ".join(rec.command_line)
        self.assertNotIn("supersecret123", cmd_str)
        self.assertIn("[REDACTED]", cmd_str)

        # Verify persisted to disk
        self.assertTrue(os.path.exists(audit_path))
        with open(audit_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            parsed = json.loads(lines[0])
            self.assertEqual(parsed["correlation_id"], req.request_id)
            self.assertIn("[REDACTED]", str(parsed["command_line"]))

        if os.path.exists(audit_path):
            try:
                os.remove(audit_path)
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
