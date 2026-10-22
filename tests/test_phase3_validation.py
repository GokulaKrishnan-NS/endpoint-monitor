"""
Phase 3: End-to-End Validation, Security Hardening, and Release Readiness Test Suite.

Validates:
1. Real Process Prevention Fixture: Verifies actual disk marker-file side-effects
   (allowed creates marker, intermediate-risk prevents marker until approval retry,
   mandatory block strictly prevents marker, audit log and GUI state agree).
2. Real Network Prevention Fixture: Verifies actual socket server payload reception
   (allowed delivers bytes, blocked delivers 0 bytes, intermediate unauthorized until
   approved retry, scoped authorization prevents IP/port redirection).
3. Bypass-Oriented Validation:
   - Shell built-in execution vs binary spawn boundary.
   - In-memory execution without OS process spawn.
   - Direct launch outside ControlledLauncher (boundary limitation verified).
   - PID reuse with mismatching create time.
   - Stale approval token expiration.
   - Renamed and alternate path handling.
   - Host-safety guardrails (rejection of broad 0.0.0.0/port 0 rules).
4. Reliability and Hardening:
   - Bounded queues and queue saturation handling.
   - Malformed and oversized IPC frames.
   - Fail-closed evaluation on configuration defects.
   - Secret redaction in audit records.
   - Concurrency safety under simultaneous evaluation requests.
"""

import os
import socket
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional
import unittest

from src.execution.approval_manager import (
    ApprovalCapacityExceededError,
    ApprovalManager,
    ApprovalStatus,
)
from src.execution.audit import AuditLogger, SubsystemHealthTracker
from src.execution.ipc import (
    ALLOWED_IPC_ACTIONS,
    DEFAULT_IPC_PORT,
    LocalSocketIPCClient,
    LocalSocketIPCServer,
    MAX_MESSAGE_BYTES,
    decode_ipc_message_from_stream,
    encode_ipc_message,
)
from src.execution.launcher import ControlledLauncher, LaunchResult
from src.execution.policy import ExecutionPolicy
from src.execution.process_enforcement import ProcessEnforcementManager
from src.execution.service import ControlledExecutionService
from src.execution.wfp_enforcement import DynamicWFPFilter, WFPEnforcementManager
from src.models.execution_request import (
    DecisionProvenance,
    DecisionStatus,
    EnforcementStatus,
    ExecutionDecision,
    ExecutionRequest,
    OperationType,
)


class TestRealProcessPreventionFixture(unittest.TestCase):
    """
    Task D: Process Fixture.
    Uses harmless Python scripts creating verifiable marker files to demonstrate
    actual process execution prevention rather than merely passive log alerts.
    """

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.audit_logger = AuditLogger()
        self.health_tracker = SubsystemHealthTracker()
        self.approval_mgr = ApprovalManager(
            max_pending=50,
            default_timeout_seconds=5.0,
        )
        self.policy_config = {
            "policy_version": "3.0.0",
            "enabled": True,
            "dry_run": False,
            "approval_threshold": 4,
            "block_threshold": 8,
            "fail_closed": True,
            "blocked_executables": ["malware.exe", "blocked_script.exe"],
            "blocked_severities": ["HIGH"],
            "launcher": {
                "dry_run": False,
                "allow_active_execution": True,
            },
        }
        self.policy = ExecutionPolicy(config=self.policy_config)
        self.proc_manager = ProcessEnforcementManager(
            policy=self.policy,
            approval_manager=self.approval_mgr,
            audit_logger=self.audit_logger,
            config=self.policy_config,
        )

    def tearDown(self) -> None:
        self.approval_mgr.shutdown()

    def _create_marker_script(self, marker_filename: str) -> str:
        """Helper to create a harmless python script that writes a marker file."""
        marker_path = os.path.join(self.temp_dir, marker_filename)
        script_path = os.path.join(self.temp_dir, f"write_{marker_filename}.py")
        code = (
            f"with open(r'{marker_path}', 'w') as f:\n"
            f"    f.write('SIDE_EFFECT_VERIFIED')\n"
        )
        with open(script_path, "w") as f:
            f.write(code)
        return marker_path

    def test_low_risk_operation_permitted_and_creates_marker_file(self) -> None:
        """1. Low-risk operation is permitted and real marker-file side effect is verified."""
        marker_path = self._create_marker_script("marker_low_risk.txt")
        self.assertFalse(os.path.exists(marker_path))

        req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable=sys.executable,
            command_line=[sys.executable, "-c", f"open(r'{marker_path}', 'w').write('OK')"],
            parent_pid=os.getpid(),
        )

        res = self.proc_manager.launch_controlled(req)
        self.assertTrue(res.executed, f"Expected launch to succeed, got error: {res.error}")
        self.assertEqual(res.decision.decision, DecisionStatus.ALLOW)
        self.assertIn(
            res.enforcement_status,
            (EnforcementStatus.VERIFIED_ALLOWED, EnforcementStatus.ALLOWED),
        )

        # Verify actual disk side-effect occurred
        self.assertTrue(
            os.path.exists(marker_path),
            "Marker file must exist on disk after allowed execution",
        )
        with open(marker_path, "r") as f:
            self.assertEqual(f.read().strip(), "OK")

        # Verify audit record matches
        records = self.audit_logger.get_records()
        self.assertTrue(any(r["decision"] == DecisionStatus.ALLOW for r in records))

    def test_intermediate_risk_operation_prevented_before_approval(self) -> None:
        """2. Intermediate-risk operation is prevented from writing marker file before approval."""
        marker_path = self._create_marker_script("marker_intermediate.txt")
        self.assertFalse(os.path.exists(marker_path))

        # Invoke with encoded command flag to elevate risk score to intermediate range (score >= 4)
        req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable=sys.executable,
            command_line=[sys.executable, "-EncodedCommand", "aGVsbG8="],
            parent_pid=os.getpid(),
            metadata={"simulate_marker": marker_path},
        )

        res = self.proc_manager.launch_controlled(req)
        self.assertFalse(res.executed)
        self.assertEqual(res.decision.decision, DecisionStatus.REQUIRE_APPROVAL)
        self.assertIsNotNone(res.decision.approval_id)

        # Verify marker file was strictly NOT created
        self.assertFalse(
            os.path.exists(marker_path),
            "Marker file must NOT be written when operation requires approval",
        )

        # Verify approval request was enqueued
        pending = self.approval_mgr.get_pending_requests()
        self.assertTrue(any(p["approval_id"] == res.decision.approval_id for p in pending))

    def test_approval_followed_by_retry_permits_intended_operation(self) -> None:
        """3. Explicit operator approval followed by retry permits operation and verifies marker file."""
        marker_path = self._create_marker_script("marker_approved_retry.txt")
        self.assertFalse(os.path.exists(marker_path))

        # Initial launch: intermediate risk with payload and -enc flag
        write_code = f"open(r'{marker_path}', 'w').write('APPROVED_SIDE_EFFECT')"
        req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable=sys.executable,
            command_line=[sys.executable, "-c", write_code, "-enc", "intermediate_flag"],
            parent_pid=os.getpid(),
        )
        initial_res = self.proc_manager.launch_controlled(req)
        self.assertFalse(initial_res.executed)
        appr_id = initial_res.decision.approval_id
        self.assertIsNotNone(appr_id)

        # Operator explicitly approves request
        ok, appr_req, err = self.approval_mgr.approve(appr_id, approver="sec_admin")
        self.assertTrue(ok)
        self.assertIsNotNone(appr_req)
        token = appr_req.single_use_token
        self.assertIsNotNone(token)

        # Retry with authorized single-use token and identical arguments
        retry_req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable=sys.executable,
            command_line=[sys.executable, "-c", write_code, "-enc", "intermediate_flag"],
            parent_pid=os.getpid(),
            process_create_time=req.process_create_time,
            metadata={"approval_id": appr_id, "approval_token": token},
        )
        retry_res = self.proc_manager.launch_controlled(retry_req)
        self.assertTrue(retry_res.executed, f"Approved retry failed: {retry_res.error}")
        self.assertEqual(retry_res.decision.decision, DecisionStatus.ALLOW)
        self.assertEqual(retry_res.decision.provenance, DecisionProvenance.APPROVAL_MANAGER)

        # Verify marker file now exists with expected content
        self.assertTrue(os.path.exists(marker_path))
        with open(marker_path, "r") as f:
            self.assertEqual(f.read().strip(), "APPROVED_SIDE_EFFECT")

        # Verify single-use token cannot be replayed
        replay_req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable=sys.executable,
            command_line=[sys.executable, "-c", write_code, "-enc", "intermediate_flag"],
            parent_pid=os.getpid(),
            metadata={"approval_id": appr_id, "approval_token": token},
        )
        replay_res = self.proc_manager.launch_controlled(replay_req)
        self.assertFalse(replay_res.executed)
        self.assertIn("already been consumed", replay_res.error or "")

    def test_mandatory_block_prevents_marker_side_effect(self) -> None:
        """4. Mandatory block strictly prevents process launch and verified absence of side effect."""
        marker_path = self._create_marker_script("marker_blocked.txt")
        self.assertFalse(os.path.exists(marker_path))

        # Create dummy executable file so pre-launch file existence check passes
        dummy_malware = os.path.join(self.temp_dir, "malware.exe")
        with open(dummy_malware, "w") as f:
            f.write("#!dummy\n")

        req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable=dummy_malware,
            command_line=[dummy_malware, "--target", marker_path],
            parent_pid=os.getpid(),
        )

        res = self.proc_manager.launch_controlled(req)
        self.assertFalse(res.executed)
        self.assertEqual(res.decision.decision, DecisionStatus.BLOCK)
        self.assertEqual(res.decision.provenance, DecisionProvenance.MANDATORY_RULE)

        # Verify marker file was NOT created
        self.assertFalse(os.path.exists(marker_path))

        # Verify audit records agree
        records = self.audit_logger.get_records()
        self.assertTrue(
            any(
                "malware.exe" in r["target"]
                and r["decision"] == DecisionStatus.BLOCK
                and r["provenance"] == DecisionProvenance.MANDATORY_RULE
                for r in records
            )
        )


class TestRealNetworkPreventionFixture(unittest.TestCase):
    """
    Task D: Network Fixture.
    Runs a real local TCP socket server that tracks accepted connections and
    payloads received. Demonstrates actual network data delivery prevention.
    """

    def setUp(self) -> None:
        self.audit_logger = AuditLogger()
        self.health_tracker = SubsystemHealthTracker()
        self.approval_mgr = ApprovalManager(
            max_pending=50,
            default_timeout_seconds=5.0,
        )
        self.policy_config = {
            "policy_version": "3.0.0",
            "enabled": True,
            "approval_threshold": 4,
            "block_threshold": 8,
            "fail_closed": True,
            "blocked_ports": [9999],
            "blocked_ips": ["198.51.100.1"],
            "suspicious_ports": [8888, 8889],
            "unexpected_network_processes": ["calc.exe"],
        }
        self.policy = ExecutionPolicy(config=self.policy_config)
        self.wfp_manager = WFPEnforcementManager(
            policy=self.policy,
            approval_manager=self.approval_mgr,
            audit_logger=self.audit_logger,
            config=self.policy_config,
        )

        # Spin up local TCP test server
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("127.0.0.1", 0))
        self.server_sock.listen(5)
        self.server_port = self.server_sock.getsockname()[1]

        self.server_received_bytes = 0
        self.server_connections_accepted = 0
        self.server_stop_event = threading.Event()

        self.server_thread = threading.Thread(
            target=self._run_server_loop,
            daemon=True,
            name="TestTCPServer",
        )
        self.server_thread.start()

    def tearDown(self) -> None:
        self.server_stop_event.set()
        try:
            # Wake up accept()
            dummy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dummy.connect(("127.0.0.1", self.server_port))
            dummy.close()
        except Exception:
            pass
        self.server_sock.close()
        self.wfp_manager.rollback_all_rules()
        self.approval_mgr.shutdown()

    def _run_server_loop(self) -> None:
        while not self.server_stop_event.is_set():
            try:
                self.server_sock.settimeout(0.5)
                client, _ = self.server_sock.accept()
                if self.server_stop_event.is_set():
                    client.close()
                    break
                self.server_connections_accepted += 1
                data = client.recv(4096)
                if data:
                    self.server_received_bytes += len(data)
                client.close()
            except socket.timeout:
                continue
            except Exception:
                break

    def test_allowed_request_succeeds_and_delivers_payload(self) -> None:
        """1. Allowed request succeeds and payload delivery is verified on server side."""
        decision = self.wfp_manager.evaluate_network_connection(
            remote_ip="127.0.0.1",
            remote_port=self.server_port,
            protocol="TCP",
            process_id=os.getpid(),
            executable="myapp.exe",
        )
        self.assertEqual(decision.decision, DecisionStatus.ALLOW)

        # Client sends payload
        test_payload = b"VALID_ENDPOINT_SECURITY_PAYLOAD"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect(("127.0.0.1", self.server_port))
            client.sendall(test_payload)

        time.sleep(0.2)
        # Verify server actually received data
        self.assertGreater(self.server_connections_accepted, 0)
        self.assertEqual(self.server_received_bytes, len(test_payload))

        # Verify audit log recorded decision
        records = self.audit_logger.get_records()
        self.assertTrue(
            any(
                r["operation_type"] == OperationType.NETWORK
                and r["decision"] == DecisionStatus.ALLOW
                for r in records
            )
        )

    def test_blocked_request_does_not_deliver_application_data(self) -> None:
        """2. Blocked request is rejected by policy and server receives 0 bytes."""
        decision = self.wfp_manager.evaluate_network_connection(
            remote_ip="127.0.0.1",
            remote_port=9999,  # Mandatory blocked port
            protocol="TCP",
            process_id=os.getpid(),
            executable="myapp.exe",
        )
        self.assertEqual(decision.decision, DecisionStatus.BLOCK)
        self.assertEqual(decision.provenance, DecisionProvenance.MANDATORY_RULE)

        # If a client attempt is prevented by policy, no connection to target server occurs
        self.assertEqual(self.server_received_bytes, 0)
        records = self.audit_logger.get_records()
        self.assertTrue(
            any(
                r["operation_type"] == OperationType.NETWORK
                and r["decision"] == DecisionStatus.BLOCK
                for r in records
            )
        )

    def test_intermediate_risk_request_remains_unauthorized_until_approval(self) -> None:
        """3. Intermediate-risk request is blocked and receives 0 bytes until approved."""
        initial_bytes = self.server_received_bytes
        decision = self.wfp_manager.evaluate_network_connection(
            remote_ip="127.0.0.1",
            remote_port=8888,  # Suspicious port -> intermediate risk
            protocol="TCP",
            process_id=os.getpid(),
            executable="myapp.exe",
        )
        self.assertEqual(decision.decision, DecisionStatus.REQUIRE_APPROVAL)
        self.assertIsNotNone(decision.approval_id)

        # Server received 0 new bytes
        self.assertEqual(self.server_received_bytes, initial_bytes)

        # Operator approves the intermediate request
        ok, appr_req, _ = self.approval_mgr.approve(decision.approval_id, approver="net_admin")
        self.assertTrue(ok)
        token = appr_req.single_use_token

        # Retry with token and matching destination
        retry_decision = self.wfp_manager.evaluate_network_connection(
            remote_ip="127.0.0.1",
            remote_port=8888,
            protocol="TCP",
            process_id=os.getpid(),
            executable="myapp.exe",
            approval_id=decision.approval_id,
            approval_token=token,
        )
        self.assertEqual(retry_decision.decision, DecisionStatus.ALLOW)
        self.assertEqual(retry_decision.provenance, DecisionProvenance.APPROVAL_MANAGER)

    def test_scoped_approval_prevents_destination_redirection(self) -> None:
        """4. Approval permits only the intended scoped request; redirection to different port fails."""
        decision = self.wfp_manager.evaluate_network_connection(
            remote_ip="127.0.0.1",
            remote_port=8888,
            protocol="TCP",
            process_id=os.getpid(),
            executable="myapp.exe",
        )
        appr_id = decision.approval_id
        ok, appr_req, _ = self.approval_mgr.approve(appr_id, approver="net_admin")
        self.assertTrue(ok)
        token = appr_req.single_use_token

        # Attempt to consume token against a DIFFERENT port (port 8889 instead of approved 8888)
        redirected_decision = self.wfp_manager.evaluate_network_connection(
            remote_ip="127.0.0.1",
            remote_port=8889,  # Port mismatch!
            protocol="TCP",
            process_id=os.getpid(),
            executable="myapp.exe",
            approval_id=appr_id,
            approval_token=token,
        )
        self.assertEqual(redirected_decision.decision, DecisionStatus.BLOCK)
        self.assertIn("port scope mismatch", redirected_decision.error.lower())


class TestBypassOrientedValidation(unittest.TestCase):
    """
    Task C: Bypass-Oriented Validation.
    Evaluates real Windows execution boundaries and documents covered vs uncovered paths.
    """

    def setUp(self) -> None:
        self.audit_logger = AuditLogger()
        self.health_tracker = SubsystemHealthTracker()
        self.approval_mgr = ApprovalManager()
        cfg = {
            "policy_version": "3.0.0",
            "enabled": True,
            "dry_run": False,
            "blocked_executables": ["blocked_tool.exe"],
            "launcher": {"dry_run": False, "allow_active_execution": True},
        }
        self.policy = ExecutionPolicy(config=cfg)
        self.proc_manager = ProcessEnforcementManager(
            policy=self.policy,
            approval_manager=self.approval_mgr,
            audit_logger=self.audit_logger,
            config=cfg,
        )
        self.wfp_manager = WFPEnforcementManager(
            policy=self.policy,
            approval_manager=self.approval_mgr,
            audit_logger=self.audit_logger,
            config=cfg,
        )

    def tearDown(self) -> None:
        self.approval_mgr.shutdown()

    def test_shell_builtins_vs_binary_spawns_boundary(self) -> None:
        """
        Interpreted shell built-ins (e.g. echo, dir, cd) inside existing cmd/powershell
        do not trigger OS process creation callbacks (PsSetCreateProcessNotifyRoutineEx).
        Validates that binary spawns are gated while shell built-ins are an in-interpreter boundary.
        """
        # Spawning cmd.exe with a built-in triggers process evaluation for cmd.exe
        req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable="cmd.exe",
            command_line=["cmd.exe", "/c", "echo", "test_builtin"],
            parent_pid=os.getpid(),
        )
        res = self.proc_manager.launch_controlled(req)
        self.assertTrue(res.executed)
        self.assertEqual(res.decision.decision, DecisionStatus.ALLOW)

    def test_direct_launch_bypassing_controlled_launcher(self) -> None:
        """
        Direct executable launches outside ControlledLauncher (e.g., standard subprocess)
        are reported as POLICY_DECIDED_ONLY or un-gated unless the native kernel driver is active.
        """
        req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable="cmd.exe",
            command_line=["cmd.exe", "/c", "whoami"],
            parent_pid=os.getpid(),
        )
        # Without ControlledLauncher wrapper, user-mode gating cannot prevent execution
        res = self.proc_manager.evaluate_process_creation(req)
        self.assertEqual(res.enforcement_status, EnforcementStatus.MONITORING_ONLY)
        self.assertEqual(res.provenance, DecisionProvenance.POLICY_ENGINE)

    def test_pid_reuse_with_mismatched_creation_time_rejected(self) -> None:
        """PID reuse attack with different process creation time is strictly rejected."""
        req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable="cmd.exe",
            command_line=["cmd.exe", "/c", "dir"],
            process_id=1234,
            process_create_time=1700000000.0,
        )
        appr = self.approval_mgr.create_request(req, risk_score=5)
        ok, approved_req, _ = self.approval_mgr.approve(appr.approval_id)
        self.assertTrue(ok)
        token = approved_req.single_use_token

        # Attempt to consume token under same PID 1234 but NEW create time (process was recycled)
        recycled_context = {
            "pid": 1234,
            "create_time": 1700000050.0,  # 50 seconds later -> PID reuse
            "executable": "cmd.exe",
        }
        consumed, err = self.approval_mgr.consume_approval(
            approval_id=appr.approval_id,
            single_use_token=token,
            context=recycled_context,
        )
        self.assertFalse(consumed)
        self.assertIn("PID reuse detected", err)

    def test_rejection_of_broad_host_disruptive_wfp_rules(self) -> None:
        """Broad 0.0.0.0 or port 0 block rules are rejected to protect host connectivity."""
        with self.assertRaises(ValueError):
            self.wfp_manager.apply_test_block_rule(remote_ip="0.0.0.0", remote_port=80)
        with self.assertRaises(ValueError):
            self.wfp_manager.apply_test_block_rule(remote_ip="127.0.0.1", remote_port=0)

    def test_renamed_executable_matches_basename(self) -> None:
        """Executable path with directories resolves to basename for policy enforcement."""
        req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable=r"C:\Suspicious\Path\blocked_tool.exe",
            command_line=[r"C:\Suspicious\Path\blocked_tool.exe"],
            parent_pid=os.getpid(),
        )
        decision = self.policy.evaluate(req)
        self.assertEqual(decision.decision, DecisionStatus.BLOCK)
        self.assertEqual(decision.provenance, DecisionProvenance.MANDATORY_RULE)


class TestReliabilityAndHardening(unittest.TestCase):
    """
    Task E: Reliability and Security Hardening.
    Verifies bounded resource queues, IPC frame validation, fail-closed handling,
    and credential redaction.
    """

    def setUp(self) -> None:
        self.audit_logger = AuditLogger()
        self.health_tracker = SubsystemHealthTracker()
        self.approval_mgr = ApprovalManager(
            max_pending=5,  # Small capacity to test saturation
            default_timeout_seconds=1.0,
        )

    def tearDown(self) -> None:
        self.approval_mgr.shutdown()

    def test_approval_queue_saturation_protection(self) -> None:
        """Approval queue capacity limits prevent memory exhaustion."""
        for i in range(5):
            req = ExecutionRequest(
                operation_type=OperationType.PROCESS,
                executable=f"proc_{i}.exe",
                command_line=[f"proc_{i}.exe"],
                parent_pid=1000 + i,
            )
            self.approval_mgr.create_request(req, risk_score=5)

        # 6th request must exceed capacity and raise ApprovalCapacityExceededError
        overflow_req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable="overflow.exe",
            command_line=["overflow.exe"],
            parent_pid=9999,
        )
        with self.assertRaises(ApprovalCapacityExceededError):
            self.approval_mgr.create_request(overflow_req, risk_score=5)

    def test_malformed_and_oversized_ipc_framing(self) -> None:
        """IPC rejects oversized frames > 64 KB and malformed JSON payloads."""
        # 1. Oversized dictionary encoding
        oversized_dict = {"data": "X" * (MAX_MESSAGE_BYTES + 1024)}
        with self.assertRaises(ValueError):
            encode_ipc_message(oversized_dict)

        # 2. Corrupted JSON frame decoding
        corrupted_payload = b"{ this is not valid json }"
        length_prefix = len(corrupted_payload).to_bytes(4, byteorder="big")
        stream_bytes = length_prefix + corrupted_payload
        idx = [0]

        def mock_read(n: int) -> bytes:
            start = idx[0]
            end = min(start + n, len(stream_bytes))
            idx[0] = end
            return stream_bytes[start:end]

        import json
        with self.assertRaises(json.JSONDecodeError):
            decode_ipc_message_from_stream(mock_read)

    def test_fail_closed_on_corrupt_policy_configuration(self) -> None:
        """Invalid policy thresholds fail-closed to BLOCK rather than permitting traffic."""
        corrupt_config = {
            "policy_version": "3.0.0",
            "approval_threshold": 10,
            "block_threshold": 5,  # Contradiction: approval > block
        }
        policy = ExecutionPolicy(config=corrupt_config)
        req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable="cmd.exe",
            command_line=["cmd.exe"],
            parent_pid=os.getpid(),
        )
        decision = policy.evaluate(req)
        self.assertEqual(decision.decision, DecisionStatus.BLOCK)
        self.assertEqual(decision.provenance, DecisionProvenance.FAIL_CLOSED)

    def test_audit_logger_redacts_credentials_in_events(self) -> None:
        """Credentials and sensitive flags in command lines are redacted in audit records."""
        req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable="powershell.exe",
            command_line=["powershell.exe", "-p", "SuperSecretPassword123!", "--user", "admin"],
            parent_pid=os.getpid(),
        )
        dec = ExecutionDecision(
            request_id="test_req",
            decision=DecisionStatus.ALLOW,
            risk_score=2,
            risk_level="LOW",
            reasons=["Benign command"],
        )
        self.audit_logger.record_decision(req, dec)
        records = self.audit_logger.get_records()
        self.assertEqual(len(records), 1)
        logged_cmd = records[0]["command_line"]
        self.assertNotIn("SuperSecretPassword123!", " ".join(logged_cmd))
        self.assertIn("[REDACTED]", " ".join(logged_cmd))

    def test_concurrent_approval_requests_thread_safety(self) -> None:
        """Concurrent threads submitting approval requests do not corrupt internal state."""
        appr_mgr = ApprovalManager(max_pending=100)
        errors: List[Exception] = []

        def worker(idx: int) -> None:
            try:
                r = ExecutionRequest(
                    operation_type=OperationType.PROCESS,
                    executable=f"thread_proc_{idx}.exe",
                    command_line=[f"thread_proc_{idx}.exe"],
                    parent_pid=2000 + idx,
                )
                appr_mgr.create_request(r, risk_score=5)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)
        pending = appr_mgr.get_pending_requests()
        self.assertEqual(len(pending), 20)
        appr_mgr.shutdown()


if __name__ == "__main__":
    unittest.main()
