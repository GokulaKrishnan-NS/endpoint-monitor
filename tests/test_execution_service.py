"""
Unit and Integration Tests for ControlledExecutionService (Phase 3).

Comprehensive test coverage verifying:
1. Mandatory safety defaults (dry_run=True, allow_active_execution=False, interception_enabled=False).
2. Request validation and fail-closed rejection for invalid/malformed requests.
3. Policy gating preventing launcher invocation when request is denied.
4. Gate blocking when active execution is disabled, even if policy approves.
5. Permitted launcher invocation only when dry_run=False, allow_active_execution=True, and policy ALLOW.
6. Fail-closed error handling for policy exceptions.
7. Fail-closed handling for missing or invalid service configuration.
8. Accurate launcher timeout reflection in result and event.
9. Accurate launcher failure reflection in result and event.
10. Event metadata accuracy and structured fields.
11. Alert integration deduplication for duplicate outcomes.
12. Deterministic resilience against logging and alert-handler exceptions (no command retries).
13. Comprehensive command line and credential redaction.
14. Passive monitoring remains completely observational and decoupled.
15. Backward compatibility with Phase 1 ControlledExecutor and Phase 2 ControlledLauncher.
"""

import inspect
import logging
import os
import shutil
import sys
import unittest
from unittest.mock import MagicMock, patch

from src.execution.config import DEFAULT_CONTROLLED_EXECUTION_CONFIG, load_execution_config
from src.execution.controller import ControlledExecutor
from src.execution.launcher import ControlledLauncher, LaunchResult
from src.execution.policy import ExecutionPolicy
from src.execution.service import (
    ControlledExecutionService,
    ExecutionEventType,
    ExecutionServiceResult,
    ExecutionServiceStatus,
    redact_command_line,
    redact_string,
)
from src.models.event import Event
from src.models.execution_request import (
    DecisionStatus,
    ExecutionDecision,
    ExecutionRequest,
)


class TestSafetyDefaults(unittest.TestCase):
    """Verify mandatory safety defaults across configuration and service instances."""

    def test_default_configuration_values(self):
        config = load_execution_config("config/config.json")
        self.assertTrue(config.get("dry_run"))
        self.assertFalse(config.get("interception_enabled"))

        launcher_cfg = config.get("launcher", {})
        self.assertFalse(launcher_cfg.get("allow_active_execution"))

    def test_service_initialization_defaults_with_empty_config(self):
        service = ControlledExecutionService(config={})
        self.assertTrue(service.dry_run)
        self.assertFalse(service.allow_active_execution)
        self.assertFalse(service.interception_enabled)

    def test_service_initialization_defaults_with_non_boolean_values(self):
        # Non-boolean gate values must fail closed to safe defaults
        bad_config = {
            "dry_run": "false",
            "interception_enabled": 1,
            "launcher": {
                "allow_active_execution": "true",
            },
        }
        service = ControlledExecutionService(config=bad_config)
        self.assertTrue(service.dry_run)
        self.assertFalse(service.allow_active_execution)
        self.assertFalse(service.interception_enabled)

    def test_request_parameters_cannot_override_service_gates(self):
        """Malicious request metadata attempting to grant execution permission must be ignored."""
        service = ControlledExecutionService(config={"dry_run": True})

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print('bypass')"],
            metadata={
                "dry_run": False,
                "allow_active_execution": True,
                "interception_enabled": True,
            },
        )

        with patch.object(service.launcher, "launch") as mock_launch:
            result = service.execute(req)
            self.assertEqual(result.status, ExecutionServiceStatus.DRY_RUN)
            self.assertFalse(result.executed)
            mock_launch.assert_not_called()


class TestRequestValidation(unittest.TestCase):
    """Verify request intake and validation failure behaviors."""

    def setUp(self):
        self.service = ControlledExecutionService()

    def test_non_execution_request_type_rejected(self):
        with patch.object(self.service.launcher, "launch") as mock_launch:
            result = self.service.execute("invalid_string_request")  # type: ignore
            self.assertEqual(result.status, ExecutionServiceStatus.VALIDATION_FAILED)
            self.assertFalse(result.executed)
            self.assertIsNotNone(result.event)
            self.assertEqual(result.event.event_type, ExecutionEventType.REJECTED)
            self.assertIn("Invalid request type", result.error)
            mock_launch.assert_not_called()

    def test_empty_executable_rejected(self):
        req = ExecutionRequest(executable="", command_line=["test"])
        with patch.object(self.service.launcher, "launch") as mock_launch:
            result = self.service.execute(req)
            self.assertEqual(result.status, ExecutionServiceStatus.VALIDATION_FAILED)
            self.assertFalse(result.executed)
            self.assertIsNotNone(result.event)
            self.assertEqual(result.event.event_type, ExecutionEventType.REJECTED)
            mock_launch.assert_not_called()

    def test_embedded_null_byte_in_executable_rejected(self):
        req = ExecutionRequest(
            executable="cmd.exe\0test",
            command_line=["cmd.exe"],
        )
        with patch.object(self.service.launcher, "launch") as mock_launch:
            result = self.service.execute(req)
            self.assertEqual(result.status, ExecutionServiceStatus.VALIDATION_FAILED)
            self.assertFalse(result.executed)
            self.assertIn("null", result.error.lower())
            mock_launch.assert_not_called()

    def test_embedded_null_byte_in_command_line_rejected(self):
        req = ExecutionRequest(
            executable="cmd.exe",
            command_line=["cmd.exe", "arg\0null"],
        )
        with patch.object(self.service.launcher, "launch") as mock_launch:
            result = self.service.execute(req)
            self.assertEqual(result.status, ExecutionServiceStatus.VALIDATION_FAILED)
            self.assertFalse(result.executed)
            self.assertIn("null", result.error.lower())
            mock_launch.assert_not_called()

    def test_negative_parent_pid_rejected(self):
        req = ExecutionRequest(
            executable="cmd.exe",
            command_line=["cmd.exe"],
            parent_pid=-1,
        )
        with patch.object(self.service.launcher, "launch") as mock_launch:
            result = self.service.execute(req)
            self.assertEqual(result.status, ExecutionServiceStatus.VALIDATION_FAILED)
            self.assertFalse(result.executed)
            mock_launch.assert_not_called()


class TestPolicyGating(unittest.TestCase):
    """Verify policy evaluation gating prevents launcher calls when denied."""

    def test_policy_denied_request_never_invokes_launcher(self):
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_decision = ExecutionDecision(
            request_id="req-deny",
            decision=DecisionStatus.BLOCK,
            risk_score=9,
            risk_level="HIGH",
            reasons=["Detected suspicious command argument", "High risk baseline"],
            indicators=["suspicious_cmd"],
        )
        mock_policy.evaluate.return_value = mock_decision

        mock_launcher = MagicMock(spec=ControlledLauncher)
        mock_alert = MagicMock()

        service = ControlledExecutionService(
            policy=mock_policy,
            launcher=mock_launcher,
            alert_handler=mock_alert,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "import os"],
            request_id="req-deny",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.POLICY_DENIED)
        self.assertFalse(result.executed)
        self.assertEqual(result.decision.decision, DecisionStatus.BLOCK)
        mock_policy.evaluate.assert_called_once_with(req)
        mock_launcher.launch.assert_not_called()

        # Verify event
        self.assertIsNotNone(result.event)
        self.assertEqual(result.event.event_type, ExecutionEventType.DENIED)
        self.assertEqual(result.event.severity, "HIGH")
        self.assertEqual(result.event.risk_score, 9)
        self.assertIn("Detected suspicious command argument", result.event.risk_reasons)

        # Verify alert emission
        mock_alert.assert_called_once()
        self.assertIn("Execution blocked", mock_alert.call_args[0][0])


class TestDualExecutionGates(unittest.TestCase):
    """Verify dual gates: dry-run suppression and active-execution authorization."""

    def test_dry_run_suppresses_launch_even_when_policy_approves(self):
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_decision = ExecutionDecision(
            request_id="req-dry",
            decision=DecisionStatus.ALLOW,
            risk_score=1,
            risk_level="LOW",
            reasons=["Benign command"],
        )
        mock_policy.evaluate.return_value = mock_decision

        mock_launcher = MagicMock(spec=ControlledLauncher)

        service = ControlledExecutionService(
            config={"dry_run": True, "interception_enabled": True, "launcher": {"allow_active_execution": True}},
            policy=mock_policy,
            launcher=mock_launcher,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print('hi')"],
            request_id="req-dry",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.DRY_RUN)
        self.assertFalse(result.executed)
        self.assertEqual(result.decision.decision, DecisionStatus.ALLOW)
        mock_launcher.launch.assert_not_called()

        self.assertIsNotNone(result.event)
        self.assertEqual(result.event.event_type, ExecutionEventType.DRY_RUN)
        self.assertEqual(result.event.severity, "LOW")

    def test_active_execution_disabled_blocks_launch_when_dry_run_is_false(self):
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_decision = ExecutionDecision(
            request_id="req-gate",
            decision=DecisionStatus.ALLOW,
            risk_score=1,
            risk_level="LOW",
        )
        mock_policy.evaluate.return_value = mock_decision

        mock_launcher = MagicMock(spec=ControlledLauncher)
        mock_alert = MagicMock()

        service = ControlledExecutionService(
            config={"dry_run": False, "interception_enabled": True, "launcher": {"allow_active_execution": False}},
            policy=mock_policy,
            launcher=mock_launcher,
            alert_handler=mock_alert,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print('hi')"],
            request_id="req-gate",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.GATE_BLOCKED)
        self.assertFalse(result.executed)
        mock_launcher.launch.assert_not_called()

        self.assertIsNotNone(result.event)
        self.assertEqual(result.event.event_type, ExecutionEventType.GATE_BLOCKED)
        self.assertEqual(result.event.severity, "MEDIUM")
        mock_alert.assert_called_once()

    def test_active_execution_permitted_when_both_gates_open_and_policy_approves(self):
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_decision = ExecutionDecision(
            request_id="req-active",
            decision=DecisionStatus.ALLOW,
            risk_score=1,
            risk_level="LOW",
        )
        mock_policy.evaluate.return_value = mock_decision

        mock_launcher = MagicMock(spec=ControlledLauncher)
        mock_launch_result = LaunchResult(
            request_id="req-active",
            decision=mock_decision,
            executed=True,
            pid=12345,
            returncode=0,
            stdout="hello\n",
            stderr="",
        )
        mock_launcher.launch.return_value = mock_launch_result

        service = ControlledExecutionService(
            config={"dry_run": False, "interception_enabled": True, "launcher": {"allow_active_execution": True}},
            policy=mock_policy,
            launcher=mock_launcher,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print('hello')"],
            request_id="req-active",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.COMPLETED)
        self.assertTrue(result.executed)
        mock_launcher.launch.assert_called_once_with(
            request=req,
            timeout=None,
            capture_output=True,
            env=None,
        )

        self.assertIsNotNone(result.event)
        self.assertEqual(result.event.event_type, ExecutionEventType.COMPLETED)
        self.assertEqual(result.event.pid, 12345)


class TestFailClosedExceptions(unittest.TestCase):
    """Verify fail-closed semantics upon errors, exceptions, and missing configurations."""

    def test_policy_exception_fails_closed(self):
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.side_effect = RuntimeError("Policy engine corrupted")

        mock_launcher = MagicMock(spec=ControlledLauncher)

        service = ControlledExecutionService(
            policy=mock_policy,
            launcher=mock_launcher,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.SERVICE_ERROR)
        self.assertFalse(result.executed)
        self.assertIn("Policy evaluation error", result.error)
        mock_launcher.launch.assert_not_called()

        self.assertIsNotNone(result.event)
        self.assertEqual(result.event.event_type, ExecutionEventType.ERROR)

    def test_invalid_configuration_fails_closed(self):
        # Pass non-dict config
        service = ControlledExecutionService(config="invalid_config_type")  # type: ignore

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
        )

        result = service.execute(req)
        self.assertEqual(result.status, ExecutionServiceStatus.SERVICE_ERROR)
        self.assertFalse(result.executed)
        self.assertIn("configuration", result.error.lower())

    def test_launcher_exception_during_launch_fails_closed(self):
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.return_value = ExecutionDecision(
            request_id="req-err",
            decision=DecisionStatus.ALLOW,
        )

        mock_launcher = MagicMock(spec=ControlledLauncher)
        mock_launcher.launch.side_effect = OSError("Pipe creation failed")

        service = ControlledExecutionService(
            config={"dry_run": False, "interception_enabled": True, "launcher": {"allow_active_execution": True}},
            policy=mock_policy,
            launcher=mock_launcher,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-err",
        )

        result = service.execute(req)
        self.assertEqual(result.status, ExecutionServiceStatus.SERVICE_ERROR)
        self.assertFalse(result.executed)
        # Service logs only the exception class name, not the raw exception string,
        # to avoid leaking untrusted path/pipe details into logs or results.
        self.assertIn("OSError", result.error)


class TestLauncherOutcomesAndMetadata(unittest.TestCase):
    """Verify that launcher outcomes (timeout, nonzero exit, failure) translate accurately."""

    def setUp(self):
        self.mock_policy = MagicMock(spec=ExecutionPolicy)
        self.mock_decision = ExecutionDecision(
            request_id="req-outcome",
            decision=DecisionStatus.ALLOW,
            risk_score=2,
            risk_level="LOW",
        )
        self.mock_policy.evaluate.return_value = self.mock_decision
        self.mock_launcher = MagicMock(spec=ControlledLauncher)

    def test_launcher_timeout_reflected_in_result_and_event(self):
        mock_alert = MagicMock()
        service = ControlledExecutionService(
            config={"dry_run": False, "interception_enabled": True, "launcher": {"allow_active_execution": True}},
            policy=self.mock_policy,
            launcher=self.mock_launcher,
            alert_handler=mock_alert,
        )

        launch_result = LaunchResult(
            request_id="req-timeout",
            decision=self.mock_decision,
            executed=True,
            pid=9999,
            returncode=-15,
            timed_out=True,
            execution_time_seconds=30.05,
            error="Process execution timed out after 30.00 seconds",
        )
        self.mock_launcher.launch.return_value = launch_result

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "import time; time.sleep(100)"],
            request_id="req-timeout",
        )

        result = service.execute(req, timeout=30.0)

        self.assertEqual(result.status, ExecutionServiceStatus.TIMEOUT)
        self.assertTrue(result.executed)
        self.assertTrue(result.launch_result.timed_out)

        self.assertIsNotNone(result.event)
        self.assertEqual(result.event.event_type, ExecutionEventType.TIMEOUT)
        self.assertEqual(result.event.severity, "HIGH")
        self.assertEqual(result.event.metadata.get("timed_out"), True)

        mock_alert.assert_called_once()
        self.assertIn("TIMEOUT", mock_alert.call_args[0][0])

    def test_launcher_process_creation_failure_reflected(self):
        mock_alert = MagicMock()
        service = ControlledExecutionService(
            config={"dry_run": False, "interception_enabled": True, "launcher": {"allow_active_execution": True}},
            policy=self.mock_policy,
            launcher=self.mock_launcher,
            alert_handler=mock_alert,
        )

        launch_result = LaunchResult(
            request_id="req-fail-create",
            decision=self.mock_decision,
            executed=False,
            pid=None,
            returncode=None,
            error="Executable not found",
        )
        self.mock_launcher.launch.return_value = launch_result

        req = ExecutionRequest(
            executable="nonexistent.exe",
            command_line=["nonexistent.exe"],
            request_id="req-fail-create",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.FAILED)
        self.assertFalse(result.executed)
        self.assertEqual(result.event.event_type, ExecutionEventType.FAILED)
        self.assertEqual(result.event.severity, "HIGH")
        mock_alert.assert_called_once()

    def test_launcher_non_zero_exit_reflected(self):
        mock_alert = MagicMock()
        service = ControlledExecutionService(
            config={"dry_run": False, "interception_enabled": True, "launcher": {"allow_active_execution": True}},
            policy=self.mock_policy,
            launcher=self.mock_launcher,
            alert_handler=mock_alert,
        )

        launch_result = LaunchResult(
            request_id="req-nonzero",
            decision=self.mock_decision,
            executed=True,
            pid=5555,
            returncode=2,
            stdout="",
            stderr="syntax error",
        )
        self.mock_launcher.launch.return_value = launch_result

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "exit(2)"],
            request_id="req-nonzero",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.FAILED)
        self.assertTrue(result.executed)
        self.assertEqual(result.launch_result.returncode, 2)
        self.assertEqual(result.event.event_type, ExecutionEventType.FAILED)
        self.assertEqual(result.event.severity, "MEDIUM")
        mock_alert.assert_called_once()

    def test_event_and_result_serialization(self):
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_decision = ExecutionDecision(
            request_id="req-serial",
            decision=DecisionStatus.ALLOW,
        )
        mock_policy.evaluate.return_value = mock_decision
        mock_launcher = MagicMock(spec=ControlledLauncher)
        mock_launcher.launch.return_value = LaunchResult(
            request_id="req-serial",
            decision=mock_decision,
            executed=True,
            pid=1111,
            returncode=0,
        )

        service = ControlledExecutionService(
            config={"dry_run": False, "interception_enabled": True, "launcher": {"allow_active_execution": True}},
            policy=mock_policy,
            launcher=mock_launcher,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print('ok')"],
            request_id="req-serial",
        )

        result = service.execute(req)
        d = result.to_dict()

        self.assertIsInstance(d, dict)
        self.assertEqual(d["request_id"], "req-serial")
        self.assertEqual(d["status"], ExecutionServiceStatus.COMPLETED)
        self.assertTrue(d["executed"])
        self.assertIsInstance(d["event"], dict)
        self.assertEqual(d["event"]["event_type"], ExecutionEventType.COMPLETED)


class TestAlertIntegrationAndDeduplication(unittest.TestCase):
    """Verify alert emission and deduplication behavior."""

    def test_alert_deduplication_for_same_request_and_event_type(self):
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_decision = ExecutionDecision(
            request_id="req-dup-alert",
            decision=DecisionStatus.BLOCK,
            risk_score=10,
            risk_level="HIGH",
            reasons=["High risk blocked"],
        )
        mock_policy.evaluate.return_value = mock_decision

        mock_alert = MagicMock()
        service = ControlledExecutionService(
            policy=mock_policy,
            alert_handler=mock_alert,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-dup-alert",
        )

        # First execution -> should emit alert
        res1 = service.execute(req)
        self.assertEqual(mock_alert.call_count, 1)

        # Second execution of same request_id -> duplicate must be suppressed
        res2 = service.execute(req)
        self.assertEqual(mock_alert.call_count, 1)

        # After clearing cache -> should emit again
        service.clear_alert_cache()
        res3 = service.execute(req)
        self.assertEqual(mock_alert.call_count, 2)

    def test_alert_delivery_failure_does_not_crash_or_retry(self):
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_decision = ExecutionDecision(
            request_id="req-alert-fail",
            decision=DecisionStatus.BLOCK,
            risk_score=10,
            risk_level="HIGH",
            reasons=["High risk blocked"],
        )
        mock_policy.evaluate.return_value = mock_decision

        mock_alert = MagicMock(side_effect=ConnectionError("Alert server offline"))
        mock_logger = MagicMock(spec=logging.Logger)

        service = ControlledExecutionService(
            policy=mock_policy,
            alert_handler=mock_alert,
            logger=mock_logger,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-alert-fail",
        )

        result = service.execute(req)

        # Must return deterministic result without throwing
        self.assertEqual(result.status, ExecutionServiceStatus.POLICY_DENIED)
        self.assertFalse(result.executed)
        mock_logger.error.assert_called()


class TestLoggingReliability(unittest.TestCase):
    """Verify that logger exceptions do not break the service or trigger retries."""

    def test_logger_exception_handled_safely(self):
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_decision = ExecutionDecision(
            request_id="req-log-fail",
            decision=DecisionStatus.ALLOW,
        )
        mock_policy.evaluate.return_value = mock_decision

        mock_logger = MagicMock(spec=logging.Logger)
        mock_logger.info.side_effect = IOError("Disk full for log file")

        service = ControlledExecutionService(
            config={"dry_run": True},
            policy=mock_policy,
            logger=mock_logger,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-log-fail",
        )

        result = service.execute(req)
        self.assertEqual(result.status, ExecutionServiceStatus.DRY_RUN)
        self.assertFalse(result.executed)


class TestRedaction(unittest.TestCase):
    """Verify credential and sensitive argument redaction."""

    def test_redact_sensitive_flag_values(self):
        cmd = ["app.exe", "--password", "Secret123!", "--token", "tok-xyz", "-p", "pass456"]
        redacted = redact_command_line(cmd)
        self.assertEqual(
            redacted,
            ["app.exe", "--password", "[REDACTED]", "--token", "[REDACTED]", "-p", "[REDACTED]"],
        )

    def test_redact_inline_flags(self):
        cmd = ["tool.exe", "--api-key=secretkey123", "--password=mypassword", "--safe-arg=normal"]
        redacted = redact_command_line(cmd)
        self.assertEqual(
            redacted,
            ["tool.exe", "--api-key=[REDACTED]", "--password=[REDACTED]", "--safe-arg=normal"],
        )

    def test_redact_assignment_variables(self):
        cmd = ["runner.exe", "API_KEY=supersecret", "PASSWORD=adminpass", "USER=john"]
        redacted = redact_command_line(cmd)
        self.assertEqual(
            redacted,
            ["runner.exe", "API_KEY=[REDACTED]", "PASSWORD=[REDACTED]", "USER=john"],
        )

    def test_redact_embedded_url_credentials(self):
        cmd = ["curl", "https://user:password123@api.service.com/endpoint"]
        redacted = redact_command_line(cmd)
        self.assertEqual(
            redacted,
            ["curl", "https://user:[REDACTED]@api.service.com/endpoint"],
        )

    def test_redact_bearer_tokens(self):
        cmd = ["curl", "-H", "Authorization: Bearer my_secret_token_12345"]
        redacted = redact_command_line(cmd)
        self.assertEqual(
            redacted,
            ["curl", "-H", "Authorization: Bearer [REDACTED]"],
        )

    def test_event_command_line_is_redacted(self):
        service = ControlledExecutionService(config={"dry_run": True})

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "import sys", "--password", "leak_pwd"],
            request_id="req-redact",
        )

        result = service.execute(req)
        self.assertIsNotNone(result.event)
        self.assertNotIn("leak_pwd", result.event.command_line)
        self.assertIn("[REDACTED]", result.event.command_line)


class TestPassiveMonitoringDecoupling(unittest.TestCase):
    """Verify that passive monitoring in src/main.py remains decoupled and observational."""

    def test_main_py_does_not_import_or_use_controlled_service(self):
        main_path = os.path.join("src", "main.py")
        with open(main_path, "r", encoding="utf-8") as f:
            main_code = f.read()

        self.assertNotIn("ControlledExecutionService", main_code)
        self.assertNotIn("ControlledLauncher", main_code)
        self.assertNotIn("src.execution", main_code)

    def test_process_monitor_does_not_invoke_launcher(self):
        proc_mon_path = os.path.join("src", "monitors", "process_monitor.py")
        with open(proc_mon_path, "r", encoding="utf-8") as f:
            proc_code = f.read()

        self.assertNotIn("ControlledLauncher", proc_code)
        self.assertNotIn("ControlledExecutionService", proc_code)
        self.assertNotIn("subprocess.Popen", proc_code)


class TestCompatibility(unittest.TestCase):
    """Verify backward compatibility with Phase 1 and Phase 2 implementations."""

    def test_phase1_controlled_executor_intact(self):
        executor = ControlledExecutor(dry_run=True)
        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
        )
        dec = executor.request_execution(req)
        self.assertFalse(dec.executed)
        self.assertTrue(dec.dry_run)

    def test_phase2_controlled_launcher_direct_invocation_intact(self):
        launcher = ControlledLauncher(config={"dry_run": True})
        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
        )
        res = launcher.launch(req)
        self.assertFalse(res.executed)
        self.assertIsNone(res.pid)


# ---------------------------------------------------------------------------
# Security regression tests (Findings 1–5)
# ---------------------------------------------------------------------------

class TestFinding1LogSanitization(unittest.TestCase):
    """Regression tests: no sensitive data should appear in log messages."""

    def _capture_log_records(self, service, request, **execute_kwargs):
        """Run service.execute and return all log records emitted."""
        handler = logging.handlers_list = []
        collected = []
        class _Capture(logging.Handler):
            def emit(self, record):
                collected.append(record.getMessage())
        capture = _Capture()
        service.logger.addHandler(capture)
        try:
            result = service.execute(request, **execute_kwargs)
        finally:
            service.logger.removeHandler(capture)
        return collected, result

    def test_policy_exception_message_not_in_log(self):
        """Exception payload containing synthetic secret must not appear in logs."""
        SECRET = "super_secret_token_XYZ789"
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.side_effect = RuntimeError(f"DB error: token={SECRET}")

        service = ControlledExecutionService(policy=mock_policy)
        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
        )

        log_records, result = self._capture_log_records(service, req)

        self.assertEqual(result.status, ExecutionServiceStatus.SERVICE_ERROR)
        combined_log = "\n".join(log_records)
        self.assertNotIn(SECRET, combined_log, "Secret leaked via policy exception into log")
        # Must still log the exception class for diagnostics
        self.assertTrue(
            any("RuntimeError" in r for r in log_records),
            "Exception class name should appear in logs for diagnostics",
        )

    def test_policy_denial_reasons_not_in_log(self):
        """Raw policy reasons containing synthetic secrets must not appear in log messages."""
        SECRET = "leaked_credential_from_reason"
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_decision = ExecutionDecision(
            request_id="req-reason-leak",
            decision=DecisionStatus.BLOCK,
            risk_score=9,
            risk_level="HIGH",
            reasons=[f"Blocked because path contains {SECRET}"],
        )
        mock_policy.evaluate.return_value = mock_decision

        service = ControlledExecutionService(policy=mock_policy)
        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-reason-leak",
        )

        log_records, result = self._capture_log_records(service, req)

        self.assertEqual(result.status, ExecutionServiceStatus.POLICY_DENIED)
        combined_log = "\n".join(log_records)
        self.assertNotIn(SECRET, combined_log, "Policy reason leaked raw secret into log")

    def test_sensitive_reason_and_path_are_removed_from_result_metadata(self):
        """Sensitive strings should be sanitized before result/event serialization."""
        SECRET = "leaked_credential_from_reason"
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.return_value = ExecutionDecision(
            request_id="req-metadata-leak",
            decision=DecisionStatus.BLOCK,
            risk_score=9,
            risk_level="HIGH",
            reasons=[f"Blocked because path contains {SECRET}"],
        )

        service = ControlledExecutionService(policy=mock_policy)
        req = ExecutionRequest(
            executable="C:/tmp/secret_token_payload/launch.exe",
            command_line=["C:/tmp/secret_token_payload/launch.exe", "--password", "p@ssword123"],
            request_id="req-metadata-leak",
        )

        result = service.execute(req)
        payload = str(result.to_dict())

        self.assertEqual(result.status, ExecutionServiceStatus.POLICY_DENIED)
        self.assertNotIn(SECRET, payload)
        self.assertNotIn("secret_token_payload", payload)
        self.assertNotIn("p@ssword123", payload)
        self.assertIn("[REDACTED]", payload)

    def test_sensitive_reason_and_path_are_removed_from_live_returned_objects(self):
        """Returned decision and event objects must not expose raw sensitive values in memory."""
        SECRET = "leaked_credential_from_reason"
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.return_value = ExecutionDecision(
            request_id="req-live-leak",
            decision=DecisionStatus.BLOCK,
            risk_score=9,
            risk_level="HIGH",
            reasons=[f"Blocked because path contains {SECRET}"],
        )

        service = ControlledExecutionService(policy=mock_policy)
        req = ExecutionRequest(
            executable="C:/tmp/secret_token_payload/launch.exe",
            command_line=["C:/tmp/secret_token_payload/launch.exe", "--password", "p@ssword123"],
            request_id="req-live-leak",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.POLICY_DENIED)
        self.assertIsNotNone(result.decision)
        self.assertNotIn(SECRET, str(result.decision.reasons))
        self.assertNotIn("secret_token_payload", str(result.decision.reasons))
        self.assertIsNotNone(result.event)
        self.assertNotIn(SECRET, str(result.event.risk_reasons))
        self.assertNotIn("secret_token_payload", str(result.event.command_line))
        self.assertNotIn("p@ssword123", str(result.event.command_line))
        self.assertIn("[REDACTED]", str(result.event.command_line))
        self.assertNotIn(SECRET, str(result.events[0].risk_reasons))
        self.assertNotIn(SECRET, str(result.to_dict()))
        self.assertNotIn("p@ssword123", str(result.to_dict()))

    def test_launcher_exception_message_not_in_log(self):
        """Launcher exception payload containing synthetic secret must not appear in logs."""
        SECRET = "pipe_secret_path_credential"
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.return_value = ExecutionDecision(
            request_id="req-launcher-exc",
            decision=DecisionStatus.ALLOW,
        )
        mock_launcher = MagicMock(spec=ControlledLauncher)
        mock_launcher.launch.side_effect = OSError(f"Pipe failed: {SECRET}")

        service = ControlledExecutionService(
            config={"dry_run": False, "interception_enabled": True,
                    "launcher": {"allow_active_execution": True}},
            policy=mock_policy,
            launcher=mock_launcher,
        )
        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-launcher-exc",
        )

        log_records, result = self._capture_log_records(service, req)

        self.assertEqual(result.status, ExecutionServiceStatus.SERVICE_ERROR)
        combined_log = "\n".join(log_records)
        self.assertNotIn(SECRET, combined_log, "Launcher exception payload leaked into log")
        self.assertTrue(any("OSError" in r for r in log_records))


class TestFinding2StrictPolicyValidation(unittest.TestCase):
    """Regression tests: malformed and unknown policy output must cause SERVICE_ERROR."""

    def test_policy_returns_non_decision_object_fails_closed(self):
        """If policy returns a dict instead of ExecutionDecision, fail with SERVICE_ERROR."""
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.return_value = {"decision": "ALLOW"}  # wrong type

        mock_launcher = MagicMock(spec=ControlledLauncher)
        service = ControlledExecutionService(policy=mock_policy, launcher=mock_launcher)

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.SERVICE_ERROR)
        self.assertFalse(result.executed)
        self.assertEqual(result.event.event_type, ExecutionEventType.ERROR)
        mock_launcher.launch.assert_not_called()

    def test_policy_returns_unknown_decision_value_fails_closed(self):
        """An ExecutionDecision with an unknown decision value must be SERVICE_ERROR."""
        mock_policy = MagicMock(spec=ExecutionPolicy)
        bad_decision = ExecutionDecision(
            request_id="req-bad-val",
            decision="GRANT_ROOT",  # not a valid DecisionStatus value
        )
        mock_policy.evaluate.return_value = bad_decision

        mock_launcher = MagicMock(spec=ControlledLauncher)
        service = ControlledExecutionService(policy=mock_policy, launcher=mock_launcher)

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-bad-val",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.SERVICE_ERROR)
        self.assertFalse(result.executed)
        self.assertEqual(result.event.event_type, ExecutionEventType.ERROR)
        mock_launcher.launch.assert_not_called()

    def test_policy_returns_none_fails_closed(self):
        """If policy returns None, must fail closed with SERVICE_ERROR."""
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.return_value = None

        mock_launcher = MagicMock(spec=ControlledLauncher)
        service = ControlledExecutionService(policy=mock_policy, launcher=mock_launcher)

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.SERVICE_ERROR)
        self.assertFalse(result.executed)
        mock_launcher.launch.assert_not_called()

    def test_valid_block_decision_is_policy_denied_not_service_error(self):
        """Verify a valid BLOCK decision maps to POLICY_DENIED, not SERVICE_ERROR."""
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.return_value = ExecutionDecision(
            request_id="req-valid-block",
            decision=DecisionStatus.BLOCK,
            risk_score=10,
            risk_level="HIGH",
            reasons=["Suspicious binary"],
        )
        mock_launcher = MagicMock(spec=ControlledLauncher)
        service = ControlledExecutionService(policy=mock_policy, launcher=mock_launcher)

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-valid-block",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.POLICY_DENIED)
        self.assertNotEqual(result.status, ExecutionServiceStatus.SERVICE_ERROR)
        mock_launcher.launch.assert_not_called()


class TestFinding3LaunchEventOrdering(unittest.TestCase):
    """Regression tests: LAUNCH_ATTEMPTED before launcher call; LAUNCHED only on executed=True."""

    def _make_allow_service(self, mock_launcher):
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.return_value = ExecutionDecision(
            request_id="req-events",
            decision=DecisionStatus.ALLOW,
            risk_score=1,
            risk_level="LOW",
        )
        return ControlledExecutionService(
            config={"dry_run": False, "interception_enabled": True,
                    "launcher": {"allow_active_execution": True}},
            policy=mock_policy,
            launcher=mock_launcher,
        )

    def test_successful_launch_emits_attempt_then_launched_then_completed(self):
        """Event sequence for successful launch: LAUNCH_ATTEMPTED, LAUNCHED, COMPLETED."""
        mock_launcher = MagicMock(spec=ControlledLauncher)
        mock_launcher.launch.return_value = LaunchResult(
            request_id="req-events",
            decision=ExecutionDecision(request_id="req-events", decision=DecisionStatus.ALLOW),
            executed=True,
            pid=12345,
            returncode=0,
        )

        emitted = []
        service = self._make_allow_service(mock_launcher)
        service.event_handler = lambda e: emitted.append(e.event_type)

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-events",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.COMPLETED)
        self.assertIn(ExecutionEventType.LAUNCH_ATTEMPTED, emitted)
        self.assertIn(ExecutionEventType.LAUNCHED, emitted)
        self.assertIn(ExecutionEventType.COMPLETED, emitted)
        # Ordering: attempt before launched before completed
        idx_attempt = emitted.index(ExecutionEventType.LAUNCH_ATTEMPTED)
        idx_launched = emitted.index(ExecutionEventType.LAUNCHED)
        idx_completed = emitted.index(ExecutionEventType.COMPLETED)
        self.assertLess(idx_attempt, idx_launched)
        self.assertLess(idx_launched, idx_completed)

    def test_failed_process_creation_emits_attempt_not_launched(self):
        """When process creation fails (executed=False), LAUNCHED must NOT be emitted."""
        mock_launcher = MagicMock(spec=ControlledLauncher)
        mock_launcher.launch.return_value = LaunchResult(
            request_id="req-no-create",
            decision=ExecutionDecision(request_id="req-no-create", decision=DecisionStatus.ALLOW),
            executed=False,
            pid=None,
            returncode=None,
            error="Executable not found on disk",
        )

        emitted = []
        service = self._make_allow_service(mock_launcher)
        service.event_handler = lambda e: emitted.append(e.event_type)

        req = ExecutionRequest(
            executable="nonexistent.exe",
            command_line=["nonexistent.exe"],
            request_id="req-no-create",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.FAILED)
        self.assertFalse(result.executed)
        self.assertIn(ExecutionEventType.LAUNCH_ATTEMPTED, emitted)
        self.assertNotIn(
            ExecutionEventType.LAUNCHED, emitted,
            "LAUNCHED must NOT be emitted when process creation fails",
        )
        self.assertIn(ExecutionEventType.FAILED, emitted)

    def test_timeout_emits_attempt_and_launched_not_completed(self):
        """Timeout: LAUNCH_ATTEMPTED + LAUNCHED (Popen succeeded) but not COMPLETED."""
        mock_launcher = MagicMock(spec=ControlledLauncher)
        mock_launcher.launch.return_value = LaunchResult(
            request_id="req-timeout-order",
            decision=ExecutionDecision(request_id="req-timeout-order", decision=DecisionStatus.ALLOW),
            executed=True,
            pid=9999,
            returncode=-15,
            timed_out=True,
            execution_time_seconds=30.1,
        )

        emitted = []
        service = self._make_allow_service(mock_launcher)
        service.event_handler = lambda e: emitted.append(e.event_type)

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "import time; time.sleep(100)"],
            request_id="req-timeout-order",
        )

        result = service.execute(req, timeout=30.0)

        self.assertEqual(result.status, ExecutionServiceStatus.TIMEOUT)
        self.assertIn(ExecutionEventType.LAUNCH_ATTEMPTED, emitted)
        self.assertIn(ExecutionEventType.LAUNCHED, emitted)   # Popen succeeded
        self.assertIn(ExecutionEventType.TIMEOUT, emitted)
        self.assertNotIn(ExecutionEventType.COMPLETED, emitted)

    def test_launcher_exception_emits_attempt_not_launched(self):
        """Launcher exception: LAUNCH_ATTEMPTED emitted; LAUNCHED must NOT be emitted."""
        mock_launcher = MagicMock(spec=ControlledLauncher)
        mock_launcher.launch.side_effect = OSError("Spawn failed")

        emitted = []
        service = self._make_allow_service(mock_launcher)
        service.event_handler = lambda e: emitted.append(e.event_type)

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-exc-order",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.SERVICE_ERROR)
        self.assertIn(ExecutionEventType.LAUNCH_ATTEMPTED, emitted)
        self.assertNotIn(ExecutionEventType.LAUNCHED, emitted)


class TestFinding4InterceptionEnabled(unittest.TestCase):
    """Regression tests: interception_enabled semantics, default, and gate enforcement."""

    def test_interception_enabled_defaults_to_false(self):
        service = ControlledExecutionService(config={})
        self.assertFalse(service.interception_enabled)

    def test_non_boolean_interception_enabled_defaults_to_false(self):
        for bad_val in ("true", 1, None, [], {}):
            service = ControlledExecutionService(config={"interception_enabled": bad_val})
            self.assertFalse(
                service.interception_enabled,
                f"Expected interception_enabled=False for bad value {bad_val!r}",
            )

    def test_interception_disabled_blocks_launch_even_with_both_other_gates_open(self):
        """When interception_enabled=False, launcher must never be called."""
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.return_value = ExecutionDecision(
            request_id="req-intercept",
            decision=DecisionStatus.ALLOW,
        )
        mock_launcher = MagicMock(spec=ControlledLauncher)

        service = ControlledExecutionService(
            config={
                "dry_run": False,
                "interception_enabled": False,  # Gate disabled
                "launcher": {"allow_active_execution": True},
            },
            policy=mock_policy,
            launcher=mock_launcher,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-intercept",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.GATE_BLOCKED)
        self.assertFalse(result.executed)
        mock_launcher.launch.assert_not_called()
        self.assertEqual(result.event.event_type, ExecutionEventType.INTERCEPTION_BLOCKED)

    def test_interception_enabled_true_allows_launch_when_other_gates_pass(self):
        """When interception_enabled=True (plus other gates open), launcher is invoked."""
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_decision = ExecutionDecision(
            request_id="req-intercept-on",
            decision=DecisionStatus.ALLOW,
        )
        mock_policy.evaluate.return_value = mock_decision

        mock_launcher = MagicMock(spec=ControlledLauncher)
        mock_launcher.launch.return_value = LaunchResult(
            request_id="req-intercept-on",
            decision=mock_decision,
            executed=True,
            pid=1234,
            returncode=0,
        )

        service = ControlledExecutionService(
            config={
                "dry_run": False,
                "interception_enabled": True,
                "launcher": {"allow_active_execution": True},
            },
            policy=mock_policy,
            launcher=mock_launcher,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-intercept-on",
        )

        result = service.execute(req)

        self.assertEqual(result.status, ExecutionServiceStatus.COMPLETED)
        mock_launcher.launch.assert_called_once()

    def test_interception_enabled_does_not_implement_os_hooks(self):
        """Service module must not import OS hook, shell wrapper, or monkey-patch modules."""
        import importlib
        import src.execution.service as svc_module
        forbidden = {"ctypes", "win32api", "win32con", "winreg", "pywin32", "shellcon"}
        # Check top-level module imports (sys.modules that were imported during module load)
        service_source_path = svc_module.__file__
        with open(service_source_path, "r", encoding="utf-8") as f:
            source = f.read()
        for name in forbidden:
            self.assertNotIn(name, source, f"service.py must not reference '{name}'")


class TestFinding5BoundedAlertCache(unittest.TestCase):
    """Regression tests: bounded cache eviction, thread safety, and delivery isolation."""

    def test_cache_evicts_oldest_when_capacity_exceeded(self):
        """When cache is full, the oldest entry is evicted and a new entry may be alerted."""
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.return_value = ExecutionDecision(
            request_id="x",
            decision=DecisionStatus.BLOCK,
            risk_score=10,
            risk_level="HIGH",
        )

        service = ControlledExecutionService(policy=mock_policy)
        # Shrink the cache max to 2 for testability
        service._alert_cache_max_size = 2

        call_count = [0]
        def counting_alert(msg):
            call_count[0] += 1

        service.alert_handler = counting_alert

        def _denied_req(rid):
            mock_policy.evaluate.return_value = ExecutionDecision(
                request_id=rid,
                decision=DecisionStatus.BLOCK,
                risk_score=10,
                risk_level="HIGH",
            )
            return ExecutionRequest(
                executable=sys.executable,
                command_line=[sys.executable, "-c", "print(1)"],
                request_id=rid,
            )

        # Fill the cache with 2 unique entries (a, b)
        service.execute(_denied_req("req-a"))
        service.execute(_denied_req("req-b"))
        self.assertEqual(call_count[0], 2)

        # Both should now be in cache; re-submitting should NOT alert again
        service.execute(_denied_req("req-a"))
        service.execute(_denied_req("req-b"))
        self.assertEqual(call_count[0], 2)

        # Adding a third entry (req-c) must evict req-a (oldest)
        service.execute(_denied_req("req-c"))
        self.assertEqual(call_count[0], 3)

        # req-a was evicted so it can be alerted again
        service.execute(_denied_req("req-a"))
        self.assertEqual(call_count[0], 4)

    def test_lock_not_held_during_alert_delivery(self):
        """Alert delivery happens outside the cache lock; a blocking handler must not deadlock."""
        import threading

        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.return_value = ExecutionDecision(
            request_id="req-lock",
            decision=DecisionStatus.BLOCK,
            risk_score=10,
            risk_level="HIGH",
        )

        delivered = []
        def slow_alert(msg):
            # Simulate I/O; if lock were held this would cause contention
            import time as _time
            _time.sleep(0.01)
            delivered.append(msg)

        service = ControlledExecutionService(
            policy=mock_policy,
            alert_handler=slow_alert,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-lock",
        )

        # Run in a thread; should complete without deadlock within 2 seconds
        result_holder = []
        def run():
            result_holder.append(service.execute(req))

        t = threading.Thread(target=run)
        t.start()
        t.join(timeout=2.0)
        self.assertFalse(t.is_alive(), "Thread deadlocked — lock may be held during alert delivery")
        self.assertEqual(len(delivered), 1)

    def test_alert_delivery_failure_does_not_retain_incomplete_cache_state(self):
        """After a failed delivery, the key is still in cache so duplicate is suppressed."""
        mock_policy = MagicMock(spec=ExecutionPolicy)
        mock_policy.evaluate.return_value = ExecutionDecision(
            request_id="req-fail-cache",
            decision=DecisionStatus.BLOCK,
            risk_score=10,
            risk_level="HIGH",
        )

        fail_count = [0]
        def failing_alert(msg):
            fail_count[0] += 1
            raise ConnectionError("Alert endpoint offline")

        service = ControlledExecutionService(
            policy=mock_policy,
            alert_handler=failing_alert,
        )

        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print(1)"],
            request_id="req-fail-cache",
        )

        # First call: handler fails but key is cached
        service.execute(req)
        self.assertEqual(fail_count[0], 1)

        # Second call: key is in cache → handler NOT called again
        service.execute(req)
        self.assertEqual(fail_count[0], 1)


if __name__ == "__main__":
    unittest.main()
