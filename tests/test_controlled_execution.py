"""
Unit Tests for Controlled Execution Layer (Phase 1).

Tests:
1. Low-risk execution requests (benign target, ALLOW decision)
2. High-risk execution requests (suspicious command/lineage, BLOCK decision)
3. Threshold boundary scenarios (below, at, and above threshold)
4. Blocked severities configuration (HIGH only vs. HIGH and MEDIUM)
5. Invalid input scenarios (malformed command_line, invalid parent PID, empty executable)
6. Analyzer error / exception scenarios (fail-closed guarantees)
7. Process tree integration with and without parent context
8. Configuration loading, fallback, and corrupted config handling
9. Dry-run safety verification (verifying process launch APIs are never called)
10. Data model serialization and round-trip conversion
"""

import os
import unittest
from unittest.mock import MagicMock, patch

from src.execution.config import (
    DEFAULT_CONTROLLED_EXECUTION_CONFIG,
    load_execution_config,
)
from src.execution.controller import ControlledExecutor
from src.execution.policy import ExecutionPolicy
from src.models.execution_request import (
    DecisionStatus,
    ExecutionDecision,
    ExecutionRequest,
)


class TestExecutionRequestModel(unittest.TestCase):
    """Test ExecutionRequest data model validation and serialization."""

    def test_valid_request(self):
        req = ExecutionRequest(
            executable="python.exe",
            command_line=["python.exe", "script.py", "--arg"],
            parent_pid=1000,
            parent_process_name="explorer.exe",
            username="testuser",
        )
        is_valid, err = req.validate()
        self.assertTrue(is_valid)
        self.assertIsNone(err)

    def test_invalid_executable_empty(self):
        for invalid_exe in ["", "   ", None, 123]:
            req = ExecutionRequest(executable=invalid_exe, command_line=["cmd.exe"])
            is_valid, err = req.validate()
            self.assertFalse(is_valid)
            self.assertIn("Executable", err)

    def test_invalid_command_line_empty_or_non_list(self):
        for invalid_cmd in [[], None, "cmd.exe", 123]:
            req = ExecutionRequest(executable="cmd.exe", command_line=invalid_cmd)
            is_valid, err = req.validate()
            self.assertFalse(is_valid)
            self.assertIn("Command line", err)

    def test_invalid_command_line_non_string_elements(self):
        req = ExecutionRequest(
            executable="cmd.exe", command_line=["cmd.exe", 123, None]
        )
        is_valid, err = req.validate()
        self.assertFalse(is_valid)
        self.assertIn("index 1 must be a string", err)

    def test_invalid_parent_pid(self):
        for invalid_pid in [-1, -999, "123", True, 3.14]:
            req = ExecutionRequest(
                executable="cmd.exe",
                command_line=["cmd.exe"],
                parent_pid=invalid_pid,
            )
            is_valid, err = req.validate()
            self.assertFalse(is_valid)
            self.assertIn("Parent PID", err)

    def test_invalid_parent_process_name_and_username(self):
        req1 = ExecutionRequest(
            executable="cmd.exe",
            command_line=["cmd.exe"],
            parent_process_name=123,
        )
        is_valid, err = req1.validate()
        self.assertFalse(is_valid)
        self.assertIn("Parent process name", err)

        req2 = ExecutionRequest(
            executable="cmd.exe",
            command_line=["cmd.exe"],
            username=123,
        )
        is_valid, err = req2.validate()
        self.assertFalse(is_valid)
        self.assertIn("Username", err)

    def test_to_process_info_conversion(self):
        req = ExecutionRequest(
            executable="C:\\Windows\\System32\\cmd.exe",
            command_line=["cmd.exe", "/c", "dir"],
            parent_pid=500,
            parent_process_name="explorer.exe",
            username="Alice",
        )
        pinfo = req.to_process_info()
        self.assertIsNone(pinfo["pid"])  # Process not started yet
        self.assertEqual(pinfo["ppid"], 500)
        self.assertEqual(pinfo["name"], "cmd.exe")
        self.assertEqual(pinfo["parent_name"], "explorer.exe")
        self.assertEqual(pinfo["username"], "Alice")
        self.assertEqual(pinfo["cmdline"], ["cmd.exe", "/c", "dir"])

    def test_to_dict_and_from_dict_roundtrip(self):
        req = ExecutionRequest(
            executable="notepad.exe",
            command_line=["notepad.exe", "file.txt"],
            parent_pid=200,
            parent_process_name="cmd.exe",
            username="Bob",
            working_directory="C:\\temp",
            metadata={"source": "unit_test"},
        )
        d = req.to_dict()
        req2 = ExecutionRequest.from_dict(d)
        self.assertEqual(req.request_id, req2.request_id)
        self.assertEqual(req.executable, req2.executable)
        self.assertEqual(req.command_line, req2.command_line)
        self.assertEqual(req.parent_pid, req2.parent_pid)
        self.assertEqual(req.parent_process_name, req2.parent_process_name)
        self.assertEqual(req.username, req2.username)
        self.assertEqual(req.metadata, req2.metadata)

    def test_decision_to_dict_and_from_dict(self):
        dec = ExecutionDecision(
            request_id="req-123",
            decision=DecisionStatus.ALLOW,
            risk_score=2,
            risk_level="LOW",
            reasons=["Benign command"],
            indicators=[],
            dry_run=True,
            executed=False,
            error=None,
        )
        d = dec.to_dict()
        dec2 = ExecutionDecision.from_dict(d)
        self.assertEqual(dec.request_id, dec2.request_id)
        self.assertEqual(dec.decision, dec2.decision)
        self.assertEqual(dec.risk_score, dec2.risk_score)
        self.assertEqual(dec.risk_level, dec2.risk_level)


class TestExecutionPolicy(unittest.TestCase):
    """Test policy evaluation, risk gating, and fail-closed safety."""

    def setUp(self):
        # Default policy: threshold = 7, blocked_severities = ["HIGH"]
        self.policy = ExecutionPolicy()

    def test_benign_low_risk_request_is_allowed(self):
        req = ExecutionRequest(
            executable="python.exe",
            command_line=["python.exe", "app.py", "--verbose"],
            parent_pid=1000,
            parent_process_name="explorer.exe",
            username="normaluser",
        )
        decision = self.policy.evaluate(req)
        self.assertEqual(decision.decision, DecisionStatus.ALLOW)
        self.assertEqual(decision.risk_score, 0)
        self.assertEqual(decision.risk_level, "LOW")
        self.assertIsNone(decision.error)
        self.assertFalse(decision.executed)

    def test_minor_indicator_below_threshold_is_allowed(self):
        # command_chaining has score 2 (LOW severity)
        req = ExecutionRequest(
            executable="cmd.exe",
            command_line=["cmd.exe", "/c", "dir && echo done"],
            parent_pid=1000,
            parent_process_name="explorer.exe",
            username="normaluser",
        )
        decision = self.policy.evaluate(req)
        # Score is 2 < 7 threshold, severity is LOW -> ALLOW
        self.assertEqual(decision.decision, DecisionStatus.ALLOW)
        self.assertEqual(decision.risk_score, 2)
        self.assertEqual(decision.risk_level, "LOW")
        self.assertIn("command_chaining", decision.indicators)

    def test_high_risk_obfuscation_is_blocked(self):
        # encoded_command (4) + hidden_execution (3) = 7 (HIGH severity)
        req = ExecutionRequest(
            executable="powershell.exe",
            command_line=["powershell.exe", "-windowstyle", "hidden", "-enc", "aW1wb3J0"],
            parent_pid=1000,
            parent_process_name="cmd.exe",
            username="user",
        )
        decision = self.policy.evaluate(req)
        self.assertEqual(decision.decision, DecisionStatus.BLOCK)
        self.assertGreaterEqual(decision.risk_score, 7)
        self.assertEqual(decision.risk_level, "HIGH")
        self.assertIn("encoded_command", decision.indicators)
        self.assertIn("hidden_execution", decision.indicators)
        self.assertTrue(any("threshold" in r.lower() or "blocked by policy" in r.lower() for r in decision.reasons))

    def test_threshold_boundary_exact_score(self):
        # Custom policy with score_threshold = 3
        custom_policy = ExecutionPolicy(config={
            "enabled": True,
            "dry_run": True,
            "score_threshold": 3,
            "blocked_severities": [],  # severities check off to isolate score threshold
            "blocked_indicators": [],
            "fail_closed": True,
        })

        # Score = 2 (command chaining) -> Just below threshold 3 -> ALLOW
        req_below = ExecutionRequest(
            executable="cmd.exe",
            command_line=["cmd.exe", "/c", "echo 1 && echo 2"],
        )
        dec_below = custom_policy.evaluate(req_below)
        self.assertEqual(dec_below.risk_score, 2)
        self.assertEqual(dec_below.decision, DecisionStatus.ALLOW)

        # Score = 3 (hidden execution) -> Exactly at threshold 3 -> BLOCK
        req_at = ExecutionRequest(
            executable="powershell.exe",
            command_line=["powershell.exe", "-windowstyle", "hidden"],
        )
        dec_at = custom_policy.evaluate(req_at)
        self.assertEqual(dec_at.risk_score, 3)
        self.assertEqual(dec_at.decision, DecisionStatus.BLOCK)

        # Score = 4 (encoded command) -> Above threshold 3 -> BLOCK
        req_above = ExecutionRequest(
            executable="powershell.exe",
            command_line=["powershell.exe", "-enc", "aW1wb3J0"],
        )
        dec_above = custom_policy.evaluate(req_above)
        self.assertEqual(dec_above.risk_score, 4)
        self.assertEqual(dec_above.decision, DecisionStatus.BLOCK)

    def test_blocked_severities_configuration(self):
        # Policy configured to block MEDIUM and HIGH
        policy_block_medium = ExecutionPolicy(config={
            "enabled": True,
            "dry_run": True,
            "score_threshold": 10,  # high score threshold
            "blocked_severities": ["MEDIUM", "HIGH"],
            "blocked_indicators": [],
            "fail_closed": True,
        })

        # hidden_execution is score 3, level "MEDIUM"
        req_med = ExecutionRequest(
            executable="powershell.exe",
            command_line=["powershell.exe", "-w", "hidden"],
        )
        dec_med = policy_block_medium.evaluate(req_med)
        self.assertEqual(dec_med.risk_level, "MEDIUM")
        self.assertEqual(dec_med.decision, DecisionStatus.BLOCK)
        self.assertTrue(any("MEDIUM" in r for r in dec_med.reasons))

    def test_blocked_indicators_configuration(self):
        # Policy configured with explicit blocked indicator
        policy_indicator = ExecutionPolicy(config={
            "enabled": True,
            "dry_run": True,
            "score_threshold": 10,
            "blocked_severities": [],
            "blocked_indicators": ["command_chaining"],
            "fail_closed": True,
        })
        req = ExecutionRequest(
            executable="cmd.exe",
            command_line=["cmd.exe", "/c", "dir && whoami"],
        )
        decision = policy_indicator.evaluate(req)
        self.assertEqual(decision.decision, DecisionStatus.BLOCK)
        self.assertTrue(any("command_chaining" in r for r in decision.reasons))

    def test_process_tree_suspicious_lineage(self):
        # Office (winword.exe) spawning cmd.exe (configured rule: score 5, HIGH in process_tree.json)
        req = ExecutionRequest(
            executable="cmd.exe",
            command_line=["cmd.exe", "/c", "echo test"],
            parent_pid=1234,
            parent_process_name="winword.exe",
        )
        decision = self.policy.evaluate(req)
        # Lineage indicator added: suspicious_process_lineage (score 4 in risk_detector)
        self.assertIn("suspicious_process_lineage", decision.indicators)
        self.assertGreaterEqual(decision.risk_score, 4)
        self.assertTrue(any("Suspicious process lineage" in r for r in decision.reasons))

    def test_missing_parent_information_handled_gracefully(self):
        # When parent_process_name is None, do not fabricate parent or crash
        req = ExecutionRequest(
            executable="cmd.exe",
            command_line=["cmd.exe", "/c", "dir"],
            parent_pid=None,
            parent_process_name=None,
        )
        decision = self.policy.evaluate(req)
        self.assertEqual(decision.decision, DecisionStatus.ALLOW)
        self.assertNotIn("suspicious_process_lineage", decision.indicators)

    def test_privileged_user_scoring_integration(self):
        # SYSTEM user adds +1 to score in risk_detector
        req = ExecutionRequest(
            executable="python.exe",
            command_line=["python.exe", "worker.py"],
            username="SYSTEM",
        )
        decision = self.policy.evaluate(req)
        self.assertEqual(decision.risk_score, 1)
        self.assertTrue(any("Privileged execution context" in r for r in decision.reasons))
        self.assertEqual(decision.decision, DecisionStatus.ALLOW)

    def test_invalid_input_fails_closed(self):
        # None or malformed requests fail closed to BLOCK
        dec1 = self.policy.evaluate(None)
        self.assertEqual(dec1.decision, DecisionStatus.BLOCK)
        self.assertIsNotNone(dec1.error)

        dec2 = self.policy.evaluate("not_a_request")
        self.assertEqual(dec2.decision, DecisionStatus.BLOCK)
        self.assertIsNotNone(dec2.error)

        req_invalid = ExecutionRequest(executable="", command_line=[])
        dec3 = self.policy.evaluate(req_invalid)
        self.assertEqual(dec3.decision, DecisionStatus.BLOCK)
        self.assertIn("Validation failure", dec3.error)

    def test_detector_exception_fails_closed(self):
        req = ExecutionRequest(
            executable="python.exe",
            command_line=["python.exe", "test.py"],
        )
        with patch("src.execution.policy.detect_command_indicators", side_effect=RuntimeError("Detector exploded")):
            decision = self.policy.evaluate(req)
            self.assertEqual(decision.decision, DecisionStatus.BLOCK)
            self.assertIn("Detector exploded", decision.error)
            self.assertTrue(any("Fail-closed policy enforced" in r for r in decision.reasons))

    def test_risk_calculator_exception_fails_closed(self):
        req = ExecutionRequest(
            executable="python.exe",
            command_line=["python.exe", "test.py"],
        )
        with patch("src.execution.policy.calculate_risk", side_effect=TypeError("Unexpected score calculation error")):
            decision = self.policy.evaluate(req)
            self.assertEqual(decision.decision, DecisionStatus.BLOCK)
            self.assertIn("Unexpected score calculation error", decision.error)

    def test_disabled_policy(self):
        disabled_policy = ExecutionPolicy(config={"enabled": False})
        req = ExecutionRequest(
            executable="powershell.exe",
            command_line=["powershell.exe", "-windowstyle", "hidden", "-enc", "abc"],
        )
        decision = disabled_policy.evaluate(req)
        self.assertEqual(decision.decision, DecisionStatus.ALLOW)
        self.assertIn("disabled", decision.reasons[0].lower())


class TestControlledExecutor(unittest.TestCase):
    """Test ControlledExecutor gating and dry-run safety verification."""

    def setUp(self):
        self.policy = ExecutionPolicy()
        self.executor = ControlledExecutor(policy=self.policy, dry_run=True)

    def test_evaluate_request_does_not_execute(self):
        req = ExecutionRequest(
            executable="python.exe",
            command_line=["python.exe", "script.py"],
        )
        decision = self.executor.evaluate_request(req)
        self.assertEqual(decision.decision, DecisionStatus.ALLOW)
        self.assertTrue(decision.dry_run)
        self.assertFalse(decision.executed)

    @patch("subprocess.Popen")
    @patch("subprocess.run")
    @patch("subprocess.call")
    @patch("os.system")
    def test_dry_run_allows_policy_but_never_launches_process(
        self, mock_system, mock_call, mock_run, mock_popen
    ):
        req = ExecutionRequest(
            executable="python.exe",
            command_line=["python.exe", "benign.py"],
        )
        decision = self.executor.request_execution(req)

        # Policy allowed it
        self.assertEqual(decision.decision, DecisionStatus.ALLOW)
        self.assertTrue(decision.dry_run)
        self.assertFalse(decision.executed)

        # Zero process launch API calls
        mock_popen.assert_not_called()
        mock_run.assert_not_called()
        mock_call.assert_not_called()
        mock_system.assert_not_called()

    @patch("subprocess.Popen")
    @patch("subprocess.run")
    @patch("subprocess.call")
    @patch("os.system")
    def test_blocked_request_never_launches_process(
        self, mock_system, mock_call, mock_run, mock_popen
    ):
        req = ExecutionRequest(
            executable="powershell.exe",
            command_line=["powershell.exe", "-windowstyle", "hidden", "-enc", "abc"],
        )
        decision = self.executor.request_execution(req)

        self.assertEqual(decision.decision, DecisionStatus.BLOCK)
        self.assertFalse(decision.executed)

        mock_popen.assert_not_called()
        mock_run.assert_not_called()
        mock_call.assert_not_called()
        mock_system.assert_not_called()

    @patch("subprocess.Popen")
    @patch("subprocess.run")
    @patch("subprocess.call")
    @patch("os.system")
    def test_phase1_foundation_disallows_active_launch(
        self, mock_system, mock_call, mock_run, mock_popen
    ):
        # Even if executor is created with dry_run=False, Phase 1 foundation prohibits launching
        active_executor = ControlledExecutor(policy=self.policy, dry_run=False)
        req = ExecutionRequest(
            executable="python.exe",
            command_line=["python.exe", "benign.py"],
        )
        decision = active_executor.request_execution(req)

        self.assertEqual(decision.decision, DecisionStatus.ALLOW)
        self.assertFalse(decision.executed)
        self.assertIn("disabled in Phase 1 foundation", decision.error)

        mock_popen.assert_not_called()
        mock_run.assert_not_called()
        mock_call.assert_not_called()
        mock_system.assert_not_called()


class TestExecutionConfig(unittest.TestCase):
    """Test configuration loading and fallback."""

    def test_default_config_values(self):
        self.assertTrue(DEFAULT_CONTROLLED_EXECUTION_CONFIG["enabled"])
        self.assertTrue(DEFAULT_CONTROLLED_EXECUTION_CONFIG["dry_run"])
        self.assertEqual(DEFAULT_CONTROLLED_EXECUTION_CONFIG["score_threshold"], 7)
        self.assertEqual(DEFAULT_CONTROLLED_EXECUTION_CONFIG["blocked_severities"], ["HIGH"])
        self.assertTrue(DEFAULT_CONTROLLED_EXECUTION_CONFIG["fail_closed"])

    def test_load_from_valid_config_file(self):
        cfg = load_execution_config("config/config.json")
        self.assertTrue(cfg["enabled"])
        self.assertTrue(cfg["dry_run"])
        self.assertEqual(cfg["score_threshold"], 7)
        self.assertEqual(cfg["blocked_severities"], ["HIGH"])

    def test_load_from_nonexistent_file_falls_back(self):
        cfg = load_execution_config("nonexistent/path/config.json")
        self.assertEqual(cfg, DEFAULT_CONTROLLED_EXECUTION_CONFIG)

    def test_load_from_corrupt_file_falls_back(self):
        corrupt_path = "tests/test_corrupt_config_temp.json"
        try:
            with open(corrupt_path, "w", encoding="utf-8") as f:
                f.write("{ invalid json")
            cfg = load_execution_config(corrupt_path)
            self.assertEqual(cfg, DEFAULT_CONTROLLED_EXECUTION_CONFIG)
        finally:
            if os.path.exists(corrupt_path):
                os.remove(corrupt_path)


if __name__ == "__main__":
    unittest.main()
