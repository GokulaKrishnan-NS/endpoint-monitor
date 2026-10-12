"""
Unit and Integration Tests for Controlled Launcher (Phase 2).

Tests:
1. LaunchResult data model, serialization, and truncation properties
2. Dual execution gating (dry_run and allow_active_execution combinations)
3. Zero-Popen guarantees for blocked, disabled, malformed, or mismatch requests
4. Executable canonical consistency validation
5. Working directory boundary security (containment, traversal, prefix spoofing)
6. Environment override validation and error handling
7. Bounded output capture, stream draining, and separate truncation flags
8. Timeout handling, direct-child termination, and reaping
9. Process creation failure handling (executed=False when Popen fails)
10. Controlled harmless real execution (gated explicitly in test configurations)
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from src.execution.config import load_execution_config
from src.execution.launcher import (
    ControlledLauncher,
    LaunchResult,
    _is_cwd_permitted,
    _is_same_canonical_file,
    _resolve_canonical_executable,
)
from src.execution.policy import ExecutionPolicy
from src.models.execution_request import (
    DecisionStatus,
    ExecutionDecision,
    ExecutionRequest,
)


class TestLaunchResultModel(unittest.TestCase):
    """Test LaunchResult model behaviors and serialization."""

    def test_default_values_and_truncated_property(self):
        decision = ExecutionDecision(
            request_id="req-1",
            decision=DecisionStatus.ALLOW,
        )
        res = LaunchResult(request_id="req-1", decision=decision)
        self.assertFalse(res.executed)
        self.assertIsNone(res.pid)
        self.assertIsNone(res.returncode)
        self.assertEqual(res.stdout, "")
        self.assertEqual(res.stderr, "")
        self.assertFalse(res.stdout_truncated)
        self.assertFalse(res.stderr_truncated)
        self.assertFalse(res.truncated)
        self.assertFalse(res.timed_out)
        self.assertIsNone(res.error)

        res.stdout_truncated = True
        self.assertTrue(res.truncated)

        res.stdout_truncated = False
        res.stderr_truncated = True
        self.assertTrue(res.truncated)

    def test_to_dict_and_from_dict_roundtrip(self):
        decision = ExecutionDecision(
            request_id="req-2",
            decision=DecisionStatus.ALLOW,
            risk_score=2,
            risk_level="LOW",
            reasons=["Benign"],
            indicators=[],
        )
        res = LaunchResult(
            request_id="req-2",
            decision=decision,
            executed=True,
            pid=9999,
            returncode=0,
            stdout="hello",
            stderr="warn",
            stdout_truncated=False,
            stderr_truncated=True,
            timed_out=False,
            error=None,
            execution_time_seconds=0.12,
        )

        d = res.to_dict()
        self.assertTrue(d["truncated"])
        self.assertEqual(d["pid"], 9999)

        reconstructed = LaunchResult.from_dict(d)
        self.assertEqual(reconstructed.request_id, "req-2")
        self.assertTrue(reconstructed.executed)
        self.assertEqual(reconstructed.pid, 9999)
        self.assertEqual(reconstructed.returncode, 0)
        self.assertEqual(reconstructed.stdout, "hello")
        self.assertEqual(reconstructed.stderr, "warn")
        self.assertFalse(reconstructed.stdout_truncated)
        self.assertTrue(reconstructed.stderr_truncated)
        self.assertTrue(reconstructed.truncated)
        self.assertEqual(reconstructed.decision.decision, DecisionStatus.ALLOW)


class TestControlledLauncherGating(unittest.TestCase):
    """Test configuration gating and zero-Popen guarantees."""

    def setUp(self):
        self.python_exe = sys.executable

    @patch("subprocess.Popen")
    def test_default_config_suppresses_execution(self, mock_popen):
        # Default config: dry_run=True, allow_active_execution=False
        launcher = ControlledLauncher()
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[self.python_exe, "-c", "pass"],
        )
        result = launcher.launch(req)
        self.assertFalse(result.executed)
        self.assertIn("dry_run is True", result.error)
        mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_dry_run_false_but_allow_active_false_suppresses_execution(self, mock_popen):
        launcher = ControlledLauncher(config={
            "enabled": True,
            "dry_run": False,
            "launcher": {
                "allow_active_execution": False,
            },
        })
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[self.python_exe, "-c", "pass"],
        )
        result = launcher.launch(req)
        self.assertFalse(result.executed)
        self.assertIn("allow_active_execution is False", result.error)
        mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_dry_run_true_and_allow_active_true_suppresses_execution(self, mock_popen):
        launcher = ControlledLauncher(config={
            "enabled": True,
            "dry_run": True,
            "launcher": {
                "allow_active_execution": True,
            },
        })
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[self.python_exe, "-c", "pass"],
        )
        result = launcher.launch(req)
        self.assertFalse(result.executed)
        self.assertIn("dry_run is True", result.error)
        mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_non_boolean_gate_values_fail_closed(self, mock_popen):
        # String or integer values in config must not activate execution
        launcher = ControlledLauncher(config={
            "enabled": True,
            "dry_run": "false",  # non-boolean -> defaults to True
            "launcher": {
                "allow_active_execution": 1,  # non-boolean -> defaults to False
            },
        })
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[self.python_exe, "-c", "pass"],
        )
        result = launcher.launch(req)
        self.assertFalse(result.executed)
        mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_request_metadata_cannot_override_trusted_gates(self, mock_popen):
        # Caller supplies override attempt in request metadata
        launcher = ControlledLauncher(config={
            "enabled": True,
            "dry_run": True,
            "launcher": {
                "allow_active_execution": False,
            },
        })
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[self.python_exe, "-c", "pass"],
            metadata={
                "dry_run": False,
                "allow_active_execution": True,
            },
        )
        result = launcher.launch(req)
        self.assertFalse(result.executed)
        mock_popen.assert_not_called()


class TestControlledLauncherValidation(unittest.TestCase):
    """Test validation of executable, arguments, directory, and environment."""

    def setUp(self):
        self.python_exe = sys.executable
        self.active_config = {
            "enabled": True,
            "dry_run": False,
            "launcher": {
                "allow_active_execution": True,
            },
        }

    @patch("subprocess.Popen")
    def test_invalid_request_type_fails_closed(self, mock_popen):
        launcher = ControlledLauncher(config=self.active_config)
        result = launcher.launch("invalid_request_string")  # type: ignore
        self.assertFalse(result.executed)
        self.assertIn("Invalid request type", result.error)
        mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_malformed_request_fails_closed(self, mock_popen):
        launcher = ControlledLauncher(config=self.active_config)
        req = ExecutionRequest(executable="", command_line=[])
        result = launcher.launch(req)
        self.assertFalse(result.executed)
        self.assertIn("validation failed", result.error.lower())
        mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_policy_blocked_request_never_invokes_popen(self, mock_popen):
        launcher = ControlledLauncher(config=self.active_config)
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[self.python_exe, "-windowstyle", "hidden", "-enc", "aW1wb3J0"],
        )
        result = launcher.launch(req)
        self.assertFalse(result.executed)
        self.assertEqual(result.decision.decision, DecisionStatus.BLOCK)
        mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_unresolvable_executable_fails_closed(self, mock_popen):
        launcher = ControlledLauncher(config=self.active_config)
        req = ExecutionRequest(
            executable="non_existent_binary_xyz_12345.exe",
            command_line=["non_existent_binary_xyz_12345.exe", "--arg"],
        )
        result = launcher.launch(req)
        self.assertFalse(result.executed)
        self.assertIn("could not be resolved", result.error)
        mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_executable_and_cmdline0_mismatch_fails_closed(self, mock_popen):
        # cmd.exe and powershell.exe resolve to different canonical binaries
        cmd_path = shutil.which("cmd.exe") or "cmd.exe"
        ps_path = shutil.which("powershell.exe") or "powershell.exe"

        launcher = ControlledLauncher(config=self.active_config)
        req = ExecutionRequest(
            executable=cmd_path,
            command_line=[ps_path, "-Command", "Write-Output 1"],
        )
        result = launcher.launch(req)
        self.assertFalse(result.executed)
        self.assertIn("mismatch", result.error.lower())
        mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_working_directory_empty_allowlist_restricts_to_cwd(self, mock_popen):
        launcher = ControlledLauncher(config={
            "enabled": True,
            "dry_run": False,
            "launcher": {
                "allow_active_execution": True,
                "allowed_working_directories": [],
            },
        })

        # Outside directory (system temp dir)
        outside_dir = tempfile.gettempdir()
        if os.path.realpath(outside_dir) != os.path.realpath(os.getcwd()):
            req = ExecutionRequest(
                executable=self.python_exe,
                command_line=[self.python_exe, "-c", "pass"],
                working_directory=outside_dir,
            )
            result = launcher.launch(req)
            self.assertFalse(result.executed)
            self.assertIn("not permitted by allowed working directories", result.error)
            mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_working_directory_prefix_spoofing_rejected(self, mock_popen):
        # If /base/allowed is allowed, /base/allowed_spoof must NOT be allowed
        temp_base = tempfile.mkdtemp()
        try:
            allowed_dir = os.path.join(temp_base, "allowed")
            spoof_dir = os.path.join(temp_base, "allowed_spoof")
            os.makedirs(allowed_dir, exist_ok=True)
            os.makedirs(spoof_dir, exist_ok=True)

            self.assertTrue(_is_cwd_permitted(allowed_dir, [allowed_dir]))
            self.assertFalse(_is_cwd_permitted(spoof_dir, [allowed_dir]))

            launcher = ControlledLauncher(config={
                "enabled": True,
                "dry_run": False,
                "launcher": {
                    "allow_active_execution": True,
                    "allowed_working_directories": [allowed_dir],
                },
            })

            req = ExecutionRequest(
                executable=self.python_exe,
                command_line=[self.python_exe, "-c", "pass"],
                working_directory=spoof_dir,
            )
            result = launcher.launch(req)
            self.assertFalse(result.executed)
            self.assertIn("not permitted", result.error)
            mock_popen.assert_not_called()
        finally:
            shutil.rmtree(temp_base, ignore_errors=True)

    @patch("subprocess.Popen")
    def test_working_directory_traversal_rejected(self, mock_popen):
        temp_base = tempfile.mkdtemp()
        try:
            allowed_dir = os.path.join(temp_base, "allowed", "sub")
            os.makedirs(allowed_dir, exist_ok=True)

            # Traversal escape ../../
            traversal_path = os.path.join(allowed_dir, "..", "..")
            self.assertFalse(_is_cwd_permitted(traversal_path, [allowed_dir]))

            launcher = ControlledLauncher(config={
                "enabled": True,
                "dry_run": False,
                "launcher": {
                    "allow_active_execution": True,
                    "allowed_working_directories": [allowed_dir],
                },
            })

            req = ExecutionRequest(
                executable=self.python_exe,
                command_line=[self.python_exe, "-c", "pass"],
                working_directory=traversal_path,
            )
            result = launcher.launch(req)
            self.assertFalse(result.executed)
            mock_popen.assert_not_called()
        finally:
            shutil.rmtree(temp_base, ignore_errors=True)

    @patch("subprocess.Popen")
    def test_environment_validation_rejects_non_string_mappings(self, mock_popen):
        launcher = ControlledLauncher(config=self.active_config)
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[self.python_exe, "-c", "pass"],
        )

        # Non-string value
        res1 = launcher.launch(req, env={"PORT": 8080})  # type: ignore
        self.assertFalse(res1.executed)
        self.assertIn("Environment override entry", res1.error)

        # Non-string key
        res2 = launcher.launch(req, env={123: "val"})  # type: ignore
        self.assertFalse(res2.executed)
        self.assertIn("Environment override entry", res2.error)

        # Non-dict env
        res3 = launcher.launch(req, env="not_a_dict")  # type: ignore
        self.assertFalse(res3.executed)
        self.assertIn("must be a dictionary", res3.error)

        mock_popen.assert_not_called()

    @patch("subprocess.Popen")
    def test_popen_creation_failure_returns_executed_false(self, mock_popen):
        # When subprocess.Popen raises OSError / PermissionError
        mock_popen.side_effect = PermissionError("Access denied by OS")

        launcher = ControlledLauncher(config=self.active_config)
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[self.python_exe, "-c", "pass"],
        )
        result = launcher.launch(req)
        self.assertFalse(result.executed)
        self.assertIn("Access denied", result.error)


class TestControlledRealExecution(unittest.TestCase):
    """
    Test real harmless execution ONLY when both execution gates are explicitly
    enabled in test configuration (dry_run=False and allow_active_execution=True).
    """

    def setUp(self):
        self.python_exe = sys.executable
        self.launcher = ControlledLauncher(
            config={
                "enabled": True,
                "dry_run": False,
                "launcher": {
                    "allow_active_execution": True,
                    "default_timeout_seconds": 15.0,
                    "max_output_bytes": 1024,
                    "allowed_working_directories": [],
                },
            },
            track_pids=True,
        )

    def test_harmless_real_execution_success(self):
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[self.python_exe, "-c", "import sys; sys.stdout.write('phase2_ok')"],
        )
        result = self.launcher.launch(req)
        self.assertTrue(result.executed)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "phase2_ok")
        self.assertEqual(result.stderr, "")
        self.assertFalse(result.stdout_truncated)
        self.assertFalse(result.stderr_truncated)
        self.assertFalse(result.truncated)
        self.assertFalse(result.timed_out)
        self.assertIsNone(result.error)
        self.assertGreater(result.pid, 0)
        # Tracking PID should be discarded upon reaping
        self.assertNotIn(result.pid, self.launcher.active_pids)

    def test_harmless_real_execution_with_stderr_and_exit_code(self):
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[
                self.python_exe,
                "-c",
                "import sys; sys.stderr.write('err_msg'); sys.exit(7)",
            ],
        )
        result = self.launcher.launch(req)
        self.assertTrue(result.executed)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stderr, "err_msg")
        self.assertFalse(result.timed_out)

    def test_harmless_real_execution_env_overrides(self):
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[
                self.python_exe,
                "-c",
                "import os, sys; sys.stdout.write(os.environ.get('TEST_PHASE2_VAR', 'NONE'))",
            ],
        )
        result = self.launcher.launch(req, env={"TEST_PHASE2_VAR": "HELLO_LAUNCHER"})
        self.assertTrue(result.executed)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "HELLO_LAUNCHER")

    def test_harmless_real_timeout_and_reaping(self):
        # Spawns a process that sleeps longer than timeout; verifies child is reaped
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[
                self.python_exe,
                "-c",
                "import time, sys; sys.stdout.write('started'); sys.stdout.flush(); time.sleep(10)",
            ],
        )
        start = time.time()
        result = self.launcher.launch(req, timeout=0.3)
        duration = time.time() - start

        self.assertTrue(result.executed)
        self.assertTrue(result.timed_out)
        self.assertIn("started", result.stdout)
        self.assertIsNotNone(result.returncode)
        self.assertIn("timed out", result.error)
        # Should finish quickly after timeout (around 0.3s + grace period, far less than 10s)
        self.assertLess(duration, 5.0)

    def test_harmless_bounded_output_truncation_without_deadlock(self):
        # Output 50,000 bytes when max_output_bytes is 512
        # Verifies stream is drained without pipe deadlock and stdout_truncated is True
        launcher = ControlledLauncher(
            config={
                "enabled": True,
                "dry_run": False,
                "launcher": {
                    "allow_active_execution": True,
                    "max_output_bytes": 512,
                },
            }
        )
        req = ExecutionRequest(
            executable=self.python_exe,
            command_line=[
                self.python_exe,
                "-c",
                "import sys; sys.stdout.write('A' * 50000); sys.stderr.write('B' * 50000)",
            ],
        )
        result = launcher.launch(req, timeout=5.0)
        self.assertTrue(result.executed)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout), 512)
        self.assertEqual(len(result.stderr), 512)
        self.assertTrue(result.stdout_truncated)
        self.assertTrue(result.stderr_truncated)
        self.assertTrue(result.truncated)


if __name__ == "__main__":
    unittest.main()
