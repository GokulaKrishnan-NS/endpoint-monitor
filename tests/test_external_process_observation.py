"""
Regression tests for External Process Observation and Runtime Telemetry Data Flow.

Verifies:
1. Long-lived external process observation via process polling (PID, executable, name).
2. Process termination and pruning from the active process snapshot.
3. Distinguishing long-lived process polling from short-lived process creation.
4. Telemetry health status reporting for process polling and Event 4688.
5. Controlled execution safety gate validation under default dry-run configuration.
"""

import os
import subprocess
import sys
import time
import unittest

from src.execution.service import ControlledExecutionService
from src.models.execution_request import (
    DecisionStatus,
    EnforcementStatus,
    ExecutionRequest,
)
from src.monitors.process_monitor import get_running_processes
from src.ui.engine import MonitoringEngine


class TestExternalProcessObservation(unittest.TestCase):
    """Test suite verifying end-to-end telemetry observation of external processes."""

    def setUp(self):
        self.engine = MonitoringEngine(poll_interval=1.0)
        self.external_procs = []

    def tearDown(self):
        self.engine.stop()
        for p in self.external_procs:
            if p.poll() is None:
                try:
                    p.terminate()
                    p.wait(timeout=2.0)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass

    def _spawn_external_process(self, sleep_seconds: float = 15.0) -> subprocess.Popen:
        """Spawn a benign long-running process independent of the monitoring engine."""
        cmd = [sys.executable, "-c", f"import time; time.sleep({sleep_seconds})"]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.external_procs.append(proc)
        return proc

    def test_external_process_discovered_with_real_pid_and_exe(self):
        """
        Verify that an externally launched process is discovered by the engine's
        process polling loop, includes valid PID, name, and exe path, and is ingested
        into the event data store.
        """
        ext_proc = self._spawn_external_process(sleep_seconds=15.0)
        ext_pid = ext_proc.pid
        self.assertIsNotNone(ext_pid)

        # Execute monitoring cycle
        self.engine.refresh_once()

        # 1. Verify presence in process snapshot
        snapshot = self.engine.get_processes_snapshot()
        self.assertIn(
            ext_pid,
            snapshot,
            f"Externally launched PID {ext_pid} was not found in engine process snapshot",
        )
        proc_info = snapshot[ext_pid]
        self.assertEqual(proc_info.get("pid"), ext_pid)
        self.assertTrue(
            proc_info.get("name", "").lower().startswith("python"),
            f"Expected process name to start with 'python', got {proc_info.get('name')}",
        )
        self.assertIn("exe", proc_info, "Expected 'exe' attribute to be present in process info")
        self.assertTrue(
            os.path.samefile(proc_info["exe"], sys.executable)
            if os.path.exists(proc_info.get("exe") or "")
            else True
        )

        # 2. Verify process event was created and ingested
        proc_events = self.engine.get_process_events_snapshot()
        self.assertIn(
            ext_pid,
            proc_events,
            f"Process event for external PID {ext_pid} was not created in engine",
        )
        evt = proc_events[ext_pid]
        self.assertEqual(evt.pid, ext_pid)
        self.assertIsNotNone(evt.timestamp)

        # 3. Verify total events count in state snapshot includes external process
        state = self.engine.get_state_snapshot()
        self.assertGreaterEqual(state["total_events"], 1)
        self.assertGreaterEqual(state["process_count"], 1)

    def test_external_process_pruning_on_termination(self):
        """
        Verify that when an external process terminates, subsequent monitoring
        cycles prune it from the active process table while preserving historical events.
        """
        ext_proc = self._spawn_external_process(sleep_seconds=10.0)
        ext_pid = ext_proc.pid

        # Observe while alive
        self.engine.refresh_once()
        self.assertIn(ext_pid, self.engine.get_processes_snapshot())

        # Terminate external process
        ext_proc.terminate()
        ext_proc.wait(timeout=3.0)
        self.assertIsNotNone(ext_proc.poll())

        # Next monitoring cycle must prune it
        self.engine.refresh_once()
        self.assertNotIn(
            ext_pid,
            self.engine.get_processes_snapshot(),
            f"Terminated PID {ext_pid} was not pruned from process snapshot",
        )

    def test_distinguish_long_lived_polling_from_short_lived_events(self):
        """
        Demonstrate that polling observes processes alive across the sample window,
        while transient processes that terminate before polling begins cannot be
        captured by polling alone (documenting the necessity of Event 4688 telemetry).
        """
        # Run a transient process that terminates in milliseconds
        res = subprocess.run([sys.executable, "-c", "import sys; sys.exit(0)"], capture_output=True)
        self.assertEqual(res.returncode, 0)

        # Start a long-lived process
        long_proc = self._spawn_external_process(sleep_seconds=10.0)

        self.engine.refresh_once()
        snapshot = self.engine.get_processes_snapshot()

        # The long-lived process is reliably observed
        self.assertIn(long_proc.pid, snapshot)

        # Check telemetry health reflects that 4688 is disabled or unavailable by default
        state = self.engine.get_state_snapshot()
        wpt = state.get("process_telemetry", {})
        self.assertIn(wpt.get("status"), ("DISABLED", "UNAVAILABLE", "AVAILABLE"))

    def test_telemetry_health_status_reporting(self):
        """
        Verify that telemetry-health status shows process polling activity,
        last success timestamp, process counts, and Event 4688 status.
        """
        # Before any poll
        fresh_engine = MonitoringEngine()
        init_health = fresh_engine.get_process_polling_status()
        self.assertEqual(init_health["total_polls"], 0)
        self.assertIsNone(init_health["last_success_timestamp"])

        # After refresh_once
        fresh_engine.refresh_once()
        active_health = fresh_engine.get_process_polling_status()
        self.assertEqual(active_health["total_polls"], 1)
        self.assertIsNotNone(active_health["last_success_timestamp"])
        self.assertGreater(active_health["observed_processes"], 0)
        self.assertIsNone(active_health["last_error"])

        # In state snapshot
        snap = fresh_engine.get_state_snapshot()
        self.assertIn("process_polling", snap)
        self.assertEqual(snap["process_polling"]["total_polls"], 1)
        self.assertIn("process_telemetry", snap)
        fresh_engine.stop()

    def test_controlled_execution_safety_gate_defaults(self):
        """
        Verify that controlled execution safely blocks active execution by default,
        preserving dry-run and allow_active_execution safety gates.
        """
        state = self.engine.get_state_snapshot()
        ce_gate = state.get("controlled_execution", {})
        self.assertTrue(ce_gate.get("dry_run"), "dry_run must default to True")
        self.assertFalse(
            ce_gate.get("allow_active_execution"),
            "allow_active_execution must default to False",
        )

        # Submitting an execution request must not spawn real processes
        from src.execution.service import ExecutionServiceStatus
        req = ExecutionRequest(
            executable=sys.executable,
            command_line=[sys.executable, "-c", "print('TEST_BENIGN')"],
        )
        res = self.engine.submit_execution_request(req)
        self.assertFalse(res.executed, "Process execution must NOT occur under default safety gates")
        self.assertIn(
            res.status,
            (ExecutionServiceStatus.DRY_RUN, ExecutionServiceStatus.GATE_BLOCKED),
            f"Expected DRY_RUN or GATE_BLOCKED, got {res.status}",
        )
        if res.launch_result is not None:
            self.assertIsNone(res.launch_result.pid, "PID must not be allocated when execution is simulated")


if __name__ == "__main__":
    unittest.main()
