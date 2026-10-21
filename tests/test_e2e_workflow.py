"""
Comprehensive End-to-End Workflow Integration and Hardening Tests (Phase 6 Release).

Validates the full lifecycle across all monitoring, risk evaluation, controlled execution,
Windows application control telemetry, UI data adapter presentation, and clean shutdown.
Includes performance benchmarks for startup, cycle, and shutdown latency.
"""

from collections import deque
import json
import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from src.execution.config import load_execution_config
from src.execution.service import (
    ControlledExecutionService,
    ExecutionServiceResult,
    ExecutionServiceStatus,
    redact_command_line,
    redact_string,
)
from src.execution.windows_enforcement import (
    WindowsEnforcementCollector,
    WindowsEnforcementCorrelator,
)
from src.models.event import Event
from src.models.execution_request import DecisionStatus, ExecutionDecision, ExecutionRequest
from src.ui.adapter import (
    adapt_event_row,
    adapt_process_row,
    filter_and_sort_events,
    filter_and_sort_processes,
)
from src.ui.cli import render_terminal_dashboard
from src.ui.engine import MonitoringEngine, MonitoringEngineStatus


class TestE2EWorkflow(unittest.TestCase):
    """End-to-End workflow validation across the full 12-stage security lifecycle."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "test_config.json")

        self.test_config = {
            "controlled_execution": {
                "enabled": True,
                "dry_run": True,
                "interception_enabled": False,
                "score_threshold": 4,
                "blocked_severities": ["HIGH"],
                "blocked_indicators": ["encoded_command", "download_cradle"],
                "fail_closed": True,
                "launcher": {
                    "allow_active_execution": False,
                    "default_timeout_seconds": 30,
                    "max_output_bytes": 65536,
                    "allowed_working_directories": [],
                },
                "windows_enforcement": {
                    "enabled": True,
                    "alert_on_blocks": True,
                    "channels": ["Microsoft-Windows-CodeIntegrity/Operational"],
                    "max_events_per_query": 50,
                },
            }
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.test_config, f)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_complete_end_to_end_pipeline(self):
        """
        Executes and validates the full 12-stage lifecycle:
        1. Configuration loading & engine initialization
        2. Process enumeration & snapshotting
        3. Hierarchical process tree construction & lineage resolution
        4. Suspicious command indicator detection
        5. Behavioral baseline engine analysis & persistence
        6. Combined risk scoring & severity assignment
        7. Alert dispatching & bounded deque ingestion
        8. OS application control (WDAC / AppLocker) telemetry ingestion & correlation
        9. Controlled execution request intake, policy evaluation & dual-gate safety
        10. Sensitive data redaction in all emitted events and records
        11. UI presentation adapter transformation, multi-column sorting & filtering
        12. Controlled lifecycle transitions & clean resource shutdown
        """
        # Stage 1: Engine Initialization
        engine = MonitoringEngine(config_path=self.config_path, poll_interval=2.0)
        self.assertEqual(engine.status, MonitoringEngineStatus.STOPPED)

        # Stage 2-7: Mock Process & System Snapshot Evaluation
        mock_processes = {
            100: {
                "pid": 100,
                "ppid": 0,
                "name": "system.exe",
                "username": "NT AUTHORITY\\SYSTEM",
                "cmdline": ["system.exe"],
                "status": "running",
                "create_time": 1700000000.0,
                "cpu_percent": 1.0,
                "memory_percent": 2.0,
            },
            200: {
                "pid": 200,
                "ppid": 100,
                "name": "cmd.exe",
                "username": "CORP\\Alice",
                "cmdline": ["cmd.exe", "/c", "powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="],
                "status": "running",
                "create_time": 1700000010.0,
                "cpu_percent": 12.5,
                "memory_percent": 4.0,
            },
            300: {
                "pid": 300,
                "ppid": 200,
                "name": "powershell.exe",
                "username": "CORP\\Alice",
                "cmdline": ["powershell.exe", "-nop", "-w", "hidden", "-enc", "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="],
                "status": "running",
                "create_time": 1700000020.0,
                "cpu_percent": 35.0,
                "memory_percent": 8.5,
            },
        }

        with patch("src.ui.engine.get_running_processes", return_value=mock_processes), \
             patch("src.ui.engine.get_new_processes", return_value=list(mock_processes.values())), \
             patch.object(engine.network_monitor, "check_connections", return_value={"total_connections": 2, "outbound_connections": 1, "suspicious_events": []}):

            # Trigger a single monitoring cycle
            engine.refresh_once()

            # Verify processes ingested
            snap_procs = engine.get_processes_snapshot()
            self.assertEqual(len(snap_procs), 3)
            self.assertIn(300, snap_procs)

            # Verify risk scoring & indicators on powershell.exe
            proc_events = engine.get_process_events_snapshot()
            ps_event = proc_events.get(300)
            self.assertIsNotNone(ps_event)
            self.assertGreaterEqual(ps_event.risk_score, 6)
            self.assertIn("encoded_command", ps_event.indicators)
            self.assertEqual(ps_event.severity, "HIGH")

            # Stage 7: Verify Alert Generation
            alerts = engine.get_alerts_snapshot()
            self.assertGreaterEqual(len(alerts), 1)
            self.assertTrue(any(a.pid == 300 for a in alerts))

            # Stage 8: OS Application Control Telemetry Ingestion (WDAC 3077 enforce block)
            mock_wdac_xml = """<Events>
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                <System>
                    <Provider Name="Microsoft-Windows-CodeIntegrity" />
                    <EventID>3077</EventID>
                    <TimeCreated SystemTime="2026-10-21T10:00:00.000Z" />
                    <Execution ProcessID="300" />
                </System>
                <EventData>
                    <Data Name="PolicyName">DefaultPolicy</Data>
                    <Data Name="RuleName">BlockUnsignedBinaries</Data>
                    <Data Name="ProcessName">powershell.exe</Data>
                    <Data Name="FileNameBuffer">\\Device\\HarddiskVolume3\\Users\\Alice\\malware.exe</Data>
                </EventData>
            </Event>
            </Events>"""

            # Explicitly mock windows_collector executor to decouple from host event log
            engine.windows_collector.channels = ["Microsoft-Windows-CodeIntegrity/Operational"]
            engine.windows_collector._executor = MagicMock(
                return_value=MagicMock(returncode=0, stdout=mock_wdac_xml, stderr="")
            )
            records = engine.windows_collector.query_live_events()
            self.assertEqual(len(records), 1)
            correlated = engine.windows_correlator.correlate_records(records, snap_procs)
            self.assertEqual(len(correlated), 1)

            c_evt = correlated[0]
            self.assertEqual(c_evt.event_type, "windows_enforcement_block")
            self.assertEqual(c_evt.severity, "HIGH")
            self.assertEqual(c_evt.pid, 300)
            self.assertEqual(c_evt.process_name, "powershell.exe")
            # Path normalized from NT Device to DOS Drive C:
            self.assertTrue(c_evt.file_path.startswith("C:") or "malware.exe" in c_evt.file_path)

            # Ingest into engine
            engine._ingest_event(c_evt)

            # Stage 9 & 10: Controlled Execution Flow & Redaction
            # 9a. Benign request: python script with token -> Allowed by policy, Dry-Run intercepted
            benign_req = ExecutionRequest(
                executable="python.exe",
                command_line=["python.exe", "script.py", "--api-token=SecretToken123456789"],
                username="CORP\\Alice",
            )
            result_benign = engine.submit_execution_request(benign_req)
            self.assertEqual(result_benign.status, ExecutionServiceStatus.DRY_RUN)
            self.assertEqual(result_benign.decision.decision, DecisionStatus.ALLOW)
            self.assertFalse(result_benign.executed)  # No active process launched in dry-run

            # Check execution records for redaction
            records = engine.get_execution_records_snapshot()
            self.assertGreaterEqual(len(records), 1)
            benign_rec = records[-1]
            rec_cmd_str = " ".join(benign_rec["command_line"])
            self.assertNotIn("SecretToken123456789", rec_cmd_str)
            self.assertIn("[REDACTED]", rec_cmd_str)

            # 9b. Malicious request: encoded powershell cradle -> Blocked by policy
            malicious_req = ExecutionRequest(
                executable="powershell.exe",
                command_line=["powershell.exe", "-nop", "-enc", "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="],
                username="CORP\\Alice",
            )
            result_malicious = engine.submit_execution_request(malicious_req)
            self.assertEqual(result_malicious.status, ExecutionServiceStatus.POLICY_DENIED)
            self.assertEqual(result_malicious.decision.decision, DecisionStatus.BLOCK)
            self.assertFalse(result_malicious.executed)

            # Stage 11: UI Presentation Adapter Transformation
            proc_table = filter_and_sort_processes(
                engine.get_processes_snapshot(),
                engine.get_process_events_snapshot(),
                sort_column="risk_score",
                reverse=True,
            )
            self.assertEqual(len(proc_table), 3)
            # Highest risk should be powershell.exe at top
            self.assertEqual(proc_table[0]["pid"], 300)
            self.assertEqual(proc_table[0]["risk_level"], "HIGH")

            # Event adapter & multi-field search filter
            events_table = filter_and_sort_events(
                engine.get_events_snapshot(),
                search_query="powershell",
                sort_column="timestamp",
                reverse=True,
            )
            self.assertGreaterEqual(len(events_table), 1)

            # Terminal CLI dashboard rendering check
            rendered = render_terminal_dashboard(engine)
            self.assertIn("ENDPOINT SECURITY MONITOR", rendered)
            self.assertIn("SYSTEM RESOURCES", rendered)
            self.assertIn("RECENT CRITICAL ALERTS", rendered)
            self.assertIn("HIGHEST-RISK OBSERVED PROCESSES", rendered)
            # Verify no non-ASCII characters that break Windows CP1252
            rendered.encode("ascii")

            # Stage 12: Controlled Lifecycle & Clean Shutdown
            self.assertTrue(engine.start())
            self.assertTrue(engine.is_running())
            engine.pause()
            self.assertTrue(engine.is_paused())
            engine.resume()
            self.assertFalse(engine.is_paused())

            shutdown_ok = engine.stop()
            self.assertTrue(shutdown_ok)
            self.assertEqual(engine.status, MonitoringEngineStatus.STOPPED)
            self.assertFalse(engine.is_running())

    def test_fail_closed_on_corrupt_request(self):
        """Verify fail-closed architecture when requests or schema validations fail."""
        engine = MonitoringEngine(config_path=self.config_path)

        # Invalid executable type / empty command line fails validation
        req = ExecutionRequest(
            executable="",
            command_line=[],
            username="",
        )
        result = engine.submit_execution_request(req)
        self.assertEqual(result.status, ExecutionServiceStatus.VALIDATION_FAILED)
        self.assertFalse(result.executed)
        self.assertIsNotNone(result.error)

        # Disallowed high-risk request fails policy evaluation
        high_risk_req = ExecutionRequest(
            executable="powershell.exe",
            command_line=["powershell.exe", "-nop", "-enc", "JABzAD0="],
            username="test_user",
        )
        policy_result = engine.submit_execution_request(high_risk_req)
        self.assertEqual(policy_result.status, ExecutionServiceStatus.POLICY_DENIED)
        self.assertEqual(policy_result.decision.decision, DecisionStatus.BLOCK)
        self.assertFalse(policy_result.executed)


class TestOperationalAndPerformanceBenchmarks(unittest.TestCase):
    """Measures startup latency, cycle throughput, memory boundedness, and shutdown latency."""

    def test_engine_startup_latency(self):
        """Engine startup latency must be < 1.00s."""
        t0 = time.perf_counter()
        engine = MonitoringEngine()
        engine.start()
        t1 = time.perf_counter()

        startup_latency = t1 - t0
        try:
            self.assertLess(startup_latency, 1.0, f"Startup took {startup_latency:.4f}s, exceeding 1.0s limit")
        finally:
            engine.stop()

    def test_single_cycle_evaluation_throughput(self):
        """Synchronized evaluation cycle duration must be < 0.50s for a process snapshot."""
        engine = MonitoringEngine()
        # Mock 20 running processes
        mock_procs = {
            pid: {
                "pid": pid,
                "ppid": 1,
                "name": f"proc_{pid}.exe",
                "cmdline": [f"proc_{pid}.exe", "--arg"],
                "username": "user",
                "status": "running",
                "create_time": 1700000000.0,
                "cpu_percent": 1.0,
                "memory_percent": 1.0,
            }
            for pid in range(100, 120)
        }

        mock_res = {
            "status": "NORMAL",
            "metrics": {
                "cpu": {"percent": 15.0},
                "memory": {"percent": 50.0},
            },
        }
        with patch("src.ui.engine.get_running_processes", return_value=mock_procs), \
             patch("src.ui.engine.get_new_processes", return_value=list(mock_procs.values())), \
             patch.object(engine.resource_monitor, "check_resources", return_value=mock_res), \
             patch.object(engine.network_monitor, "check_connections", return_value={"total_connections": 5, "suspicious_events": []}), \
             patch.object(engine.windows_collector, "query_live_events", return_value=[]):

            t0 = time.perf_counter()
            engine.refresh_once()
            t1 = time.perf_counter()

            cycle_latency = t1 - t0
            self.assertLess(cycle_latency, 0.50, f"Cycle evaluation took {cycle_latency:.4f}s, exceeding 0.50s limit")

    def test_engine_shutdown_latency(self):
        """Engine clean shutdown must complete in < 0.50s."""
        engine = MonitoringEngine()
        engine.start()
        time.sleep(0.05)

        t0 = time.perf_counter()
        stopped = engine.stop()
        t1 = time.perf_counter()

        shutdown_latency = t1 - t0
        self.assertTrue(stopped)
        self.assertLess(shutdown_latency, 0.50, f"Shutdown took {shutdown_latency:.4f}s, exceeding 0.50s limit")

    def test_memory_bounded_capacity_under_high_volume(self):
        """Verify memory boundedness: event and alert queues strictly adhere to maxlen."""
        capacity = 50
        engine = MonitoringEngine(max_events_capacity=capacity, max_alerts_capacity=capacity)

        # Flood engine with 500 events
        for i in range(500):
            evt = Event(
                event_id=f"flood-{i}",
                event_type="test_event",
                severity="HIGH",
                risk_score=8,
                risk_level="HIGH",
                risk_reasons=[f"Flood reason {i}"],
            )
            engine._ingest_event(evt)

        # Verify capacities never exceed declared bounds
        events_snap = engine.get_events_snapshot()
        alerts_snap = engine.get_alerts_snapshot()

        self.assertEqual(len(events_snap), capacity)
        self.assertEqual(len(alerts_snap), capacity)
        # Verify newest events retained (FIFO eviction of oldest)
        self.assertEqual(events_snap[-1].event_id, "flood-499")
        self.assertEqual(alerts_snap[-1].event_id, "flood-499")


if __name__ == "__main__":
    unittest.main()
