"""
Unit and Integration Tests for UI Presentation, Adapter, and Monitoring Engine (Phase 5).
"""

import os
import queue
import time
import unittest
from unittest.mock import MagicMock, patch

from src.models.event import Event
from src.models.execution_request import ExecutionRequest
from src.ui.adapter import (
    SEVERITY_COLORS,
    adapt_event_row,
    adapt_file_event_row,
    adapt_network_event_row,
    adapt_process_row,
    filter_and_sort_events,
    filter_and_sort_processes,
    format_bytes,
    format_percent,
    format_timestamp,
    get_severity_color,
)
from src.ui.cli import render_terminal_dashboard
from src.ui.dashboard import SecurityDashboardApp, is_gui_available
from src.ui.engine import MonitoringEngine, MonitoringEngineStatus


class TestUIAdapter(unittest.TestCase):
    """Test presentation formatting, filtering, sorting, and data adaptation."""

    def test_format_timestamp(self):
        self.assertEqual(format_timestamp(None), "N/A")
        self.assertEqual(format_timestamp(0), "N/A")
        self.assertEqual(format_timestamp(-100), "N/A")
        formatted = format_timestamp(1700000000)
        self.assertIn("2023", formatted)

    def test_format_bytes(self):
        self.assertEqual(format_bytes(None), "N/A")
        self.assertEqual(format_bytes(-5), "N/A")
        self.assertEqual(format_bytes(500), "500.0 B")
        self.assertEqual(format_bytes(2048), "2.0 KB")
        self.assertEqual(format_bytes(1048576 * 5), "5.0 MB")
        self.assertEqual(format_bytes(1073741824 * 3), "3.0 GB")

    def test_format_percent(self):
        self.assertEqual(format_percent(None), "N/A")
        self.assertEqual(format_percent(45.678), "45.7%")
        self.assertEqual(format_percent(100.0), "100.0%")
        self.assertEqual(format_percent("invalid"), "N/A")  # type: ignore

    def test_get_severity_color(self):
        self.assertEqual(get_severity_color("HIGH"), SEVERITY_COLORS["HIGH"])
        self.assertEqual(get_severity_color("MEDIUM"), SEVERITY_COLORS["MEDIUM"])
        self.assertEqual(get_severity_color("LOW"), SEVERITY_COLORS["LOW"])
        self.assertEqual(get_severity_color("UNKNOWN"), SEVERITY_COLORS["UNKNOWN"])
        self.assertEqual(get_severity_color(""), SEVERITY_COLORS["UNKNOWN"])

    def test_adapt_process_row_with_credential_redaction(self):
        proc_info = {
            "pid": 1234,
            "ppid": 100,
            "name": "powershell.exe",
            "cmdline": ["powershell.exe", "--password=SuperSecretPassword123"],
            "username": "CORP\\Administrator",
            "cpu_percent": 15.5,
            "memory_percent": 8.2,
        }
        event = Event(
            event_id="evt-1",
            risk_score=8,
            risk_level="HIGH",
            risk_reasons=["Suspicious command line"],
            metadata={"process_tree": {"lineage": ["explorer.exe", "powershell.exe"]}},
        )

        row = adapt_process_row(proc_info, event)
        self.assertEqual(row["pid"], 1234)
        self.assertEqual(row["ppid"], 100)
        self.assertEqual(row["name"], "powershell.exe")
        self.assertNotIn("SuperSecretPassword123", row["path"])
        self.assertEqual(row["risk_score"], 8)
        self.assertEqual(row["risk_level"], "HIGH")
        self.assertEqual(row["lineage"], "explorer.exe -> powershell.exe")

    def test_filter_and_sort_processes(self):
        procs = {
            101: {"pid": 101, "name": "notepad.exe", "ppid": 1, "username": "user1"},
            102: {"pid": 102, "name": "cmd.exe", "ppid": 1, "username": "user1"},
            103: {"pid": 103, "name": "powershell.exe", "ppid": 102, "username": "admin"},
        }
        events = {
            101: Event(pid=101, risk_score=1, risk_level="LOW"),
            102: Event(pid=102, risk_score=5, risk_level="MEDIUM"),
            103: Event(pid=103, risk_score=9, risk_level="HIGH", risk_reasons=["Encoded command"]),
        }

        # 1. Filter by severity HIGH
        high_rows = filter_and_sort_processes(procs, events, severity_filter="HIGH")
        self.assertEqual(len(high_rows), 1)
        self.assertEqual(high_rows[0]["pid"], 103)

        # 2. Search query matching name
        cmd_rows = filter_and_sort_processes(procs, events, search_query="cmd")
        self.assertEqual(len(cmd_rows), 1)
        self.assertEqual(cmd_rows[0]["pid"], 102)

        # 3. Sort by risk score descending
        sorted_rows = filter_and_sort_processes(
            procs, events, sort_column="risk_score", reverse=True
        )
        self.assertEqual(sorted_rows[0]["pid"], 103)
        self.assertEqual(sorted_rows[1]["pid"], 102)
        self.assertEqual(sorted_rows[2]["pid"], 101)

    def test_filter_and_sort_events(self):
        evts = [
            Event(
                event_id="e1",
                timestamp=1000,
                severity="LOW",
                source="process_monitor",
                process_name="calc.exe",
            ),
            Event(
                event_id="e2",
                timestamp=2000,
                severity="HIGH",
                source="windows_enforcement",
                process_name="bad.exe",
                risk_reasons=["Blocked by WDAC"],
            ),
            Event(
                event_id="e3",
                timestamp=1500,
                severity="MEDIUM",
                source="network_monitor",
                process_name="curl.exe",
            ),
        ]

        # Filter by source windows_enforcement
        win_rows = filter_and_sort_events(evts, source_filter="windows_enforcement")
        self.assertEqual(len(win_rows), 1)
        self.assertEqual(win_rows[0]["event_id"], "e2")

        # Filter by severity HIGH
        high_rows = filter_and_sort_events(evts, severity_filter="HIGH")
        self.assertEqual(len(high_rows), 1)
        self.assertEqual(high_rows[0]["event_id"], "e2")

        # Sort by timestamp descending
        sorted_rows = filter_and_sort_events(evts, sort_column="timestamp", reverse=True)
        self.assertEqual(sorted_rows[0]["event_id"], "e2")
        self.assertEqual(sorted_rows[1]["event_id"], "e3")
        self.assertEqual(sorted_rows[2]["event_id"], "e1")

    def test_adapt_network_and_file_rows(self):
        net_evt = Event(
            event_id="net-1",
            timestamp=1700000000,
            pid=5555,
            process_name="python.exe",
            risk_level="MEDIUM",
            indicators=["suspicious_port"],
            network_info={
                "local_address": "127.0.0.1:5000",
                "remote_address": "198.51.100.1:4444",
                "protocol": "TCP",
            },
        )
        net_row = adapt_network_event_row(net_evt)
        self.assertEqual(net_row["pid"], 5555)
        self.assertEqual(net_row["status"], "SUSPICIOUS")
        self.assertEqual(net_row["remote_address"], "198.51.100.1:4444")

        file_evt = Event(
            event_id="file-1",
            timestamp=1700000000,
            file_action="deleted",
            file_path="C:\\Temp\\key.pem",
            severity="HIGH",
        )
        file_row = adapt_file_event_row(file_evt)
        self.assertEqual(file_row["action"], "DELETED")
        self.assertEqual(file_row["file_path"], "C:\\Temp\\key.pem")


class TestMonitoringEngine(unittest.TestCase):
    """Test background MonitoringEngine lifecycle, synchronization, and telemetry queues."""

    def setUp(self):
        self.engine = MonitoringEngine(poll_interval=1.0, max_events_capacity=50)

    def tearDown(self):
        self.engine.stop(timeout=1.0)

    def test_initial_state(self):
        self.assertEqual(self.engine.status, MonitoringEngineStatus.STOPPED)
        self.assertFalse(self.engine.is_running())
        self.assertFalse(self.engine.is_paused())

    def test_start_pause_resume_stop_lifecycle(self):
        # Start
        self.assertTrue(self.engine.start())
        self.assertTrue(self.engine.is_running())
        self.assertEqual(self.engine.status, MonitoringEngineStatus.RUNNING)

        # Idempotent start
        self.assertTrue(self.engine.start())
        self.assertEqual(self.engine.status, MonitoringEngineStatus.RUNNING)

        # Pause
        self.engine.pause()
        self.assertTrue(self.engine.is_paused())
        self.assertEqual(self.engine.status, MonitoringEngineStatus.PAUSED)

        # Resume
        self.engine.resume()
        self.assertFalse(self.engine.is_paused())
        self.assertEqual(self.engine.status, MonitoringEngineStatus.RUNNING)

        # Stop
        self.assertTrue(self.engine.stop(timeout=1.0))
        self.assertFalse(self.engine.is_running())
        self.assertEqual(self.engine.status, MonitoringEngineStatus.STOPPED)

    def test_refresh_once_execution(self):
        self.engine.refresh_once()
        snap = self.engine.get_state_snapshot()
        self.assertIn("process_count", snap)
        self.assertIn("alert_counts", snap)
        self.assertIn("controlled_execution", snap)
        self.assertIn("windows_enforcement", snap)
        self.assertGreaterEqual(snap["process_count"], 0)

    def test_event_ingestion_and_bounded_capacity(self):
        small_engine = MonitoringEngine(max_events_capacity=5)
        for i in range(10):
            evt = Event(event_id=f"evt-{i}", severity="HIGH", risk_score=i)
            small_engine._ingest_event(evt)

        events = small_engine.get_events_snapshot()
        self.assertEqual(len(events), 5)
        # Should keep latest items (5..9)
        self.assertEqual(events[-1].event_id, "evt-9")

        # Check queue consumption
        pulled = small_engine.poll_new_events(max_items=20)
        self.assertGreater(len(pulled), 0)

    def test_submit_execution_request_integration(self):
        req = ExecutionRequest(
            executable="python.exe",
            command_line=["python.exe", "-c", "print(123)"],
            parent_pid=1,
        )
        result = self.engine.submit_execution_request(req)
        self.assertIsNotNone(result)

        records = self.engine.get_execution_records_snapshot()
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["request_id"], req.request_id)
        self.assertEqual(rec["executable"], "python.exe")
        self.assertIn("decision", rec)

    def test_error_recording_safety(self):
        self.engine._record_error("Test non-fatal error")
        snap = self.engine.get_state_snapshot()
        self.assertIn("Test non-fatal error", snap["errors"][-1])


class TestTerminalDashboard(unittest.TestCase):
    """Test text-based terminal dashboard rendering."""

    def test_render_terminal_dashboard(self):
        engine = MonitoringEngine()
        engine.refresh_once()
        text = render_terminal_dashboard(engine)
        self.assertIn("ENDPOINT SECURITY MONITOR", text)
        self.assertIn("Engine Status", text)
        self.assertIn("SYSTEM RESOURCES", text)
        self.assertIn("RECENT CRITICAL ALERTS", text)


class TestDashboardAppInit(unittest.TestCase):
    """Test desktop UI initialization and window binding."""

    def test_is_gui_available_boolean(self):
        res = is_gui_available()
        self.assertIsInstance(res, bool)

    def test_dashboard_app_mock_init(self):
        if not is_gui_available():
            self.skipTest("GUI display environment not available (headless mode).")

        import tkinter as tk
        try:
            root = tk.Tk()
        except Exception as e:
            self.skipTest(f"Tk environment unavailable: {e}")
        root.withdraw()  # Keep window hidden during test
        try:
            engine = MonitoringEngine()
            app = SecurityDashboardApp(engine=engine, root=root, auto_start=False)
            self.assertIsNotNone(app.notebook)
            self.assertIsNotNone(app.tree_processes)
            self.assertIsNotNone(app.tree_alerts)
            self.assertIsNotNone(app.tree_recent_alerts)

            # Test safe view update
            app._update_all_views()
            app.on_close()
        except Exception as e:
            root.destroy()
            raise e

    def test_overview_view_shows_process_count(self):
        """Overview tab must show accurate process counts from engine snapshot."""
        if not is_gui_available():
            self.skipTest("GUI display environment not available.")

        import tkinter as tk
        try:
            root = tk.Tk()
        except Exception as e:
            self.skipTest(f"Tk environment unavailable: {e}")
        root.withdraw()
        try:
            engine = MonitoringEngine()
            # Populate mock processes
            mock_procs = {
                1001: {"pid": 1001, "name": "service.exe", "ppid": 1, "username": "SYSTEM", "create_time": 100.0},
                1002: {"pid": 1002, "name": "app.exe", "ppid": 1001, "username": "user", "create_time": 105.0},
            }
            with engine._lock:
                engine._processes = mock_procs
            app = SecurityDashboardApp(engine=engine, root=root, auto_start=False)
            app._update_all_views()

            self.assertEqual(app.lbl_card_procs.cget("text"), "2")
            self.assertIn("Observed PIDs: 2", app.status_text_var.get())
            app.on_close()
        except Exception as e:
            root.destroy()
            raise e

    def test_tab_switch_populates_process_tree(self):
        """Switching to Process Explorer tab must immediately populate table from engine snapshot."""
        if not is_gui_available():
            self.skipTest("GUI display environment not available.")

        import tkinter as tk
        try:
            root = tk.Tk()
        except Exception as e:
            self.skipTest(f"Tk environment unavailable: {e}")
        root.withdraw()
        try:
            engine = MonitoringEngine()
            mock_procs = {
                1001: {"pid": 1001, "name": "explorer.exe", "ppid": 1, "username": "user", "create_time": 100.0},
                1002: {"pid": 1002, "name": "cmd.exe", "ppid": 1001, "username": "user", "create_time": 105.0},
            }
            with engine._lock:
                engine._processes = mock_procs
            app = SecurityDashboardApp(engine=engine, root=root, auto_start=False)

            # Initially on Overview tab, process tree has 0 rows
            initial_rows = len(app.tree_processes.get_children())
            self.assertEqual(initial_rows, 0)

            # Switch tab to Process Explorer
            app.notebook.select(app.tab_processes)
            app.notebook.event_generate("<<NotebookTabChanged>>")
            root.update_idletasks()

            # Now process tree must be populated
            updated_rows = len(app.tree_processes.get_children())
            self.assertEqual(updated_rows, 2)
            app.on_close()
        except Exception as e:
            root.destroy()
            raise e


if __name__ == "__main__":
    unittest.main()

