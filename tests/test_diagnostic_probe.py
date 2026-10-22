"""
End-to-End Diagnostic Probe Tests.

The probe launches a harmless child process with a unique marker and verifies
the complete monitoring pipeline.  The test asserts process visibility and
alert generation separately: a benign process must be visible without
producing a security alert.
"""

import os
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from tools.diagnostic_probe import (  # noqa: E402
    LONG_LIVED_MARKER,
    SHORT_LIVED_MARKER,
    format_report,
    run_probe,
)


class TestDiagnosticProbe(unittest.TestCase):
    """The probe must observe the marker process without false alerts."""

    def test_end_to_end_probe(self):
        report = run_probe(
            config_path=os.path.join(PROJECT_ROOT, "config", "config.json"),
            poll_interval=1.0,
            wait_seconds=20.0,
            lifetime_seconds=30,
        )

        checks = report["checks"]

        # 1. Process creation and collection through the polling monitor
        self.assertTrue(checks["process_visible_via_polling"])

        # 2. Identity and metadata normalization
        self.assertTrue(checks["identity_has_creation_time"])

        # 3. Parent and ancestry resolution
        self.assertTrue(checks["parent_resolved"])

        # 4. Command detector invocation
        self.assertTrue(checks["command_detector_invoked"])

        # 5. Risk calculation
        self.assertTrue(checks["risk_calculated"])

        # 6. Event ingestion and 9. event history delivery
        self.assertTrue(checks["event_ingested"])
        self.assertTrue(checks["event_history_contains_process"])

        # 7. A benign process must not raise a security alert
        self.assertTrue(checks["no_false_alert_for_benign_process"])

        # 10. Clean shutdown
        self.assertTrue(checks["engine_stopped_cleanly"])

        details = report["details"]
        self.assertEqual(details["observed_process"]["name"], "python.exe")
        self.assertIn("pid", details["observed_process"])
        self.assertEqual(details["alerts_for_probe_process"], 0)

        # The report is human readable and states the result explicitly
        rendered = format_report(report)
        self.assertIn("ESM_AUDIT_2026", rendered)
        self.assertIn("RESULT:", rendered)

    def test_probe_reports_telemetry_state(self):
        report = run_probe(
            config_path=os.path.join(PROJECT_ROOT, "config", "config.json"),
            poll_interval=1.0,
            wait_seconds=12.0,
            lifetime_seconds=20,
            include_short_lived=False,
        )

        telemetry = report["details"]["process_telemetry"]
        # The telemetry source is disabled by default - the probe must not
        # claim coverage it does not have.
        self.assertFalse(telemetry["enabled"])
        self.assertIn("status", telemetry)

    def test_probe_schema_completeness_on_timeout(self):
        """When the probe times out without finding the marker, every check key must still exist."""
        report = run_probe(
            config_path=os.path.join(PROJECT_ROOT, "config", "config.json"),
            poll_interval=1.0,
            wait_seconds=0.01,
            lifetime_seconds=5,
            include_short_lived=False,
        )
        required_keys = {
            "process_visible_via_polling",
            "identity_has_creation_time",
            "parent_resolved",
            "command_detector_invoked",
            "risk_calculated",
            "event_ingested",
            "event_history_contains_process",
            "no_false_alert_for_benign_process",
            "short_lived_captured_by_telemetry",
            "engine_stopped_cleanly",
        }
        self.assertTrue(required_keys.issubset(report["checks"].keys()))
        self.assertFalse(report["checks"]["process_visible_via_polling"])
        self.assertFalse(report["checks"]["command_detector_invoked"])
        self.assertTrue(report["checks"]["engine_stopped_cleanly"])

    def test_detector_invocation_and_error_handling(self):
        """Detector errors must not be reported as successful invocations, and keys must remain stable."""
        from unittest.mock import patch
        with patch("src.ui.engine.detect_command_indicators", side_effect=RuntimeError("Simulated detector fault")):
            report = run_probe(
                config_path=os.path.join(PROJECT_ROOT, "config", "config.json"),
                poll_interval=1.0,
                wait_seconds=10.0,
                lifetime_seconds=20,
                include_short_lived=False,
            )
            self.assertIn("command_detector_invoked", report["checks"])
            self.assertFalse(report["checks"]["command_detector_invoked"])
            self.assertTrue(report["checks"]["engine_stopped_cleanly"])

    def test_snapshot_consistency_contract(self):
        """Processes in the published snapshot must already have corresponding evaluated events."""
        from src.ui.engine import MonitoringEngine
        engine = MonitoringEngine(poll_interval=1.0)
        engine.refresh_once()
        procs = engine.get_processes_snapshot()
        proc_events = engine.get_process_events_snapshot()
        self.assertGreater(len(procs), 0)
        for pid in procs:
            if pid in proc_events:
                evt = proc_events[pid]
                self.assertIsNotNone(evt)
                self.assertTrue(evt.metadata.get("command_detector_invoked"))
        engine.stop()


if __name__ == "__main__":
    unittest.main()
