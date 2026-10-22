"""
Unit Tests for Windows Process-Creation Telemetry (Security Event 4688).

The tests are fully mocked: no audit policy is modified, no administrator
privileges are required and the ordinary test suite never depends on the
Windows event log configuration of the host machine.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.execution.config import load_execution_config
from src.models.event import Event
from src.monitors.windows_process_telemetry import (
    PROCESS_CREATION_EVENT_ID,
    ProcessCreationEventParser,
    ProcessCreationTelemetryRecord,
    ProcessTelemetryCorrelator,
    TelemetryStatus,
    WindowsProcessTelemetryCollector,
)
from src.ui.engine import MonitoringEngine


VALID_4688_XML = """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing"/>
      <EventID>4688</EventID>
      <EventRecordID>4242</EventRecordID>
      <Channel>Security</Channel>
      <TimeCreated SystemTime="2026-10-21T10:00:00.000Z"/>
    </System>
    <EventData>
      <Data Name="SubjectUserSid">S-1-5-18</Data>
      <Data Name="SubjectUserName">SYSTEM</Data>
      <Data Name="SubjectDomainName">HOST</Data>
      <Data Name="NewProcessId">0x4</Data>
      <Data Name="NewParentProcessId">0x3c8</Data>
      <Data Name="NewProcessName">\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe</Data>
      <Data Name="CommandLine">"C:\\Windows\\System32\\cmd.exe" /c dir</Data>
      <Data Name="TokenElevationType">%%1842</Data>
    </EventData>
  </Event>
</Events>"""


NO_COMMAND_LINE_XML = """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing"/>
      <EventID>4688</EventID>
      <EventRecordID>4243</EventRecordID>
      <Channel>Security</Channel>
      <TimeCreated SystemTime="2026-10-21T10:00:05.000Z"/>
    </System>
    <EventData>
      <Data Name="SubjectUserName">alice</Data>
      <Data Name="NewProcessId">0x64</Data>
      <Data Name="NewParentProcessId">0x20</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\notepad.exe</Data>
    </EventData>
  </Event>
</Events>"""


MALFORMED_FIELDS_XML = """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>4688</EventID>
      <EventRecordID>4244</EventRecordID>
      <TimeCreated SystemTime="not-a-timestamp"/>
    </System>
    <EventData>
      <Data Name="NewProcessId">not-a-number</Data>
      <Data Name="NewParentProcessId"></Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>
</Events>"""


def _result(stdout="", returncode=0, stderr=""):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


class TestProcessCreationEventParser(unittest.TestCase):
    """Parsing of raw Windows Event Log XML payloads."""

    def setUp(self):
        self.parser = ProcessCreationEventParser()

    def test_parse_valid_process_creation_event(self):
        records = self.parser.parse_event_xml(VALID_4688_XML)
        self.assertEqual(len(records), 1)

        record = records[0]
        self.assertEqual(record.event_id, PROCESS_CREATION_EVENT_ID)
        self.assertEqual(record.record_id, "4242")
        self.assertEqual(record.record_sequence, 4242)
        self.assertEqual(record.pid, 4)
        self.assertEqual(record.ppid, 968)
        self.assertEqual(record.process_name, "cmd.exe")
        self.assertEqual(record.command_line, '"C:\\Windows\\System32\\cmd.exe" /c dir')
        self.assertEqual(record.subject_user, "SYSTEM")
        self.assertIn("command_line", record.fields_available)
        self.assertIn("pid", record.fields_available)

    def test_missing_command_line_is_reported_as_unavailable(self):
        records = self.parser.parse_event_xml(NO_COMMAND_LINE_XML)
        self.assertEqual(len(records), 1)

        record = records[0]
        self.assertIsNone(record.command_line)
        self.assertNotIn("command_line", record.fields_available)
        # A verified negative finding stays different from an absent value
        self.assertEqual(record.pid, 100)

    def test_malformed_fields_are_tolerated(self):
        records = self.parser.parse_event_xml(MALFORMED_FIELDS_XML)
        self.assertEqual(len(records), 1)

        record = records[0]
        self.assertIsNone(record.pid)
        self.assertIsNone(record.ppid)
        self.assertIsNotNone(record.timestamp)

    def test_malformed_xml_is_ignored(self):
        self.assertEqual(self.parser.parse_event_xml("<Events><Event>"), [])
        self.assertEqual(self.parser.parse_event_xml("not xml at all"), [])
        self.assertEqual(self.parser.parse_event_xml(""), [])

    def test_other_event_ids_are_ignored(self):
        xml = VALID_4688_XML.replace("4688", "4689")
        self.assertEqual(self.parser.parse_event_xml(xml), [])


class TestWindowsProcessTelemetryCollector(unittest.TestCase):
    """Collection behaviour, availability handling and cleanup."""

    def test_query_builds_incremental_xpath(self):
        collector = WindowsProcessTelemetryCollector()
        self.assertIn("EventID=4688", collector.build_query(0))
        self.assertIn("EventRecordID > 100", collector.build_query(100))

    def test_collects_new_records_only(self):
        collector = WindowsProcessTelemetryCollector()
        collector._executor = MagicMock(
            side_effect=[
                _result(VALID_4688_XML),   # baseline seeding
                _result(VALID_4688_XML),   # first collection
                _result(VALID_4688_XML),   # same record again -> no new records
                _result(NO_COMMAND_LINE_XML),
            ]
        )

        self.assertTrue(collector.seed_baseline())
        first = collector.query_live_events()
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0].pid, 4)

        # The same record must not be reported twice
        second = collector.query_live_events()
        self.assertEqual(second, [])

        third = collector.query_live_events()
        self.assertEqual(len(third), 1)
        self.assertEqual(third[0].pid, 100)

        self.assertGreaterEqual(collector.records_collected, 2)

    def test_access_denied_marks_source_unavailable(self):
        collector = WindowsProcessTelemetryCollector()
        collector._executor = MagicMock(
            return_value=_result(
                returncode=1,
                stderr="The specified channel could not be found. Access is denied.",
            )
        )

        self.assertFalse(collector.seed_baseline())
        self.assertEqual(collector.status, TelemetryStatus.UNAVAILABLE)
        self.assertEqual(collector.unavailable_reason, "access_denied")
        self.assertEqual(collector.query_live_events(), [])
        self.assertIn("administrative", (collector.last_error or "").lower())

    def test_missing_wevtutil_is_handled(self):
        collector = WindowsProcessTelemetryCollector()
        collector._executor = MagicMock(side_effect=FileNotFoundError())

        self.assertFalse(collector.seed_baseline())
        self.assertEqual(collector.status, TelemetryStatus.UNAVAILABLE)
        self.assertEqual(collector.unavailable_reason, "wevtutil_not_found")

    def test_query_timeout_is_not_fatal(self):
        import subprocess

        collector = WindowsProcessTelemetryCollector()
        collector._executor = MagicMock(
            side_effect=subprocess.TimeoutExpired(cmd="wevtutil.exe", timeout=10)
        )

        self.assertFalse(collector.seed_baseline())
        # A timeout is transient: the collector stays usable
        self.assertNotEqual(collector.status, TelemetryStatus.UNAVAILABLE)
        self.assertIsNotNone(collector.last_error)

    def test_close_releases_deduplication_state(self):
        collector = WindowsProcessTelemetryCollector()
        collector._executor = MagicMock(
            side_effect=[_result(VALID_4688_XML), _result(VALID_4688_XML)]
        )
        collector.seed_baseline()
        collector.query_live_events()
        collector.close()
        self.assertEqual(len(collector._seen_record_ids), 0)

    def test_status_snapshot_is_serializable(self):
        collector = WindowsProcessTelemetryCollector()
        snapshot = collector.get_status_snapshot()
        json.dumps(snapshot)
        self.assertIn("status", snapshot)
        self.assertIn("records_collected", snapshot)


class TestProcessTelemetryCorrelator(unittest.TestCase):
    """Normalization of telemetry records into the standard event model."""

    def setUp(self):
        self.parser = ProcessCreationEventParser()
        self.correlator = ProcessTelemetryCorrelator()
        self.record = self.parser.parse_event_xml(VALID_4688_XML)[0]

    def test_to_process_info_normalizes_fields(self):
        info = self.correlator.to_process_info(self.record)
        self.assertEqual(info["pid"], 4)
        self.assertEqual(info["ppid"], 968)
        self.assertEqual(info["name"], "cmd.exe")
        self.assertEqual(info["username"], "SYSTEM")
        self.assertIsInstance(info["cmdline"], list)
        self.assertTrue(any("cmd.exe" in token for token in info["cmdline"]))
        self.assertEqual(info["telemetry_source"], "Security")

    def test_to_event_preserves_source_and_metadata(self):
        event = self.correlator.to_event(self.record)
        self.assertIsInstance(event, Event)
        self.assertEqual(event.source, "windows_process_telemetry")
        self.assertEqual(event.event_type, "process_start")
        self.assertEqual(event.pid, 4)
        self.assertTrue(event.metadata["telemetry"]["command_line_available"])

    def test_correlates_with_running_snapshot(self):
        running = {
            4: {
                "pid": 4,
                "ppid": 968,
                "name": "cmd.exe",
                "parent_name": "services.exe",
                "username": "CORP\\alice",
                "cmdline": ["cmd.exe", "/c", "dir"],
                "create_time": self.record.timestamp,
            }
        }
        info = self.correlator.to_process_info(self.record, running_processes=running)
        self.assertEqual(info["parent_name"], "services.exe")
        self.assertEqual(info["username"], "CORP\\alice")
        self.assertTrue(info["live_process_matched"])

    def test_recycled_pid_does_not_inherit_unrelated_metadata(self):
        running = {
            4: {
                "pid": 4,
                "ppid": 968,
                "name": "unrelated.exe",
                "parent_name": "other.exe",
                "username": "other",
                "cmdline": ["unrelated.exe"],
                "create_time": self.record.timestamp + 3600,
            }
        }
        info = self.correlator.to_process_info(self.record, running_processes=running)
        self.assertFalse(info["live_process_matched"])
        self.assertEqual(info["name"], "cmd.exe")

    def test_missing_command_line_stays_none(self):
        record = self.parser.parse_event_xml(NO_COMMAND_LINE_XML)[0]
        info = self.correlator.to_process_info(record)
        self.assertIsNone(info["cmdline"])
        self.assertIsNone(info["command_line_raw"])


class TestEngineTelemetryIntegration(unittest.TestCase):
    """The telemetry source feeds the existing monitoring pipeline."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = os.path.join(self.temp_dir.name, "config.json")
        config = {
            "controlled_execution": {
                "enabled": True,
                "dry_run": True,
                "interception_enabled": False,
                "score_threshold": 7,
                "blocked_severities": ["HIGH"],
                "blocked_indicators": [],
                "fail_closed": True,
                "launcher": {
                    "allow_active_execution": False,
                    "default_timeout_seconds": 30,
                    "max_output_bytes": 65536,
                    "allowed_working_directories": [],
                },
                "windows_process_telemetry": {
                    "enabled": True,
                    "channel": "Security",
                    "event_id": 4688,
                    "max_events_per_query": 50,
                    "dedup_tolerance_seconds": 5.0,
                },
            }
        }
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)

        self.baseline_path = os.path.join(self.temp_dir.name, "baseline.json")
        self.parser = ProcessCreationEventParser()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _make_engine(self):
        return MonitoringEngine(
            config_path=self.config_path,
            poll_interval=1.0,
            baseline_path=self.baseline_path,
        )

    def test_configuration_defaults_are_safe(self):
        defaults = load_execution_config("config/does-not-exist.json")
        telemetry = defaults["windows_process_telemetry"]
        self.assertFalse(telemetry["enabled"])
        self.assertEqual(telemetry["channel"], "Security")
        self.assertEqual(telemetry["event_id"], 4688)

        loaded = load_execution_config(self.config_path)
        self.assertTrue(loaded["windows_process_telemetry"]["enabled"])

    def test_telemetry_event_is_ingested_through_the_normal_pipeline(self):
        engine = self._make_engine()
        record = self.parser.parse_event_xml(VALID_4688_XML)[0]

        with patch("src.ui.engine.get_running_processes", return_value={}), \
             patch("src.ui.engine.get_new_processes", return_value=[]), \
             patch.object(engine.resource_monitor, "check_resources", return_value={"status": "NORMAL", "metrics": {}}), \
             patch.object(engine.network_monitor, "check_connections", return_value={"total_connections": 0, "outbound_connections": 0, "suspicious_events": []}), \
             patch.object(engine.login_monitor, "check_logon_events", return_value=[]), \
             patch.object(engine.process_telemetry_collector, "query_live_events", return_value=[record]):

            engine.refresh_once()

        events = engine.get_events_snapshot()
        telemetry_events = [e for e in events if e.source == "windows_process_telemetry"]
        self.assertEqual(len(telemetry_events), 1)
        self.assertEqual(telemetry_events[0].pid, 4)
        self.assertEqual(telemetry_events[0].event_type, "process_start")
        self.assertTrue(telemetry_events[0].metadata["telemetry"]["command_line_available"])

        engine.stop()

    def test_polling_and_telemetry_do_not_duplicate_the_same_process(self):
        engine = self._make_engine()
        record = self.parser.parse_event_xml(VALID_4688_XML)[0]

        create_time = record.timestamp
        running = {
            4: {
                "pid": 4,
                "ppid": 968,
                "name": "cmd.exe",
                "parent_name": "services.exe",
                "username": "SYSTEM",
                "cmdline": ["cmd.exe", "/c", "dir"],
                "create_time": create_time,
                "status": "running",
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
            }
        }

        with patch("src.ui.engine.get_running_processes", return_value=running), \
             patch("src.ui.engine.get_new_processes", return_value=list(running.values())), \
             patch.object(engine.resource_monitor, "check_resources", return_value={"status": "NORMAL", "metrics": {}}), \
             patch.object(engine.network_monitor, "check_connections", return_value={"total_connections": 0, "outbound_connections": 0, "suspicious_events": []}), \
             patch.object(engine.login_monitor, "check_logon_events", return_value=[]), \
             patch.object(engine.process_telemetry_collector, "query_live_events", return_value=[record]):

            engine.refresh_once()

        events = engine.get_events_snapshot()
        process_events = [e for e in events if e.pid == 4]
        self.assertEqual(len(process_events), 1)
        self.assertEqual(process_events[0].source, "process_monitor")

        engine.stop()

    def test_pid_reuse_creates_a_new_event(self):
        engine = self._make_engine()
        record = self.parser.parse_event_xml(VALID_4688_XML)[0]

        running = {
            4: {
                "pid": 4,
                "ppid": 968,
                "name": "cmd.exe",
                "parent_name": "services.exe",
                "username": "SYSTEM",
                "cmdline": ["cmd.exe", "/c", "dir"],
                # Different creation time: the PID was recycled
                "create_time": record.timestamp + 3600,
                "status": "running",
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
            }
        }

        with patch("src.ui.engine.get_running_processes", return_value=running), \
             patch("src.ui.engine.get_new_processes", return_value=[]), \
             patch.object(engine.resource_monitor, "check_resources", return_value={"status": "NORMAL", "metrics": {}}), \
             patch.object(engine.network_monitor, "check_connections", return_value={"total_connections": 0, "outbound_connections": 0, "suspicious_events": []}), \
             patch.object(engine.login_monitor, "check_logon_events", return_value=[]), \
             patch.object(engine.process_telemetry_collector, "query_live_events", return_value=[record]):

            engine.refresh_once()

        events = engine.get_events_snapshot()
        telemetry_events = [e for e in events if e.source == "windows_process_telemetry"]
        self.assertEqual(len(telemetry_events), 1)

        engine.stop()

    def test_unavailable_source_keeps_polling_functional(self):
        engine = self._make_engine()
        running = {
            10: {
                "pid": 10,
                "ppid": 1,
                "name": "notepad.exe",
                "parent_name": "explorer.exe",
                "username": "tester",
                "cmdline": ["notepad.exe"],
                "create_time": 1790000000.0,
                "status": "running",
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
            }
        }

        def _unavailable(*args, **kwargs):
            raise AssertionError("the collector must fail open, not raise")

        with patch("src.ui.engine.get_running_processes", return_value=running), \
             patch("src.ui.engine.get_new_processes", return_value=list(running.values())), \
             patch.object(engine.resource_monitor, "check_resources", return_value={"status": "NORMAL", "metrics": {}}), \
             patch.object(engine.network_monitor, "check_connections", return_value={"total_connections": 0, "outbound_connections": 0, "suspicious_events": []}), \
             patch.object(engine.login_monitor, "check_logon_events", return_value=[]), \
             patch.object(
                 engine.process_telemetry_collector,
                 "query_live_events",
                 side_effect=Exception("channel unavailable"),
             ):

            engine.refresh_once()

        self.assertEqual(len(engine.get_processes_snapshot()), 1)
        status = engine.get_process_telemetry_status()
        self.assertTrue(status["enabled"])
        self.assertIn("failed", " ".join(engine.get_state_snapshot()["errors"]).lower())

        engine.stop()


class TestWindowsTelemetryIntegration(unittest.TestCase):
    """
    Windows-only integration check for the live event log source.

    The test is skipped when the Security channel cannot be read (missing
    administrator privileges or a disabled "Audit Process Creation" policy).
    The ordinary unit test suite never depends on either.
    """

    def test_live_collection_of_a_short_lived_process(self):
        import subprocess
        import sys

        if sys.platform != "win32":
            self.skipTest("Windows event log source is only available on Windows.")

        collector = WindowsProcessTelemetryCollector()

        if not collector.seed_baseline():
            self.skipTest(
                "Windows Security channel is not readable "
                f"({collector.unavailable_reason or 'unknown reason'})."
            )

        child = subprocess.Popen(
            [sys.executable, "-c", "pass", "ESM_TELEMETRY_PROBE"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            child.wait(timeout=10)
        except Exception:
            child.kill()

        records = collector.query_live_events()
        observed = [
            record
            for record in records
            if record.pid is not None and record.pid == child.pid
        ]

        if not observed:
            self.skipTest(
                "Process creation events are not recorded on this machine "
                "(the 'Audit Process Creation' audit policy is most likely disabled)."
            )

        record = observed[0]
        self.assertIsNotNone(record.pid)
        self.assertIsNotNone(record.ppid)
        self.assertIsNotNone(record.process_name)
        # The command line is only present when the additional audit policy
        # for command line inclusion is enabled.
        if record.command_line is not None:
            self.assertIn("command_line", record.fields_available)


if __name__ == "__main__":
    unittest.main()
