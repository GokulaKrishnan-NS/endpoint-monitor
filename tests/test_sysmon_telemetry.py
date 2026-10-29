"""
Unit and Integration Tests for Sysmon Telemetry Integration.

Tests cover:
- Event ID 1 (process creation) parsing and normalization
- Event ID 3 (network connection) parsing and normalization
- Field order independence (named event-data parsing)
- Missing and optional fields
- Malformed XML and malformed event fields
- Incremental collection with EventRecordID bookmarking
- Deduplication and log rollover / channel clear recovery
- Collector failure paths and diagnostic status snapshots
- Event normalization and risk detection pipeline integration
- Multi-source process correlation (psutil, 4688, Sysmon)
- Continuous monitoring loop integration
"""

import os
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.analysis.process_tree import ProcessTree, ProcessTreeAnalyzer
from src.baseline.baseline_engine import BaselineEngine
from src.detectors.command_detector import detect_command_indicators
from src.detectors.risk_detector import calculate_risk
from src.main import run_continuous_loop
from src.models.event import Event
from src.monitors.network_monitor import NetworkConnection, NetworkMonitor
from src.monitors.process_monitor import ProcessIdentityRegistry
from src.monitors.sysmon_telemetry import (
    SYSMON_CHANNEL,
    SYSMON_NETWORK_CONNECT_EVENT_ID,
    SYSMON_PROCESS_CREATION_EVENT_ID,
    SysmonEventParser,
    SysmonNetworkRecord,
    SysmonProcessRecord,
    SysmonTelemetryCollector,
    SysmonTelemetryCorrelator,
    SysmonTelemetryStatus,
    _parse_bool_value,
    _parse_hashes,
    _parse_int_value,
    _parse_timestamp,
)
from src.ui.engine import MonitoringEngine


VALID_SYSMON_EVENT1_XML = """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
      <EventID>1</EventID>
      <Version>5</Version>
      <EventRecordID>5001</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <TimeCreated SystemTime="2026-10-21T10:00:00.0000000Z" />
    </System>
    <EventData>
      <Data Name="RuleName">technique_id=T1059.001</Data>
      <Data Name="UtcTime">2026-10-21 10:00:00.000</Data>
      <Data Name="ProcessGuid">{AAAAAAAA-1111-2222-3333-444444444444}</Data>
      <Data Name="ProcessId">4096</Data>
      <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="CommandLine">"cmd.exe" /c echo hello</Data>
      <Data Name="CurrentDirectory">C:\\Users\\User\\</Data>
      <Data Name="User">WORKSTATION\\alice</Data>
      <Data Name="LogonGuid">{BBBBBBBB-1111-2222-3333-444444444444}</Data>
      <Data Name="LogonId">0x3e7</Data>
      <Data Name="TerminalSessionId">1</Data>
      <Data Name="IntegrityLevel">Medium</Data>
      <Data Name="Hashes">SHA256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855,MD5=D41D8CD98F00B204E9800998ECF8427E</Data>
      <Data Name="ParentProcessGuid">{CCCCCCCC-1111-2222-3333-444444444444}</Data>
      <Data Name="ParentProcessId">1024</Data>
      <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
      <Data Name="ParentCommandLine">C:\\Windows\\Explorer.EXE</Data>
      <Data Name="ParentUser">WORKSTATION\\alice</Data>
      <Data Name="OriginalFileName">Cmd.Exe</Data>
      <Data Name="Description">Windows Command Processor</Data>
      <Data Name="Product">Microsoft Windows Operating System</Data>
      <Data Name="Company">Microsoft Corporation</Data>
    </EventData>
  </Event>
</Events>"""


SHUFFLED_EVENT1_XML = """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>1</EventID>
      <EventRecordID>5002</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <TimeCreated SystemTime="2026-10-21T10:05:00.000Z" />
    </System>
    <EventData>
      <Data Name="ParentImage">C:\\Windows\\System32\\svchost.exe</Data>
      <Data Name="User">NT AUTHORITY\\SYSTEM</Data>
      <Data Name="ProcessId">2048</Data>
      <Data Name="ParentProcessId">500</Data>
      <Data Name="CommandLine">whoami.exe /all</Data>
      <Data Name="Image">C:\\Windows\\System32\\whoami.exe</Data>
      <Data Name="ProcessGuid">{DDDDDDDD-1111-2222-3333-444444444444}</Data>
    </EventData>
  </Event>
</Events>"""


VALID_SYSMON_EVENT3_XML = """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
      <EventID>3</EventID>
      <Version>5</Version>
      <EventRecordID>6001</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <TimeCreated SystemTime="2026-10-21T10:10:00.0000000Z" />
    </System>
    <EventData>
      <Data Name="RuleName">technique_id=T1071.001</Data>
      <Data Name="UtcTime">2026-10-21 10:10:00.000</Data>
      <Data Name="ProcessGuid">{AAAAAAAA-1111-2222-3333-444444444444}</Data>
      <Data Name="ProcessId">4096</Data>
      <Data Name="Image">C:\\Windows\\System32\\curl.exe</Data>
      <Data Name="User">WORKSTATION\\alice</Data>
      <Data Name="Protocol">tcp</Data>
      <Data Name="Initiated">true</Data>
      <Data Name="SourceIsIpv6">false</Data>
      <Data Name="SourceIp">192.168.1.100</Data>
      <Data Name="SourceHostname">ws-alice</Data>
      <Data Name="SourcePort">51234</Data>
      <Data Name="SourcePortName">ephemeral</Data>
      <Data Name="DestinationIsIpv6">false</Data>
      <Data Name="DestinationIp">93.184.216.34</Data>
      <Data Name="DestinationHostname">example.com</Data>
      <Data Name="DestinationPort">443</Data>
      <Data Name="DestinationPortName">https</Data>
    </EventData>
  </Event>
</Events>"""


SUSPICIOUS_EVENT3_XML = """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>3</EventID>
      <EventRecordID>6002</EventRecordID>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <TimeCreated SystemTime="2026-10-21T10:15:00.000Z" />
    </System>
    <EventData>
      <Data Name="ProcessId">8192</Data>
      <Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data>
      <Data Name="Protocol">tcp</Data>
      <Data Name="Initiated">true</Data>
      <Data Name="SourceIp">10.0.0.5</Data>
      <Data Name="SourcePort">55555</Data>
      <Data Name="DestinationIp">198.51.100.25</Data>
      <Data Name="DestinationPort">4444</Data>
    </EventData>
  </Event>
</Events>"""


MALFORMED_XML = "<Events><Event><System><EventID>1</EventID></Events>"


def _mock_result(stdout="", returncode=0, stderr=""):
    return MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)


class TestSysmonEventParser(unittest.TestCase):
    """Test XML parsing of Event ID 1 and Event ID 3 with named fields."""

    def setUp(self):
        self.parser = SysmonEventParser()

    def test_parse_valid_event_id_1(self):
        records = self.parser.parse_event_xml(VALID_SYSMON_EVENT1_XML)
        self.assertEqual(len(records), 1)

        rec = records[0]
        self.assertIsInstance(rec, SysmonProcessRecord)
        self.assertEqual(rec.event_id, SYSMON_PROCESS_CREATION_EVENT_ID)
        self.assertEqual(rec.record_id, "5001")
        self.assertEqual(rec.record_sequence, 5001)
        self.assertEqual(rec.pid, 4096)
        self.assertEqual(rec.parent_pid, 1024)
        self.assertEqual(rec.process_name, "cmd.exe")
        self.assertEqual(rec.parent_process_name, "explorer.exe")
        self.assertEqual(rec.command_line, '"cmd.exe" /c echo hello')
        self.assertEqual(rec.process_guid, "{AAAAAAAA-1111-2222-3333-444444444444}")
        self.assertEqual(rec.parent_process_guid, "{CCCCCCCC-1111-2222-3333-444444444444}")
        self.assertEqual(rec.user, "WORKSTATION\\alice")
        self.assertEqual(rec.integrity_level, "Medium")
        self.assertIn("SHA256", rec.hashes)
        self.assertIn("MD5", rec.hashes)
        self.assertEqual(rec.rule_name, "technique_id=T1059.001")
        self.assertIn("CommandLine", rec.fields_available)
        self.assertIn("Hashes", rec.fields_available)

    def test_parse_shuffled_field_order_event_1(self):
        records = self.parser.parse_event_xml(SHUFFLED_EVENT1_XML)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.pid, 2048)
        self.assertEqual(rec.parent_pid, 500)
        self.assertEqual(rec.process_name, "whoami.exe")
        self.assertEqual(rec.parent_process_name, "svchost.exe")
        self.assertEqual(rec.user, "NT AUTHORITY\\SYSTEM")

    def test_parse_missing_fields_stay_none(self):
        records = self.parser.parse_event_xml(SHUFFLED_EVENT1_XML)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertIsNone(rec.hashes_raw)
        self.assertEqual(rec.hashes, {})
        self.assertIsNone(rec.integrity_level)
        self.assertIsNone(rec.rule_name)
        self.assertNotIn("Hashes", rec.fields_available)

    def test_parse_valid_event_id_3(self):
        records = self.parser.parse_event_xml(VALID_SYSMON_EVENT3_XML)
        self.assertEqual(len(records), 1)

        rec = records[0]
        self.assertIsInstance(rec, SysmonNetworkRecord)
        self.assertEqual(rec.event_id, SYSMON_NETWORK_CONNECT_EVENT_ID)
        self.assertEqual(rec.record_id, "6001")
        self.assertEqual(rec.record_sequence, 6001)
        self.assertEqual(rec.pid, 4096)
        self.assertEqual(rec.process_name, "curl.exe")
        self.assertEqual(rec.protocol, "TCP")
        self.assertTrue(rec.initiated)
        self.assertEqual(rec.source_ip, "192.168.1.100")
        self.assertEqual(rec.source_port, 51234)
        self.assertEqual(rec.destination_ip, "93.184.216.34")
        self.assertEqual(rec.destination_port, 443)
        self.assertEqual(rec.destination_hostname, "example.com")
        self.assertEqual(rec.rule_name, "technique_id=T1071.001")

    def test_parse_malformed_xml_tolerated(self):
        self.assertEqual(self.parser.parse_event_xml(MALFORMED_XML), [])
        self.assertEqual(self.parser.parse_event_xml("not-xml"), [])
        self.assertEqual(self.parser.parse_event_xml(""), [])
        self.assertGreater(self.parser.malformed_count, 0)

    def test_other_event_ids_ignored(self):
        xml = VALID_SYSMON_EVENT1_XML.replace("<EventID>1</EventID>", "<EventID>2</EventID>")
        records = self.parser.parse_event_xml(xml)
        self.assertEqual(records, [])

    def test_missing_system_or_event_id_counted_as_malformed(self):
        bad_xml = "<Events><Event><EventData><Data Name='ProcessId'>123</Data></EventData></Event></Events>"
        records = self.parser.parse_event_xml(bad_xml)
        self.assertEqual(records, [])
        self.assertGreater(self.parser.malformed_count, 0)

    def test_helpers(self):
        self.assertEqual(_parse_int_value("0x10"), 16)
        self.assertEqual(_parse_int_value("100"), 100)
        self.assertIsNone(_parse_int_value("invalid"))
        self.assertIsNone(_parse_int_value(None))
        self.assertTrue(_parse_bool_value("true"))
        self.assertFalse(_parse_bool_value("false"))
        self.assertIsNone(_parse_bool_value(None))

        hashes = _parse_hashes("SHA256=ABC,MD5=DEF")
        self.assertEqual(hashes, {"SHA256": "ABC", "MD5": "DEF"})
        self.assertEqual(_parse_hashes(None), {})


class TestSysmonTelemetryCollector(unittest.TestCase):
    """Test Sysmon query building, incremental collection, rollover, and failure modes."""

    def test_build_query_variants(self):
        collector = SysmonTelemetryCollector(enable_process_events=True, enable_network_events=True)
        q = collector.build_query(0)
        self.assertIn("EventID=1", q)
        self.assertIn("EventID=3", q)

        # Only process events
        collector_proc = SysmonTelemetryCollector(enable_process_events=True, enable_network_events=False)
        q_proc = collector_proc.build_query(100)
        self.assertIn("EventID=1", q_proc)
        self.assertNotIn("EventID=3", q_proc)
        self.assertIn("EventRecordID > 100", q_proc)

        # Only network events
        collector_net = SysmonTelemetryCollector(enable_process_events=False, enable_network_events=True)
        q_net = collector_net.build_query(200)
        self.assertIn("EventID=3", q_net)
        self.assertNotIn("EventID=1", q_net)
        self.assertIn("EventRecordID > 200", q_net)

    def test_seed_baseline_success(self):
        executor = MagicMock(return_value=_mock_result(stdout=VALID_SYSMON_EVENT1_XML, returncode=0))
        collector = SysmonTelemetryCollector(executor=executor)

        self.assertTrue(collector.seed_baseline())
        self.assertEqual(collector.status, SysmonTelemetryStatus.AVAILABLE)
        self.assertEqual(collector.last_record_id, 5001)

    def test_seed_baseline_empty_channel(self):
        executor = MagicMock(return_value=_mock_result(stdout="<Events></Events>", returncode=0))
        collector = SysmonTelemetryCollector(executor=executor)

        self.assertTrue(collector.seed_baseline())
        self.assertEqual(collector.status, SysmonTelemetryStatus.AVAILABLE)
        self.assertEqual(collector.last_record_id, 0)

    def test_incremental_collection_and_deduplication(self):
        calls = []

        def executor(cmd, **kwargs):
            calls.append(cmd)
            if len(calls) == 1:
                # Baseline seed query
                return _mock_result(stdout=VALID_SYSMON_EVENT1_XML, returncode=0)
            elif len(calls) == 2:
                # Live query returning new Event 3
                return _mock_result(stdout=VALID_SYSMON_EVENT3_XML, returncode=0)
            else:
                # Next live query returning duplicate Event 3
                return _mock_result(stdout=VALID_SYSMON_EVENT3_XML, returncode=0)

        collector = SysmonTelemetryCollector(executor=executor)
        new_events = collector.query_live_events()
        self.assertEqual(len(new_events), 1)
        self.assertIsInstance(new_events[0], SysmonNetworkRecord)
        self.assertEqual(collector.last_record_id, 6001)

        # Next query with same XML should deduplicate
        dup_events = collector.query_live_events()
        self.assertEqual(len(dup_events), 0)

    def test_log_rollover_recovery(self):
        # Initial baseline seeded at 5001
        seed_res = _mock_result(stdout=VALID_SYSMON_EVENT1_XML, returncode=0)
        empty_res = _mock_result(stdout="<Events></Events>", returncode=0)
        # Probe query detects newest record is 100 (< 5001)
        rollover_xml = VALID_SYSMON_EVENT1_XML.replace("5001", "100")
        probe_res = _mock_result(stdout=rollover_xml, returncode=0)

        responses = [seed_res, empty_res, probe_res, probe_res]
        call_idx = [0]

        def executor(cmd, **kwargs):
            idx = call_idx[0]
            call_idx[0] += 1
            if idx < len(responses):
                return responses[idx]
            return empty_res

        collector = SysmonTelemetryCollector(executor=executor)
        collector.seed_baseline()
        self.assertEqual(collector.last_record_id, 5001)

        # Query live events triggers rollover probe and reset
        records = collector.query_live_events()
        self.assertEqual(collector.last_record_id, 100)
        self.assertEqual(len(records), 1)

    def test_access_denied_diagnostic(self):
        executor = MagicMock(return_value=_mock_result(returncode=1, stderr="Access is denied."))
        collector = SysmonTelemetryCollector(executor=executor)

        records = collector.query_live_events()
        self.assertEqual(records, [])
        self.assertEqual(collector.status, SysmonTelemetryStatus.UNAVAILABLE)
        self.assertEqual(collector.unavailable_reason, "access_denied")

        snap = collector.get_status_snapshot()
        self.assertFalse(snap["enabled"])
        self.assertEqual(snap["unavailable_reason"], "access_denied")

    def test_channel_unavailable_diagnostic(self):
        executor = MagicMock(return_value=_mock_result(returncode=1, stderr="The specified channel could not be found."))
        collector = SysmonTelemetryCollector(executor=executor)

        records = collector.query_live_events()
        self.assertEqual(records, [])
        self.assertEqual(collector.status, SysmonTelemetryStatus.UNAVAILABLE)
        self.assertEqual(collector.unavailable_reason, "channel_unavailable")

    def test_wevtutil_not_found(self):
        def executor(*args, **kwargs):
            raise FileNotFoundError("wevtutil.exe not found")

        collector = SysmonTelemetryCollector(executor=executor)
        records = collector.query_live_events()
        self.assertEqual(records, [])
        self.assertEqual(collector.status, SysmonTelemetryStatus.UNAVAILABLE)
        self.assertEqual(collector.unavailable_reason, "wevtutil_not_found")

    def test_timeout_and_transient_failure(self):
        def executor(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=["wevtutil"], timeout=5.0)

        collector = SysmonTelemetryCollector(executor=executor)
        records = collector.query_live_events()
        self.assertEqual(records, [])
        self.assertEqual(collector.status, SysmonTelemetryStatus.DEGRADED)

    def test_diagnostics_event_3_logging_status(self):
        # Event 3 disabled
        c_disabled = SysmonTelemetryCollector(enable_network_events=False)
        snap1 = c_disabled.get_status_snapshot()
        self.assertEqual(snap1["event_id_3_logging_status"], "DISABLED_BY_CONFIG")

        # Event 3 enabled but none observed yet
        c_enabled = SysmonTelemetryCollector(enable_network_events=True)
        snap2 = c_enabled.get_status_snapshot()
        self.assertEqual(snap2["event_id_3_logging_status"], "ENABLED_AWAITING_EVENTS")


class TestSysmonTelemetryCorrelator(unittest.TestCase):
    """Test event normalization and pipeline scoring for Sysmon events."""

    def setUp(self):
        self.correlator = SysmonTelemetryCorrelator()
        self.parser = SysmonEventParser()
        self.tree_analyzer = ProcessTreeAnalyzer()
        self.network_monitor = NetworkMonitor()

    def test_benign_child_process_event(self):
        records = self.parser.parse_event_xml(VALID_SYSMON_EVENT1_XML)
        self.assertEqual(len(records), 1)

        event = self.correlator.to_event(
            records[0],
            tree_analyzer=self.tree_analyzer,
        )

        self.assertIsInstance(event, Event)
        self.assertEqual(event.source, "sysmon")
        self.assertEqual(event.event_type, "process_start")
        self.assertEqual(event.process_name, "cmd.exe")
        self.assertEqual(event.parent_process_name, "explorer.exe")
        self.assertEqual(event.pid, 4096)
        self.assertEqual(event.ppid, 1024)
        self.assertEqual(event.severity, "LOW")
        self.assertEqual(event.risk_score, 0)
        self.assertIn("sysmon", event.metadata)
        self.assertEqual(event.metadata["sysmon"]["process_guid"], "{AAAAAAAA-1111-2222-3333-444444444444}")
        self.assertIn("SHA256", event.metadata["sysmon"]["hashes"])

    def test_suspicious_command_in_sysmon_process_event(self):
        xml = VALID_SYSMON_EVENT1_XML.replace(
            '"cmd.exe" /c echo hello',
            'powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBFAFgA',
        ).replace("cmd.exe", "powershell.exe")

        records = self.parser.parse_event_xml(xml)
        event = self.correlator.to_event(records[0], tree_analyzer=self.tree_analyzer)

        self.assertEqual(event.source, "sysmon")
        self.assertIn("encoded_command", event.indicators)
        self.assertGreater(event.risk_score, 0)
        self.assertIn(event.severity, ("MEDIUM", "HIGH"))

    def test_network_event_normalization_and_scoring(self):
        records = self.parser.parse_event_xml(SUSPICIOUS_EVENT3_XML)
        self.assertEqual(len(records), 1)
        rec = records[0]

        net_event = self.correlator.to_network_event(
            rec,
            network_monitor=self.network_monitor,
        )

        self.assertIsInstance(net_event, Event)
        self.assertEqual(net_event.source, "sysmon")
        self.assertEqual(net_event.event_type, "network_connection")
        self.assertEqual(net_event.pid, 8192)
        self.assertEqual(net_event.process_name, "powershell.exe")
        self.assertIsNotNone(net_event.network_info)
        self.assertEqual(net_event.network_info["remote_port"], 4444)
        # Port 4444 is in suspicious ports list
        self.assertIn("suspicious_destination_port", net_event.indicators)
        self.assertGreater(net_event.risk_score, 0)
        self.assertIn("sysmon", net_event.metadata)


class TestProcessCorrelationAndDeduplication(unittest.TestCase):
    """Test correlation across psutil polling, Security 4688, and Sysmon."""

    def test_guid_correlation_in_identity_registry(self):
        registry = ProcessIdentityRegistry(tolerance=5.0)
        guid = "{12345678-ABCD-1234-ABCD-1234567890AB}"

        registry.register(pid=5000, create_time=1000.0, source="sysmon", process_guid=guid)

        # Immediate definitive match on GUID regardless of PID/timestamp jitter
        self.assertTrue(registry.matches(pid=5000, create_time=1000.0, process_guid=guid))
        self.assertTrue(registry.matches(pid=9999, create_time=2000.0, process_guid=guid))
        self.assertFalse(registry.matches(pid=6000, create_time=1000.0, process_guid="{DIFFERENT-GUID}"))

    def test_sysmon_after_polling_suppresses_duplicate(self):
        registry = ProcessIdentityRegistry(tolerance=5.0)
        pid = 4096
        create_time = 1700000000.0

        # 1. Polling observes process first
        registry.register(pid=pid, create_time=create_time, source="polling")
        self.assertTrue(registry.matches(pid, create_time))

        # 2. Sysmon later delivers Event 1 for same PID/timestamp
        parser = SysmonEventParser()
        records = parser.parse_event_xml(VALID_SYSMON_EVENT1_XML)
        rec = records[0]
        rec.pid = pid
        rec.timestamp = create_time

        # Match check indicates it was already processed
        is_dup = registry.matches(rec.pid, rec.timestamp, process_guid=rec.process_guid)
        self.assertTrue(is_dup)


class TestContinuousMonitoringIntegration(unittest.TestCase):
    """Test that main.py run_continuous_loop consumes and routes Sysmon events."""

    def test_continuous_loop_processes_sysmon_events(self):
        logger = MagicMock()
        processes = {
            100: {"pid": 100, "name": "system.exe", "create_time": 1000.0, "ppid": 0, "parent_name": None}
        }
        resource_monitor = MagicMock(check_interval=0.1)
        baseline_engine = MagicMock()
        baseline_engine.analyze_event.return_value = {"is_anomaly": False, "reasons": []}
        tree_analyzer = ProcessTreeAnalyzer()
        network_monitor = NetworkMonitor()
        process_tree = ProcessTree.build(processes)

        # Mock Sysmon collector returning one process event and one network event
        parser = SysmonEventParser()
        proc_record = parser.parse_event_xml(VALID_SYSMON_EVENT1_XML)[0]
        net_record = parser.parse_event_xml(VALID_SYSMON_EVENT3_XML)[0]

        sysmon_collector = MagicMock()
        sysmon_collector.status = SysmonTelemetryStatus.AVAILABLE
        sysmon_collector.get_status_snapshot.return_value = {
            "status": "AVAILABLE",
            "process_events_enabled": True,
            "event_id_3_logging_status": "ACTIVE",
        }
        sysmon_collector.query_live_events.return_value = [proc_record, net_record]

        windows_collector = MagicMock()
        windows_collector.status = "UNAVAILABLE"

        with patch("src.main.get_running_processes", return_value=processes), \
             patch("src.main.get_new_processes", return_value=[]):

            prev_procs, p_tree, identities = run_continuous_loop(
                logger=logger,
                processes=processes,
                resource_monitor=resource_monitor,
                baseline_engine=baseline_engine,
                tree_analyzer=tree_analyzer,
                network_monitor=network_monitor,
                process_tree=process_tree,
                sysmon_collector=sysmon_collector,
                windows_collector=windows_collector,
                max_iterations=1,
                sleep_fn=lambda _: None,
            )

        # Verify baseline_engine collected the normalized Sysmon process event
        self.assertTrue(baseline_engine.collect_event.called)
        collected_event = baseline_engine.collect_event.call_args[0][0]
        self.assertEqual(collected_event.source, "sysmon")
        self.assertEqual(collected_event.pid, 4096)
        self.assertEqual(collected_event.process_name, "cmd.exe")

        # Verify identities registered the Sysmon event
        self.assertTrue(identities.matches(4096, proc_record.timestamp))


class TestMonitoringEngineSysmonIntegration(unittest.TestCase):
    """Test Sysmon integration in UI MonitoringEngine."""

    def test_engine_initializes_and_reports_sysmon_status(self):
        engine = MonitoringEngine()
        status = engine.get_sysmon_telemetry_status()
        self.assertIn("status", status)
        self.assertIn("enabled", status)
        self.assertIn("event_id_3_logging_status", status)
        engine.close()


if __name__ == "__main__":
    unittest.main()
