"""
Unit and Integration Tests for Windows Enforcement and Audit Telemetry (Phase 4).
"""

import subprocess
import unittest
from unittest.mock import MagicMock, patch

from src.execution.config import (
    DEFAULT_CONTROLLED_EXECUTION_CONFIG,
    load_execution_config,
)
from src.execution.windows_enforcement import (
    EnforcementOutcome,
    NTPathNormalizer,
    WindowsEnforcementCollector,
    WindowsEnforcementCorrelator,
    WindowsEnforcementEventType,
    WindowsEnforcementRecord,
    WindowsEventLogParser,
)
from src.models.event import Event


# Sample XML Payloads
SAMPLE_WDAC_3076_AUDIT_XML = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-CodeIntegrity' Guid='{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}'/>
    <EventID>3076</EventID>
    <Version>1</Version>
    <Level>3</Level>
    <TimeCreated SystemTime='2026-10-21T08:00:00.1234567Z'/>
    <EventRecordID>1001</EventRecordID>
    <Execution ProcessID='4321' ThreadID='1234'/>
    <Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel>
    <Computer>TEST-HOST</Computer>
    <Security UserID='S-1-5-21-1001'/>
  </System>
  <EventData>
    <Data Name='FileNameBuffer'>\\Device\\HarddiskVolume3\\Tools\\untrusted_tool.exe</Data>
    <Data Name='ProcessNameBuffer'>\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe</Data>
    <Data Name='PolicyName'>AuditBaselinePolicy</Data>
    <Data Name='PolicyID'>{ABCDEF01-2345-6789-ABCD-EF0123456789}</Data>
    <Data Name='SHA256'>A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2</Data>
    <Data Name='Status'>3221226536</Data>
  </EventData>
</Event>
"""

SAMPLE_WDAC_3077_ENFORCE_XML = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-CodeIntegrity' Guid='{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}'/>
    <EventID>3077</EventID>
    <Version>1</Version>
    <Level>2</Level>
    <TimeCreated SystemTime='2026-10-21T08:01:00.0000000Z'/>
    <EventRecordID>1002</EventRecordID>
    <Execution ProcessID='5555' ThreadID='2222'/>
    <Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel>
    <Computer>TEST-HOST</Computer>
    <Security UserID='S-1-5-21-1001'/>
  </System>
  <EventData>
    <Data Name='FileNameBuffer'>\\Device\\HarddiskVolume3\\Malware\\payload.exe</Data>
    <Data Name='ProcessNameBuffer'>\\Device\\HarddiskVolume3\\Windows\\System32\\powershell.exe</Data>
    <Data Name='PolicyName'>EnforcedBaselinePolicy</Data>
    <Data Name='PolicyID'>{99999999-2345-6789-ABCD-EF0123456789}</Data>
    <Data Name='SHA256'>11223344556677889900AABBCCDDEEFF11223344556677889900AABBCCDDEEFF</Data>
    <Data Name='Status'>3221226536</Data>
  </EventData>
</Event>
"""

SAMPLE_WDAC_3033_SIGNING_XML = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-CodeIntegrity' Guid='{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}'/>
    <EventID>3033</EventID>
    <Version>0</Version>
    <Level>2</Level>
    <TimeCreated SystemTime='2026-10-21T08:02:00.0000000Z'/>
    <EventRecordID>1003</EventRecordID>
    <Execution ProcessID='7777' ThreadID='3333'/>
    <Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel>
    <Computer>TEST-HOST</Computer>
    <Security UserID='S-1-5-18'/>
  </System>
  <EventData>
    <Data Name='FileNameBuffer'>\\Device\\HarddiskVolume3\\Program Files\\Vendor\\driver.sys</Data>
    <Data Name='ProcessNameBuffer'>\\Device\\HarddiskVolume3\\Windows\\System32\\services.exe</Data>
    <Data Name='Status'>3221226536</Data>
  </EventData>
</Event>
"""

SAMPLE_WDAC_3089_SIGINFO_XML = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-CodeIntegrity' Guid='{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}'/>
    <EventID>3089</EventID>
    <Version>3</Version>
    <Level>4</Level>
    <TimeCreated SystemTime='2026-10-21T08:02:00.5000000Z'/>
    <EventRecordID>1004</EventRecordID>
    <Execution ProcessID='7777' ThreadID='3333'/>
    <Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel>
    <Computer>TEST-HOST</Computer>
  </System>
  <EventData>
    <Data Name='PublisherName'>Test Vendor LLC</Data>
    <Data Name='IssuerName'>Test Root CA</Data>
    <Data Name='Hash'>11223344556677889900</Data>
  </EventData>
</Event>
"""

SAMPLE_APPLOCKER_8003_AUDIT_XML = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-AppLocker' Guid='{cbda4dbf-8d5d-4f69-9578-be14aa540d22}'/>
    <EventID>8003</EventID>
    <Version>0</Version>
    <Level>3</Level>
    <TimeCreated SystemTime='2026-10-21T08:05:00.0000000Z'/>
    <EventRecordID>2001</EventRecordID>
    <Execution ProcessID='8888' ThreadID='4444'/>
    <Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel>
    <Computer>TEST-HOST</Computer>
    <Security UserID='S-1-5-21-1001'/>
  </System>
  <EventData>
    <Data Name='FilePath'>C:\\Temp\\script_wrapper.exe</Data>
    <Data Name='RuleName'>%OSDRIVE%\\TEMP\\*</Data>
    <Data Name='RuleId'>{11111111-2222-3333-4444-555555555555}</Data>
    <Data Name='TargetProcessId'>8888</Data>
    <Data Name='FileHash'>FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210</Data>
    <Data Name='Fqbn'>O=EXAMPLE, L=REDMOND, S=WASHINGTON, C=US</Data>
  </EventData>
</Event>
"""

SAMPLE_APPLOCKER_8004_ENFORCE_XML = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-AppLocker' Guid='{cbda4dbf-8d5d-4f69-9578-be14aa540d22}'/>
    <EventID>8004</EventID>
    <Version>0</Version>
    <Level>2</Level>
    <TimeCreated SystemTime='2026-10-21T08:06:00.0000000Z'/>
    <EventRecordID>2002</EventRecordID>
    <Execution ProcessID='8889' ThreadID='4445'/>
    <Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel>
    <Computer>TEST-HOST</Computer>
    <Security UserID='S-1-5-21-1001'/>
  </System>
  <EventData>
    <Data Name='FilePath'>C:\\Users\\Public\\bad.exe</Data>
    <Data Name='RuleName'>Block Unapproved Executables</Data>
    <Data Name='RuleId'>{22222222-2222-3333-4444-555555555555}</Data>
    <Data Name='TargetProcessId'>8889</Data>
  </EventData>
</Event>
"""

SAMPLE_APPLOCKER_8002_ALLOWED_XML = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-AppLocker' Guid='{cbda4dbf-8d5d-4f69-9578-be14aa540d22}'/>
    <EventID>8002</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <TimeCreated SystemTime='2026-10-21T08:07:00.0000000Z'/>
    <EventRecordID>2003</EventRecordID>
    <Execution ProcessID='9990' ThreadID='5550'/>
    <Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel>
    <Computer>TEST-HOST</Computer>
  </System>
  <EventData>
    <Data Name='FilePath'>C:\\Windows\\System32\\calc.exe</Data>
    <Data Name='RuleName'>Default Windows Rules</Data>
  </EventData>
</Event>
"""


class TestNTPathNormalizer(unittest.TestCase):
    """Test resolution and normalization of kernel NT device paths."""

    def setUp(self):
        self.normalizer = NTPathNormalizer()
        self.normalizer.set_device_mapping("\\device\\harddiskvolume3", "C:")
        self.normalizer.set_device_mapping("\\device\\harddiskvolume4", "D:")

    def test_nt_device_to_dos_drive_resolution(self):
        raw = "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe"
        normalized = self.normalizer.normalize_path(raw)
        self.assertEqual(normalized, "C:\\Windows\\System32\\cmd.exe")

    def test_nt_device_case_insensitivity(self):
        raw = "\\DEVICE\\HARDDISKVOLUME3\\program files\\app\\tool.exe"
        normalized = self.normalizer.normalize_path(raw)
        self.assertEqual(normalized, "C:\\program files\\app\\tool.exe")

    def test_dos_device_prefix_stripping(self):
        raw = "\\??\\C:\\Windows\\System32\\calc.exe"
        normalized = self.normalizer.normalize_path(raw)
        self.assertEqual(normalized, "C:\\Windows\\System32\\calc.exe")

    def test_forward_slash_conversion(self):
        raw = "\\Device\\HarddiskVolume4/Data/report.pdf"
        normalized = self.normalizer.normalize_path(raw)
        self.assertEqual(normalized, "D:\\Data\\report.pdf")

    def test_unknown_device_preserves_path_safely(self):
        raw = "\\Device\\UnknownVolume99\\file.bin"
        normalized = self.normalizer.normalize_path(raw)
        self.assertEqual(normalized, "\\Device\\UnknownVolume99\\file.bin")

    def test_empty_and_non_string_inputs(self):
        self.assertIsNone(self.normalizer.normalize_path(None))
        self.assertEqual(self.normalizer.normalize_path(""), "")
        self.assertEqual(self.normalizer.normalize_path("   "), "")


class TestWindowsEventLogParser(unittest.TestCase):
    """Test XML parsing and schema normalization for Windows Code Integrity and AppLocker."""

    def setUp(self):
        self.normalizer = NTPathNormalizer()
        self.normalizer.set_device_mapping("\\device\\harddiskvolume3", "C:")
        self.parser = WindowsEventLogParser(path_normalizer=self.normalizer)

    def test_parse_wdac_3076_audit_event(self):
        records = self.parser.parse_event_xml(SAMPLE_WDAC_3076_AUDIT_XML)
        self.assertEqual(len(records), 1)
        rec = records[0]

        self.assertEqual(rec.record_id, "1001")
        self.assertEqual(rec.provider, "Microsoft-Windows-CodeIntegrity")
        self.assertEqual(rec.event_id, 3076)
        self.assertEqual(rec.event_type, WindowsEnforcementEventType.WDAC_AUDIT_BLOCKED)
        self.assertEqual(rec.outcome, EnforcementOutcome.AUDIT)
        self.assertEqual(rec.executable_path, "C:\\Tools\\untrusted_tool.exe")
        self.assertEqual(rec.process_name, "cmd.exe")
        self.assertEqual(rec.policy_name, "AuditBaselinePolicy")
        self.assertEqual(rec.policy_id, "{ABCDEF01-2345-6789-ABCD-EF0123456789}")
        self.assertEqual(rec.pid, 4321)
        self.assertEqual(rec.thread_id, 1234)
        self.assertEqual(rec.user_sid, "S-1-5-21-1001")
        self.assertEqual(rec.sha256_hash, "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2")
        self.assertGreater(rec.timestamp, 0)

    def test_parse_wdac_3077_enforce_event(self):
        records = self.parser.parse_event_xml(SAMPLE_WDAC_3077_ENFORCE_XML)
        self.assertEqual(len(records), 1)
        rec = records[0]

        self.assertEqual(rec.record_id, "1002")
        self.assertEqual(rec.event_id, 3077)
        self.assertEqual(rec.event_type, WindowsEnforcementEventType.WDAC_ENFORCE_BLOCKED)
        self.assertEqual(rec.outcome, EnforcementOutcome.BLOCKED)
        self.assertEqual(rec.executable_path, "C:\\Malware\\payload.exe")
        self.assertEqual(rec.process_name, "powershell.exe")
        self.assertEqual(rec.pid, 5555)

    def test_parse_wdac_3033_signing_level_block(self):
        records = self.parser.parse_event_xml(SAMPLE_WDAC_3033_SIGNING_XML)
        self.assertEqual(len(records), 1)
        rec = records[0]

        self.assertEqual(rec.record_id, "1003")
        self.assertEqual(rec.event_id, 3033)
        self.assertEqual(rec.event_type, WindowsEnforcementEventType.WDAC_SIGNING_LEVEL_BLOCKED)
        self.assertEqual(rec.outcome, EnforcementOutcome.BLOCKED)
        self.assertEqual(rec.executable_path, "C:\\Program Files\\Vendor\\driver.sys")
        self.assertEqual(rec.process_name, "services.exe")

    def test_parse_wdac_3089_signature_info(self):
        records = self.parser.parse_event_xml(SAMPLE_WDAC_3089_SIGINFO_XML)
        self.assertEqual(len(records), 1)
        rec = records[0]

        self.assertEqual(rec.record_id, "1004")
        self.assertEqual(rec.event_id, 3089)
        self.assertEqual(rec.outcome, EnforcementOutcome.INFO)
        self.assertEqual(rec.publisher, "Test Vendor LLC")
        self.assertEqual(rec.issuer, "Test Root CA")

    def test_parse_applocker_8003_audit_event(self):
        records = self.parser.parse_event_xml(SAMPLE_APPLOCKER_8003_AUDIT_XML)
        self.assertEqual(len(records), 1)
        rec = records[0]

        self.assertEqual(rec.record_id, "2001")
        self.assertEqual(rec.provider, "Microsoft-Windows-AppLocker")
        self.assertEqual(rec.event_id, 8003)
        self.assertEqual(rec.event_type, WindowsEnforcementEventType.APPLOCKER_AUDIT_BLOCKED)
        self.assertEqual(rec.outcome, EnforcementOutcome.AUDIT)
        self.assertEqual(rec.executable_path, "C:\\Temp\\script_wrapper.exe")
        self.assertEqual(rec.process_name, "script_wrapper.exe")
        self.assertEqual(rec.policy_name, "%OSDRIVE%\\TEMP\\*")
        self.assertEqual(rec.pid, 8888)

    def test_parse_applocker_8004_enforce_event(self):
        records = self.parser.parse_event_xml(SAMPLE_APPLOCKER_8004_ENFORCE_XML)
        self.assertEqual(len(records), 1)
        rec = records[0]

        self.assertEqual(rec.record_id, "2002")
        self.assertEqual(rec.event_id, 8004)
        self.assertEqual(rec.event_type, WindowsEnforcementEventType.APPLOCKER_ENFORCE_BLOCKED)
        self.assertEqual(rec.outcome, EnforcementOutcome.BLOCKED)
        self.assertEqual(rec.executable_path, "C:\\Users\\Public\\bad.exe")
        self.assertEqual(rec.pid, 8889)

    def test_parse_applocker_8002_allowed_event(self):
        records = self.parser.parse_event_xml(SAMPLE_APPLOCKER_8002_ALLOWED_XML)
        self.assertEqual(len(records), 1)
        rec = records[0]

        self.assertEqual(rec.record_id, "2003")
        self.assertEqual(rec.event_id, 8002)
        self.assertEqual(rec.event_type, WindowsEnforcementEventType.APPLOCKER_ALLOWED)
        self.assertEqual(rec.outcome, EnforcementOutcome.ALLOWED)
        self.assertEqual(rec.executable_path, "C:\\Windows\\System32\\calc.exe")

    def test_parse_multi_event_xml_stream(self):
        multi_xml = f"<Events>{SAMPLE_WDAC_3076_AUDIT_XML}{SAMPLE_WDAC_3077_ENFORCE_XML}</Events>"
        records = self.parser.parse_event_xml(multi_xml)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].record_id, "1001")
        self.assertEqual(records[1].record_id, "1002")

    def test_malformed_and_truncated_xml_handled_gracefully(self):
        # Syntax error
        self.assertEqual(self.parser.parse_event_xml("<NotEvenValidXML>>>"), [])
        # Truncated tag
        self.assertEqual(self.parser.parse_event_xml("<Event><System><EventID>307"), [])
        # Empty and blank
        self.assertEqual(self.parser.parse_event_xml(""), [])
        self.assertEqual(self.parser.parse_event_xml("   "), [])
        self.assertEqual(self.parser.parse_event_xml(None), [])  # type: ignore

    def test_sensitive_data_redaction_in_event_fields(self):
        secret_xml = """
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System>
            <Provider Name='Microsoft-Windows-CodeIntegrity'/>
            <EventID>3076</EventID>
            <EventRecordID>3001</EventRecordID>
          </System>
          <EventData>
            <Data Name='FileNameBuffer'>C:\\Tools\\script.exe?api_key=SECRET_TOKEN_XYZ</Data>
            <Data Name='ProcessNameBuffer'>runner.exe</Data>
            <Data Name='PublisherName'>--password=supersecret</Data>
          </EventData>
        </Event>
        """
        records = self.parser.parse_event_xml(secret_xml)
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertNotIn("SECRET_TOKEN_XYZ", str(rec.executable_path))
        self.assertIn("[REDACTED]", str(rec.executable_path))
        self.assertNotIn("supersecret", str(rec.publisher))
        self.assertIn("[REDACTED]", str(rec.publisher))


class TestWindowsEnforcementCollector(unittest.TestCase):
    """Test collection, live polling simulation, deduplication, and failure modes."""

    def setUp(self):
        self.collector = WindowsEnforcementCollector(cache_capacity=5)

    def test_xml_ingestion_and_deduplication(self):
        # First ingestion
        records1 = self.collector.ingest_xml_stream(SAMPLE_WDAC_3076_AUDIT_XML)
        self.assertEqual(len(records1), 1)
        self.assertEqual(records1[0].record_id, "1001")

        # Second ingestion of the same record should be deduplicated
        records2 = self.collector.ingest_xml_stream(SAMPLE_WDAC_3076_AUDIT_XML)
        self.assertEqual(len(records2), 0)

    def test_cache_capacity_and_bounded_eviction(self):
        # Create collector with capacity of 2
        small_collector = WindowsEnforcementCollector(cache_capacity=2)

        def make_event_xml(rec_id):
            return f"""
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
              <System>
                <Provider Name='Microsoft-Windows-CodeIntegrity'/>
                <EventID>3076</EventID>
                <EventRecordID>{rec_id}</EventRecordID>
              </System>
              <EventData>
                <Data Name='FileNameBuffer'>C:\\app_{rec_id}.exe</Data>
              </EventData>
            </Event>
            """

        r1 = small_collector.ingest_xml_stream(make_event_xml("1"))
        r2 = small_collector.ingest_xml_stream(make_event_xml("2"))
        self.assertEqual(len(r1), 1)
        self.assertEqual(len(r2), 1)

        # Ingest 3rd item -> causes eviction of 1st item
        r3 = small_collector.ingest_xml_stream(make_event_xml("3"))
        self.assertEqual(len(r3), 1)

        # Re-ingesting 1 should now be permitted because it was evicted
        r1_again = small_collector.ingest_xml_stream(make_event_xml("1"))
        self.assertEqual(len(r1_again), 1)

    def test_clear_cache(self):
        self.collector.ingest_xml_stream(SAMPLE_WDAC_3076_AUDIT_XML)
        self.assertEqual(len(self.collector.ingest_xml_stream(SAMPLE_WDAC_3076_AUDIT_XML)), 0)

        self.collector.clear_cache()
        records = self.collector.ingest_xml_stream(SAMPLE_WDAC_3076_AUDIT_XML)
        self.assertEqual(len(records), 1)

    def test_live_query_with_mock_executor_success(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = SAMPLE_WDAC_3077_ENFORCE_XML

        mock_exec = MagicMock(return_value=mock_proc)
        collector = WindowsEnforcementCollector(
            channels=["Microsoft-Windows-CodeIntegrity/Operational"],
            executor=mock_exec,
        )

        records = collector.query_live_events()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].record_id, "1002")
        mock_exec.assert_called_once()

    def test_live_query_executor_errors_handled_safely(self):
        # 1. Non-zero exit code
        mock_proc_fail = MagicMock()
        mock_proc_fail.returncode = 1
        mock_proc_fail.stdout = ""
        c1 = WindowsEnforcementCollector(executor=MagicMock(return_value=mock_proc_fail))
        self.assertEqual(c1.query_live_events(), [])

        # 2. FileNotFoundError (wevtutil missing)
        c2 = WindowsEnforcementCollector(executor=MagicMock(side_effect=FileNotFoundError("Missing")))
        self.assertEqual(c2.query_live_events(), [])

        # 3. TimeoutExpired
        c3 = WindowsEnforcementCollector(
            executor=MagicMock(side_effect=subprocess.TimeoutExpired(cmd=["wevtutil"], timeout=10))
        )
        self.assertEqual(c3.query_live_events(), [])

        # 4. Generic Exception
        c4 = WindowsEnforcementCollector(executor=MagicMock(side_effect=RuntimeError("Unexpected error")))
        self.assertEqual(c4.query_live_events(), [])


class TestWindowsEnforcementCorrelator(unittest.TestCase):
    """Test correlation with ProcessMonitor, standard Event generation, and alert dispatch."""

    def setUp(self):
        self.mock_alert = MagicMock()
        self.correlator = WindowsEnforcementCorrelator(
            alert_on_blocks=True,
            alert_callback=self.mock_alert,
        )
        self.parser = WindowsEventLogParser()

    def test_correlate_blocked_event_with_running_process(self):
        records = self.parser.parse_event_xml(SAMPLE_WDAC_3077_ENFORCE_XML)
        self.assertEqual(len(records), 1)
        rec = records[0]

        # Mock running processes snapshot containing PID 5555
        running_procs = {
            5555: {
                "pid": 5555,
                "ppid": 1111,
                "name": "powershell.exe",
                "parent_name": "explorer.exe",
                "username": "CORP\\Administrator",
                "cmdline": ["powershell.exe", "-ExecutionPolicy", "Bypass"],
            }
        }

        events = self.correlator.correlate_records(records, running_processes=running_procs)
        self.assertEqual(len(events), 1)
        evt = events[0]

        # Verify Event standard structure
        self.assertIsInstance(evt, Event)
        self.assertEqual(evt.source, "windows_enforcement")
        self.assertEqual(evt.event_type, "windows_enforcement_block")
        self.assertEqual(evt.severity, "HIGH")
        self.assertEqual(evt.risk_score, 9)
        self.assertEqual(evt.risk_level, "HIGH")
        self.assertIn("os_enforced_block", evt.indicators)

        # Verify process table correlation
        self.assertEqual(evt.pid, 5555)
        self.assertEqual(evt.ppid, 1111)
        self.assertEqual(evt.parent_process_name, "explorer.exe")
        self.assertEqual(evt.username, "CORP\\Administrator")
        self.assertEqual(evt.command_line, ["powershell.exe", "-ExecutionPolicy", "Bypass"])

        # Verify alert was dispatched
        self.mock_alert.assert_called_once()
        alert_text = self.mock_alert.call_args[0][0]
        self.assertIn("OS APPLICATION CONTROL: BLOCKED", alert_text)

    def test_correlate_audit_event_without_process_snapshot(self):
        records = self.parser.parse_event_xml(SAMPLE_WDAC_3076_AUDIT_XML)
        self.assertEqual(len(records), 1)
        rec = records[0]

        # Running processes empty (process already exited)
        events = self.correlator.correlate_records(records, running_processes={})
        self.assertEqual(len(events), 1)
        evt = events[0]

        self.assertEqual(evt.source, "windows_enforcement")
        self.assertEqual(evt.event_type, "windows_enforcement_audit")
        self.assertEqual(evt.severity, "MEDIUM")
        self.assertEqual(evt.risk_score, 6)
        self.assertIn("os_audit_block", evt.indicators)
        self.assertIsNone(evt.ppid)
        self.assertEqual(evt.process_name, "cmd.exe")

    def test_alert_deduplication(self):
        records = self.parser.parse_event_xml(SAMPLE_WDAC_3077_ENFORCE_XML)

        # First correlation emits alert
        self.correlator.correlate_records(records)
        self.assertEqual(self.mock_alert.call_count, 1)

        # Second correlation for same target binary suppresses alert
        self.correlator.correlate_records(records)
        self.assertEqual(self.mock_alert.call_count, 1)

        # Clearing alert cache allows alert to re-emit
        self.correlator.clear_alert_cache()
        self.correlator.correlate_records(records)
        self.assertEqual(self.mock_alert.call_count, 2)

    def test_alert_disabled_configuration(self):
        silent_correlator = WindowsEnforcementCorrelator(
            alert_on_blocks=False,
            alert_callback=self.mock_alert,
        )
        records = self.parser.parse_event_xml(SAMPLE_WDAC_3077_ENFORCE_XML)
        events = silent_correlator.correlate_records(records)
        self.assertEqual(len(events), 1)
        self.mock_alert.assert_not_called()

    def test_alert_delivery_failure_fails_safely(self):
        broken_alert_callback = MagicMock(side_effect=ConnectionError("Alert sink down"))
        resilient_correlator = WindowsEnforcementCorrelator(
            alert_callback=broken_alert_callback,
        )
        records = self.parser.parse_event_xml(SAMPLE_WDAC_3077_ENFORCE_XML)
        # Should not raise exception
        events = resilient_correlator.correlate_records(records)
        self.assertEqual(len(events), 1)


class TestWindowsEnforcementConfiguration(unittest.TestCase):
    """Test configuration loading and defaults for windows_enforcement."""

    def test_default_config_structure(self):
        self.assertIn("windows_enforcement", DEFAULT_CONTROLLED_EXECUTION_CONFIG)
        we_cfg = DEFAULT_CONTROLLED_EXECUTION_CONFIG["windows_enforcement"]
        self.assertFalse(we_cfg["enabled"])
        self.assertEqual(
            we_cfg["channels"],
            [
                "Microsoft-Windows-CodeIntegrity/Operational",
                "Microsoft-Windows-AppLocker/EXE and DLL",
            ],
        )
        self.assertEqual(we_cfg["poll_interval_seconds"], 5.0)
        self.assertEqual(we_cfg["max_events_per_query"], 50)
        self.assertTrue(we_cfg["correlate_with_processes"])
        self.assertTrue(we_cfg["alert_on_blocks"])

    def test_loaded_config_preserves_safety_defaults(self):
        cfg = load_execution_config("config/config.json")
        self.assertIn("windows_enforcement", cfg)
        self.assertFalse(cfg["windows_enforcement"]["enabled"])
        self.assertTrue(cfg["windows_enforcement"]["correlate_with_processes"])


if __name__ == "__main__":
    unittest.main()

