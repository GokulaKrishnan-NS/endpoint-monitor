"""
Windows Enforcement and Audit Telemetry Integration Module (Phase 4).

Collects, normalizes, sanitizes, and correlates operating system-level application
control events from Windows App Control for Business (WDAC / Code Integrity) and
AppLocker. Integrates OS enforcement evidence into the Endpoint Monitor event bus.
"""

from collections import deque
import ctypes
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import os
import re
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple
import uuid
import xml.etree.ElementTree as ET

from src.alerts.alert_manager import show_alert
from src.execution.service import redact_string
from src.models.event import Event


logger = logging.getLogger("endpoint_monitor")


class WindowsEnforcementEventType:
    """Standardized event type constants for Windows application-control events."""
    WDAC_AUDIT_BLOCKED = "wdac_audit_blocked"
    WDAC_ENFORCE_BLOCKED = "wdac_enforce_blocked"
    WDAC_SIGNATURE_INFO = "wdac_signature_info"
    WDAC_SIGNING_LEVEL_BLOCKED = "wdac_signing_level_blocked"
    WDAC_SIGNING_LEVEL_AUDIT = "wdac_signing_level_audit"
    APPLOCKER_POLICY_APPLIED = "applocker_policy_applied"
    APPLOCKER_ALLOWED = "applocker_allowed"
    APPLOCKER_AUDIT_BLOCKED = "applocker_audit_blocked"
    APPLOCKER_ENFORCE_BLOCKED = "applocker_enforce_blocked"
    UNKNOWN = "windows_enforcement_unknown"


class EnforcementOutcome:
    """Standardized policy outcome classifications."""
    BLOCKED = "BLOCKED"
    AUDIT = "AUDIT"
    ALLOWED = "ALLOWED"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


# Mapping from Windows Event Log IDs to (event_type, outcome)
EVENT_ID_MAP: Dict[Tuple[str, int], Tuple[str, str]] = {
    # Microsoft-Windows-CodeIntegrity
    ("Microsoft-Windows-CodeIntegrity", 3076): (
        WindowsEnforcementEventType.WDAC_AUDIT_BLOCKED,
        EnforcementOutcome.AUDIT,
    ),
    ("Microsoft-Windows-CodeIntegrity", 3077): (
        WindowsEnforcementEventType.WDAC_ENFORCE_BLOCKED,
        EnforcementOutcome.BLOCKED,
    ),
    ("Microsoft-Windows-CodeIntegrity", 3089): (
        WindowsEnforcementEventType.WDAC_SIGNATURE_INFO,
        EnforcementOutcome.INFO,
    ),
    ("Microsoft-Windows-CodeIntegrity", 3033): (
        WindowsEnforcementEventType.WDAC_SIGNING_LEVEL_BLOCKED,
        EnforcementOutcome.BLOCKED,
    ),
    ("Microsoft-Windows-CodeIntegrity", 3034): (
        WindowsEnforcementEventType.WDAC_SIGNING_LEVEL_AUDIT,
        EnforcementOutcome.AUDIT,
    ),
    # Microsoft-Windows-AppLocker
    ("Microsoft-Windows-AppLocker", 8001): (
        WindowsEnforcementEventType.APPLOCKER_POLICY_APPLIED,
        EnforcementOutcome.INFO,
    ),
    ("Microsoft-Windows-AppLocker", 8002): (
        WindowsEnforcementEventType.APPLOCKER_ALLOWED,
        EnforcementOutcome.ALLOWED,
    ),
    ("Microsoft-Windows-AppLocker", 8003): (
        WindowsEnforcementEventType.APPLOCKER_AUDIT_BLOCKED,
        EnforcementOutcome.AUDIT,
    ),
    ("Microsoft-Windows-AppLocker", 8004): (
        WindowsEnforcementEventType.APPLOCKER_ENFORCE_BLOCKED,
        EnforcementOutcome.BLOCKED,
    ),
}


@dataclass
class WindowsEnforcementRecord:
    """
    Normalized data representation of a single Windows application-control event.
    """
    record_id: str
    provider: str
    channel: str
    event_id: int
    event_type: str
    outcome: str
    timestamp: float
    time_created_iso: str = ""
    executable_path: Optional[str] = None
    process_name: Optional[str] = None
    pid: Optional[int] = None
    thread_id: Optional[int] = None
    user_sid: Optional[str] = None
    policy_name: Optional[str] = None
    policy_id: Optional[str] = None
    sha256_hash: Optional[str] = None
    publisher: Optional[str] = None
    issuer: Optional[str] = None
    status_code: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return asdict(self)


class NTPathNormalizer:
    """
    Resolves Windows NT kernel device paths (e.g. \\Device\\HarddiskVolume3\\...)
    to standard Win32 DOS drive paths (e.g. C:\\...).
    """

    def __init__(self) -> None:
        self._device_map: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._init_mappings()

    def _init_mappings(self) -> None:
        """Initialize drive letter to NT device mappings on Windows."""
        if sys.platform != "win32":
            return
        try:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            buf = ctypes.create_unicode_buffer(512)
            for char_code in range(ord("A"), ord("Z") + 1):
                drive_letter = f"{chr(char_code)}:"
                chars_written = kernel32.QueryDosDeviceW(drive_letter, buf, 512)
                if chars_written > 0:
                    nt_target = buf.value.rstrip("\x00")
                    if nt_target:
                        self._device_map[nt_target.lower()] = drive_letter
        except Exception as e:
            logger.debug(f"Failed to query DOS devices: {e}")

    def set_device_mapping(self, nt_device: str, dos_drive: str) -> None:
        """Explicitly set or override an NT device mapping (useful for testing/mocking)."""
        with self._lock:
            self._device_map[nt_device.rstrip("\\").lower()] = dos_drive.rstrip("\\")

    def normalize_path(self, raw_path: Optional[str]) -> Optional[str]:
        """
        Convert an NT device path, dos device prefix, or raw path to normalized Win32 format.
        """
        if not raw_path or not isinstance(raw_path, str):
            return raw_path

        cleaned = raw_path.strip()
        if not cleaned:
            return cleaned

        # Standardize forward slashes to backslashes
        cleaned = cleaned.replace("/", "\\")

        # Strip Win32 device prefix \??\
        if cleaned.startswith("\\??\\"):
            cleaned = cleaned[4:]

        with self._lock:
            # Check if path starts with a known NT device name
            cleaned_lower = cleaned.lower()
            for nt_device, dos_drive in self._device_map.items():
                if cleaned_lower.startswith(nt_device):
                    remainder = cleaned[len(nt_device):]
                    if not remainder.startswith("\\"):
                        remainder = "\\" + remainder
                    return f"{dos_drive}{remainder}"

        return cleaned


class WindowsEventLogParser:
    """
    Parses Windows Event Log XML representations for Code Integrity and AppLocker events.
    Applies strict field validation and sensitive data redaction.
    """

    def __init__(self, path_normalizer: Optional[NTPathNormalizer] = None) -> None:
        self.normalizer = path_normalizer if path_normalizer is not None else NTPathNormalizer()

    @staticmethod
    def _strip_ns(tag: str) -> str:
        """Remove XML namespace prefix if present."""
        if tag.startswith("{"):
            return tag.split("}", 1)[1]
        return tag

    def parse_event_xml(self, xml_text: str) -> List[WindowsEnforcementRecord]:
        """
        Parse XML containing one or more Windows Event Log entries.
        Returns a list of successfully parsed WindowsEnforcementRecord objects.
        """
        records: List[WindowsEnforcementRecord] = []
        if not xml_text or not isinstance(xml_text, str) or not xml_text.strip():
            return records

        try:
            # Wrap in root element if root is not present
            trimmed = xml_text.strip()
            if not trimmed.startswith("<"):
                return records

            # Handle fragment streams without single root
            if not trimmed.startswith("<Events") and trimmed.count("<Event") > 1:
                trimmed = f"<Events>{trimmed}</Events>"

            root = ET.fromstring(trimmed)
            if self._strip_ns(root.tag) == "Event":
                rec = self._parse_single_event_element(root)
                if rec:
                    records.append(rec)
            else:
                for elem in root:
                    if self._strip_ns(elem.tag) == "Event":
                        rec = self._parse_single_event_element(elem)
                        if rec:
                            records.append(rec)
        except ET.ParseError as pe:
            logger.debug(f"XML parse error in Windows event payload: {pe}")
        except Exception as e:
            logger.debug(f"Unexpected error while parsing Windows event XML: {e}")

        return records

    def _parse_single_event_element(self, event_elem: ET.Element) -> Optional[WindowsEnforcementRecord]:
        """Parse an individual <Event> Element into a WindowsEnforcementRecord."""
        try:
            system_elem: Optional[ET.Element] = None
            event_data_elem: Optional[ET.Element] = None

            for child in event_elem:
                tag = self._strip_ns(child.tag)
                if tag == "System":
                    system_elem = child
                elif tag == "EventData":
                    event_data_elem = child

            if system_elem is None:
                return None

            # Extract System attributes
            event_id_val: Optional[int] = None
            record_id_val: Optional[str] = None
            provider_name = ""
            channel_name = ""
            time_created_iso = ""
            timestamp_val = time.time()
            pid_val: Optional[int] = None
            thread_id_val: Optional[int] = None
            user_sid_val: Optional[str] = None

            for s_child in system_elem:
                s_tag = self._strip_ns(s_child.tag)
                if s_tag == "EventID":
                    try:
                        event_id_val = int(s_child.text.strip()) if s_child.text else None
                    except (ValueError, TypeError):
                        event_id_val = None
                elif s_tag == "EventRecordID":
                    record_id_val = s_child.text.strip() if s_child.text else None
                elif s_tag == "Provider":
                    provider_name = s_child.attrib.get("Name", "")
                elif s_tag == "Channel":
                    channel_name = s_child.text.strip() if s_child.text else ""
                elif s_tag == "TimeCreated":
                    time_created_iso = s_child.attrib.get("SystemTime", "")
                    if time_created_iso:
                        try:
                            # Parse ISO 8601 timestamp e.g. 2026-10-21T07:37:59.7375947Z
                            iso_clean = time_created_iso.rstrip("Z")
                            if "." in iso_clean:
                                base, frac = iso_clean.split(".", 1)
                                frac = frac[:6]  # Truncate fractional seconds to microseconds
                                iso_clean = f"{base}.{frac}"
                            dt = datetime.fromisoformat(iso_clean).replace(tzinfo=timezone.utc)
                            timestamp_val = dt.timestamp()
                        except Exception:
                            timestamp_val = time.time()
                elif s_tag == "Execution":
                    p_text = s_child.attrib.get("ProcessID")
                    t_text = s_child.attrib.get("ThreadID")
                    if p_text:
                        try:
                            pid_val = int(p_text)
                        except (ValueError, TypeError):
                            pid_val = None
                    if t_text:
                        try:
                            thread_id_val = int(t_text)
                        except (ValueError, TypeError):
                            thread_id_val = None
                elif s_tag == "Security":
                    user_sid_val = s_child.attrib.get("UserID")

            if event_id_val is None:
                return None

            # Fallback record_id if missing in System
            if not record_id_val:
                record_id_val = str(uuid.uuid4())

            # Extract EventData key-value pairs
            data_dict: Dict[str, Any] = {}
            if event_data_elem is not None:
                for d_child in event_data_elem:
                    d_name = d_child.attrib.get("Name")
                    d_val = d_child.text if d_child.text is not None else ""
                    if d_name:
                        data_dict[d_name] = d_val

            # Resolve event type and outcome
            lookup_key = (provider_name, event_id_val)
            if lookup_key in EVENT_ID_MAP:
                event_type, outcome = EVENT_ID_MAP[lookup_key]
            else:
                event_type = WindowsEnforcementEventType.UNKNOWN
                outcome = EnforcementOutcome.UNKNOWN

            # Extract fields based on provider schema
            executable_path: Optional[str] = None
            process_name: Optional[str] = None
            policy_name: Optional[str] = None
            policy_id: Optional[str] = None
            sha256_hash: Optional[str] = None
            publisher: Optional[str] = None
            issuer: Optional[str] = None
            status_code: Optional[str] = None

            if "Microsoft-Windows-CodeIntegrity" in provider_name:
                raw_file = data_dict.get("FileNameBuffer") or data_dict.get("FileName")
                if raw_file:
                    executable_path = self.normalizer.normalize_path(raw_file)
                raw_proc = data_dict.get("ProcessNameBuffer") or data_dict.get("ProcessName")
                if raw_proc:
                    process_name = os.path.basename(self.normalizer.normalize_path(raw_proc) or "")
                policy_name = data_dict.get("PolicyName")
                policy_id = data_dict.get("PolicyID") or data_dict.get("PolicyGuid")
                sha256_hash = data_dict.get("SHA256") or data_dict.get("Hash")
                publisher = data_dict.get("PublisherName")
                issuer = data_dict.get("IssuerName")
                status_code = data_dict.get("Status")

            elif "Microsoft-Windows-AppLocker" in provider_name:
                raw_file = data_dict.get("FilePath")
                if raw_file:
                    executable_path = self.normalizer.normalize_path(raw_file)
                    if executable_path:
                        process_name = os.path.basename(executable_path)
                policy_name = data_dict.get("RuleName")
                policy_id = data_dict.get("RuleId")
                sha256_hash = data_dict.get("FileHash")
                publisher = data_dict.get("Fqbn")
                target_pid = data_dict.get("TargetProcessId")
                if target_pid:
                    try:
                        pid_val = int(target_pid)
                    except (ValueError, TypeError):
                        pass

            # Redact sensitive parameters
            if executable_path:
                executable_path = redact_string(executable_path)
            if process_name:
                process_name = redact_string(process_name)
            if publisher:
                publisher = redact_string(publisher)

            # Redact sensitive values inside raw_data
            sanitized_raw_data: Dict[str, Any] = {}
            for k, v in data_dict.items():
                if isinstance(v, str):
                    sanitized_raw_data[k] = redact_string(v)
                else:
                    sanitized_raw_data[k] = v

            return WindowsEnforcementRecord(
                record_id=record_id_val,
                provider=provider_name,
                channel=channel_name,
                event_id=event_id_val,
                event_type=event_type,
                outcome=outcome,
                timestamp=timestamp_val,
                time_created_iso=time_created_iso,
                executable_path=executable_path,
                process_name=process_name,
                pid=pid_val,
                thread_id=thread_id_val,
                user_sid=user_sid_val,
                policy_name=policy_name,
                policy_id=policy_id,
                sha256_hash=sha256_hash,
                publisher=publisher,
                issuer=issuer,
                status_code=status_code,
                raw_data=sanitized_raw_data,
            )

        except Exception as e:
            logger.debug(f"Failed to parse individual event element: {e}")
            return None


class WindowsEnforcementCollector:
    """
    Collects Windows application-control events from the Windows Event Log
    via wevtutil.exe or custom XML input streams. Enforces bounded deduplication.
    """

    DEFAULT_CHANNELS = [
        "Microsoft-Windows-CodeIntegrity/Operational",
        "Microsoft-Windows-AppLocker/EXE and DLL",
    ]

    def __init__(
        self,
        channels: Optional[List[str]] = None,
        max_events_per_query: int = 50,
        cache_capacity: int = 1000,
        parser: Optional[WindowsEventLogParser] = None,
        executor: Optional[Callable[[List[str]], subprocess.CompletedProcess]] = None,
    ) -> None:
        self.channels = channels if channels is not None else list(self.DEFAULT_CHANNELS)
        self.max_events_per_query = max(1, min(max_events_per_query, 500))
        self.cache_capacity = max(1, cache_capacity)
        self.parser = parser if parser is not None else WindowsEventLogParser()
        self._executor = executor if executor is not None else subprocess.run
        self._seen_records: Set[str] = set()
        self._record_order: Deque[str] = deque(maxlen=self.cache_capacity)
        self._lock = threading.Lock()

    def _is_record_seen(self, record_id: str) -> bool:
        """Check if record ID has already been collected."""
        with self._lock:
            return record_id in self._seen_records

    def _mark_record_seen(self, record_id: str) -> None:
        """Mark record ID as seen with bounded cache eviction."""
        with self._lock:
            if record_id in self._seen_records:
                return
            if len(self._record_order) >= self.cache_capacity:
                oldest = self._record_order.popleft()
                self._seen_records.discard(oldest)
            self._record_order.append(record_id)
            self._seen_records.add(record_id)

    def clear_cache(self) -> None:
        """Clear deduplication cache."""
        with self._lock:
            self._seen_records.clear()
            self._record_order.clear()

    def query_live_events(self) -> List[WindowsEnforcementRecord]:
        """
        Query Windows Event Log for recent application control events across configured channels.
        Safely fails open (returns empty list) if wevtutil is unavailable or fails.
        """
        new_records: List[WindowsEnforcementRecord] = []

        for channel in self.channels:
            if not isinstance(channel, str) or not re.match(r"^[A-Za-z0-9_\-\.\/ ]+$", channel.strip()):
                logger.warning(f"Skipping invalid or unsafe channel name: {channel}")
                continue
            cmd = [
                "wevtutil.exe",
                "qe",
                channel,
                f"/c:{self.max_events_per_query}",
                "/rd:true",
                "/f:xml",
            ]
            try:
                result = self._executor(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode == 0 and result.stdout:
                    records = self.parser.parse_event_xml(result.stdout)
                    for rec in records:
                        if not self._is_record_seen(rec.record_id):
                            self._mark_record_seen(rec.record_id)
                            new_records.append(rec)
                elif result.returncode != 0:
                    logger.debug(
                        f"wevtutil query for channel '{channel}' exited with return code {result.returncode}"
                    )
            except FileNotFoundError:
                logger.debug("wevtutil.exe not found on system PATH.")
                break
            except subprocess.TimeoutExpired:
                logger.warning(f"wevtutil query timed out for channel '{channel}'.")
            except Exception as e:
                logger.debug(f"Failed to query events from channel '{channel}': {e}")

        return new_records

    def ingest_xml_stream(self, xml_content: str) -> List[WindowsEnforcementRecord]:
        """
        Ingest and deduplicate events from an explicit XML string (e.g. file or synthetic test).
        """
        new_records: List[WindowsEnforcementRecord] = []
        parsed = self.parser.parse_event_xml(xml_content)
        for rec in parsed:
            if not self._is_record_seen(rec.record_id):
                self._mark_record_seen(rec.record_id)
                new_records.append(rec)
        return new_records


class WindowsEnforcementCorrelator:
    """
    Correlates WindowsEnforcementRecords with passive ProcessMonitor telemetry,
    emits normalized Event objects, and dispatches bounded security alerts.
    """

    def __init__(
        self,
        alert_on_blocks: bool = True,
        alert_cache_capacity: int = 500,
        alert_callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.alert_on_blocks = alert_on_blocks
        self.alert_cache_capacity = max(1, alert_cache_capacity)
        self._alert_callback = alert_callback if alert_callback is not None else show_alert
        self._alerted_keys: Set[str] = set()
        self._alerted_order: Deque[str] = deque(maxlen=self.alert_cache_capacity)
        self._lock = threading.Lock()

    def clear_alert_cache(self) -> None:
        """Clear alert deduplication cache."""
        with self._lock:
            self._alerted_keys.clear()
            self._alerted_order.clear()

    def correlate_records(
        self,
        records: List[WindowsEnforcementRecord],
        running_processes: Optional[Dict[int, Dict[str, Any]]] = None,
    ) -> List[Event]:
        """
        Convert WindowsEnforcementRecords to standard Event models, enriching them
        with process table context when available, and generating alerts for blocked events.
        """
        events: List[Event] = []
        proc_map = running_processes or {}

        for rec in records:
            # Map severity and indicators based on policy outcome
            if rec.outcome == EnforcementOutcome.BLOCKED:
                severity = "HIGH"
                risk_score = 9
                risk_level = "HIGH"
                indicators = ["os_enforced_block"]
                event_type = "windows_enforcement_block"
                reason = (
                    f"Process execution blocked by Windows {rec.provider} "
                    f"(Event {rec.event_id}, Policy: {rec.policy_name or 'Default'})"
                )
            elif rec.outcome == EnforcementOutcome.AUDIT:
                severity = "MEDIUM"
                risk_score = 6
                risk_level = "MEDIUM"
                indicators = ["os_audit_block"]
                event_type = "windows_enforcement_audit"
                reason = (
                    f"Process execution would be blocked in enforce mode by {rec.provider} "
                    f"(Event {rec.event_id}, Policy: {rec.policy_name or 'Default'})"
                )
            elif rec.outcome == EnforcementOutcome.ALLOWED:
                severity = "LOW"
                risk_score = 1
                risk_level = "LOW"
                indicators = []
                event_type = "windows_enforcement_allowed"
                reason = f"Process execution verified and allowed by {rec.provider} (Event {rec.event_id})"
            else:
                severity = "LOW"
                risk_score = 0
                risk_level = "LOW"
                indicators = []
                event_type = "windows_enforcement_info"
                reason = f"Windows application control informational event {rec.event_id} from {rec.provider}"

            # Correlate with running process snapshot
            ppid: Optional[int] = None
            parent_proc_name: Optional[str] = None
            proc_user: Optional[str] = None
            cmdline: Optional[List[str]] = None

            if rec.pid and rec.pid in proc_map:
                proc_info = proc_map[rec.pid]
                ppid = proc_info.get("ppid")
                parent_proc_name = proc_info.get("parent_name")
                proc_user = proc_info.get("username")
                cmdline = proc_info.get("cmdline")

            # Fallback to record attributes
            final_proc_name = rec.process_name or (
                os.path.basename(rec.executable_path) if rec.executable_path else "unknown"
            )

            # Metadata enrichment
            metadata: Dict[str, Any] = {
                "record_id": rec.record_id,
                "provider": rec.provider,
                "channel": rec.channel,
                "event_id": rec.event_id,
                "outcome": rec.outcome,
                "policy_name": rec.policy_name,
                "policy_id": rec.policy_id,
                "sha256_hash": rec.sha256_hash,
                "publisher": rec.publisher,
                "issuer": rec.issuer,
                "status_code": rec.status_code,
                "time_created_iso": rec.time_created_iso,
                "user_sid": rec.user_sid,
                "raw_data": rec.raw_data,
            }

            event = Event(
                event_id=str(uuid.uuid4()),
                timestamp=rec.timestamp,
                event_type=event_type,
                source="windows_enforcement",
                severity=severity,
                pid=rec.pid,
                ppid=ppid,
                process_name=final_proc_name,
                parent_process_name=parent_proc_name,
                username=proc_user,
                command_line=cmdline,
                file_path=rec.executable_path,
                indicators=indicators,
                risk_score=risk_score,
                risk_level=risk_level,
                risk_reasons=[reason],
                metadata=metadata,
            )

            events.append(event)

            # Trigger alert for blocked / audited events if enabled
            if self.alert_on_blocks and rec.outcome in (EnforcementOutcome.BLOCKED, EnforcementOutcome.AUDIT):
                self._maybe_send_alert(rec, reason)

        return events

    def _maybe_send_alert(self, rec: WindowsEnforcementRecord, reason: str) -> None:
        """Dispatch deduplicated alert."""
        # Key on provider, event_id, and executable_path / hash
        target_id = rec.executable_path or rec.sha256_hash or str(rec.pid) or rec.record_id
        dedup_key = f"{rec.provider}:{rec.event_id}:{target_id}"

        with self._lock:
            if dedup_key in self._alerted_keys:
                return
            if len(self._alerted_order) >= self.alert_cache_capacity:
                oldest = self._alerted_order.popleft()
                self._alerted_keys.discard(oldest)
            self._alerted_order.append(dedup_key)
            self._alerted_keys.add(dedup_key)

        alert_msg = (
            f"OS APPLICATION CONTROL: {rec.outcome} | "
            f"Target: '{rec.executable_path or rec.process_name}' | "
            f"PID: {rec.pid} | Reason: {reason}"
        )
        try:
            self._alert_callback(alert_msg)
        except Exception as e:
            logger.debug(f"Failed to deliver OS enforcement alert: {e}")

