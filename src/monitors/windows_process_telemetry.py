"""
Windows Process-Creation Telemetry Module.

Collects Security Event 4688 ("A new process has been created") records from
the Windows Event Log and normalizes them into the standard event model, so
that short-lived processes can be observed in addition to the psutil polling
monitor.

Target machine requirements (documented only - never modified automatically):

* Advanced Audit Policy: ``Audit Process Creation``
  (``auditpol /SA /CS /CR "Process Creation"``).
* Command line inclusion: ``Include command line in process creation events``
  (registry value
  ``HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine = 1``).
  Without this policy the 4688 record simply has no command line; the field is
  then reported as *unavailable* (None) instead of an empty string.
* Reading the ``Security`` channel requires administrative privileges.  All
  other monitoring functionality keeps working without them.

The collector never changes audit policy, never installs services or drivers
and never touches firewall or Defender configuration.  It only reads the
event log and degrades gracefully when the channel is unavailable.
"""

from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import os
import subprocess
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Set
import xml.etree.ElementTree as ET

from src.detectors.command_detector import split_command_line
from src.execution.windows_enforcement import NTPathNormalizer
from src.models.event import Event
from src.monitors.process_monitor import get_parent_process_name


logger = logging.getLogger("endpoint_monitor")


PROCESS_CREATION_EVENT_ID = 4688
DEFAULT_TELEMETRY_CHANNEL = "Security"


class TelemetryStatus:
    """Availability states of the process-creation telemetry source."""

    UNKNOWN = "UNKNOWN"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    DEGRADED = "DEGRADED"


@dataclass
class ProcessCreationTelemetryRecord:
    """
    Normalized representation of a single Windows process-creation record.

    Fields that are not present in the source event stay ``None`` so that an
    unavailable value is never confused with a verified empty value.
    """

    record_id: str
    event_id: int
    channel: str
    timestamp: float
    record_sequence: Optional[int] = None
    time_created_iso: str = ""
    provider: str = ""
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_name: Optional[str] = None
    executable_path: Optional[str] = None
    command_line: Optional[str] = None
    subject_user: Optional[str] = None
    subject_user_sid: Optional[str] = None
    subject_domain: Optional[str] = None
    subject_logon_id: Optional[str] = None
    token_elevation_type: Optional[str] = None
    mandatory_label: Optional[str] = None
    fields_available: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a JSON-serializable dictionary."""
        return asdict(self)

    def to_process_info(self) -> Dict[str, Any]:
        """Convert the record into a psutil-compatible process information dict."""
        cmdline = None
        if self.command_line:
            cmdline = [token.strip('"') for token in split_command_line(self.command_line)]
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.process_name,
            "parent_name": None,
            "username": self.subject_user,
            "cmdline": cmdline,
            "create_time": self.timestamp,
            "exe": self.executable_path,
            "command_line_raw": self.command_line,
            "telemetry_source": self.channel,
            "telemetry_record_id": self.record_id,
            "telemetry_fields_available": list(self.fields_available),
        }


def _strip_ns(tag: str) -> str:
    """Remove the XML namespace prefix if present."""
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def _parse_int_value(raw: Any) -> Optional[int]:
    """
    Parse an integer that may be encoded as decimal or hexadecimal text.

    Security event 4688 encodes process identifiers as hexadecimal strings
    (for example ``0x1f4``).
    """
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw

    text = str(raw).strip()
    if not text:
        return None

    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except (TypeError, ValueError):
        try:
            return int(float(text))
        except (TypeError, ValueError):
            return None


def _parse_timestamp(iso_text: str) -> float:
    """Parse a Windows SystemTime value into a Unix timestamp."""
    if not iso_text:
        return time.time()

    cleaned = iso_text.strip().rstrip("Z")
    if "." in cleaned:
        base, _, fraction = cleaned.partition(".")
        fraction = fraction[:6]
        cleaned = f"{base}.{fraction}"

    try:
        parsed = datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError):
        return time.time()


class ProcessCreationEventParser:
    """
    Parses Windows Event Log XML payloads for process-creation (4688) records.
    """

    def __init__(self, path_normalizer: Optional[NTPathNormalizer] = None) -> None:
        self.normalizer = path_normalizer if path_normalizer is not None else NTPathNormalizer()

    def parse_event_xml(self, xml_text: str) -> List[ProcessCreationTelemetryRecord]:
        """Parse an XML payload containing one or more event records."""
        records: List[ProcessCreationTelemetryRecord] = []
        if not xml_text or not isinstance(xml_text, str) or not xml_text.strip():
            return records

        trimmed = xml_text.strip()
        if not trimmed.startswith("<"):
            return records

        if not trimmed.startswith("<Events") and trimmed.count("<Event") > 1:
            trimmed = f"<Events>{trimmed}</Events>"

        try:
            root = ET.fromstring(trimmed)
        except ET.ParseError as exc:
            logger.debug(f"Malformed Windows event payload: {exc}")
            return records

        elements: List[ET.Element] = []
        if _strip_ns(root.tag) == "Event":
            elements = [root]
        else:
            elements = [child for child in root if _strip_ns(child.tag) == "Event"]

        for element in elements:
            record = self._parse_event_element(element)
            if record is not None:
                records.append(record)

        return records

    def _parse_event_element(self, event_elem: ET.Element) -> Optional[ProcessCreationTelemetryRecord]:
        """Convert a single ``<Event>`` element into a telemetry record."""
        try:
            system_elem: Optional[ET.Element] = None
            event_data_elem: Optional[ET.Element] = None

            for child in event_elem:
                tag = _strip_ns(child.tag)
                if tag == "System":
                    system_elem = child
                elif tag == "EventData":
                    event_data_elem = child

            if system_elem is None:
                return None

            event_id: Optional[int] = None
            record_id: str = ""
            record_sequence: Optional[int] = None
            provider_name = ""
            channel_name = DEFAULT_TELEMETRY_CHANNEL
            time_created_iso = ""
            timestamp = time.time()

            for s_child in system_elem:
                s_tag = _strip_ns(s_child.tag)
                if s_tag == "EventID":
                    event_id = _parse_int_value(s_child.text)
                elif s_tag == "EventRecordID":
                    record_id = (s_child.text or "").strip()
                    record_sequence = _parse_int_value(record_id)
                elif s_tag == "Provider":
                    provider_name = s_child.attrib.get("Name", "")
                elif s_tag == "Channel":
                    channel_name = (s_child.text or "").strip() or DEFAULT_TELEMETRY_CHANNEL
                elif s_tag == "TimeCreated":
                    time_created_iso = s_child.attrib.get("SystemTime", "")
                    timestamp = _parse_timestamp(time_created_iso)

            if event_id is None:
                return None
            if event_id != PROCESS_CREATION_EVENT_ID:
                return None

            data: Dict[str, str] = {}
            if event_data_elem is not None:
                for d_child in event_data_elem:
                    d_name = d_child.attrib.get("Name")
                    d_value = d_child.text if d_child.text is not None else ""
                    if d_name:
                        data[d_name] = d_value

            available: List[str] = []

            pid = _parse_int_value(data.get("NewProcessId"))
            if pid is not None:
                available.append("pid")

            ppid = _parse_int_value(data.get("NewParentProcessId"))
            if ppid is not None:
                available.append("ppid")

            raw_process_name = data.get("NewProcessName") or None
            executable_path: Optional[str] = None
            process_name: Optional[str] = None
            if raw_process_name:
                executable_path = self.normalizer.normalize_path(raw_process_name)
                process_name = os.path.basename(executable_path or raw_process_name)
                available.extend(["process_name", "executable_path"])

            command_line = data.get("CommandLine")
            if command_line is None or command_line == "":
                command_line = None
            else:
                available.append("command_line")

            subject_user = data.get("SubjectUserName") or None
            if subject_user:
                available.append("subject_user")

            subject_user_sid = data.get("SubjectUserSid") or None
            if subject_user_sid:
                available.append("subject_user_sid")

            subject_domain = data.get("SubjectDomainName") or None
            subject_logon_id = data.get("SubjectLogonId") or None
            token_elevation_type = data.get("TokenElevationType") or None
            mandatory_label = data.get("MandatoryLabel") or None

            return ProcessCreationTelemetryRecord(
                record_id=record_id or f"{channel_name}:{record_sequence or 0}",
                event_id=event_id,
                channel=channel_name,
                timestamp=timestamp,
                record_sequence=record_sequence,
                time_created_iso=time_created_iso,
                provider=provider_name,
                pid=pid,
                ppid=ppid,
                process_name=process_name,
                executable_path=executable_path,
                command_line=command_line,
                subject_user=subject_user,
                subject_user_sid=subject_user_sid,
                subject_domain=subject_domain,
                subject_logon_id=subject_logon_id,
                token_elevation_type=token_elevation_type,
                mandatory_label=mandatory_label,
                fields_available=available,
                raw_data=data,
            )

        except Exception as exc:  # pragma: no cover - defensive parsing guard
            logger.debug(f"Failed to parse process creation event: {exc}")
            return None


class WindowsProcessTelemetryCollector:
    """
    Reads process-creation records from a Windows Event Log channel.

    The collector keeps track of the highest ``EventRecordID`` it has already
    processed and queries the log for newer records only.  This keeps the
    polling cheap and guarantees that a burst of process creations is not
    silently truncated.
    """

    def __init__(
        self,
        channel: str = DEFAULT_TELEMETRY_CHANNEL,
        event_id: int = PROCESS_CREATION_EVENT_ID,
        max_events_per_query: int = 200,
        query_timeout: float = 10.0,
        executor: Optional[Callable[..., Any]] = None,
        dedup_capacity: int = 2000,
    ) -> None:
        self.channel = channel or DEFAULT_TELEMETRY_CHANNEL
        self.event_id = int(event_id)
        self.max_events_per_query = max(1, min(int(max_events_per_query), 1000))
        self.query_timeout = float(query_timeout)
        self._executor = executor if executor is not None else subprocess.run
        self.parser = ProcessCreationEventParser()

        self._lock = threading.RLock()
        self._last_record_id = 0
        self._baseline_seeded = False
        self._seen_record_ids: Set[str] = set()
        self._seen_order: Deque[str] = deque(maxlen=max(1, dedup_capacity))
        self._status = TelemetryStatus.UNKNOWN
        self._unavailable_reason: Optional[str] = None
        self._last_error: Optional[str] = None
        self._records_collected = 0
        self._warnings_emitted = 0

    # ------------------------------------------------------------------
    # Status helpers
    # ------------------------------------------------------------------

    @property
    def status(self) -> str:
        """Current availability status of the telemetry source."""
        with self._lock:
            return self._status

    @property
    def unavailable_reason(self) -> Optional[str]:
        """Reason why the telemetry source cannot be used (if any)."""
        with self._lock:
            return self._unavailable_reason

    @property
    def last_error(self) -> Optional[str]:
        """Last error message observed while collecting records."""
        with self._lock:
            return self._last_error

    @property
    def records_collected(self) -> int:
        """Total number of records handed to the correlation layer."""
        with self._lock:
            return self._records_collected

    @property
    def last_record_id(self) -> int:
        """Highest event record identifier that has been processed."""
        with self._lock:
            return self._last_record_id

    def get_status_snapshot(self) -> Dict[str, Any]:
        """Return a diagnostic snapshot of the telemetry source."""
        with self._lock:
            return {
                "enabled": self._status != TelemetryStatus.UNAVAILABLE,
                "status": self._status,
                "channel": self.channel,
                "event_id": self.event_id,
                "unavailable_reason": self._unavailable_reason,
                "last_error": self._last_error,
                "records_collected": self._records_collected,
                "last_record_id": self._last_record_id,
            }

    def close(self) -> None:
        """Release collector resources.  The collector holds no OS handles."""
        with self._lock:
            self._seen_record_ids.clear()
            self._seen_order.clear()

    # ------------------------------------------------------------------
    # Query building
    # ------------------------------------------------------------------

    def build_query(self, last_record_id: Optional[int] = None) -> str:
        """Build the XPath filter used to read process-creation records."""
        if last_record_id is None:
            last_record_id = self._last_record_id

        try:
            sequence = int(last_record_id)
        except (TypeError, ValueError):
            sequence = 0

        if sequence > 0:
            return (
                f"*[System[(EventID={self.event_id}) and "
                f"(EventRecordID > {sequence})]]"
            )

        return f"*[System[(EventID={self.event_id})]]"

    def _build_command(self, query: str, reverse: bool = False, count: Optional[int] = None) -> List[str]:
        """Build the wevtutil command line for a channel query."""
        command = [
            "wevtutil.exe",
            "qe",
            self.channel,
            f"/q:{query}",
            f"/c:{count or self.max_events_per_query}",
            "/f:xml",
        ]
        if reverse:
            command.append("/rd:true")
        return command

    # ------------------------------------------------------------------
    # Collection
    # ------------------------------------------------------------------

    def _run_query(self, command: List[str]) -> Optional[str]:
        """Execute a wevtutil query and return stdout, or None on failure."""
        try:
            result = self._executor(
                command,
                capture_output=True,
                text=True,
                timeout=self.query_timeout,
                check=False,
            )
        except FileNotFoundError:
            self._disable("wevtutil_not_found", "wevtutil.exe is not available on this system.")
            return None
        except subprocess.TimeoutExpired:
            self._warn("Windows event log query timed out.")
            return None
        except Exception as exc:
            self._warn(f"Windows event log query failed: {exc}")
            return None

        returncode = getattr(result, "returncode", 0)
        stdout = getattr(result, "stdout", "") or ""
        stderr = getattr(result, "stderr", "") or ""

        if returncode != 0:
            lowered = str(stderr).lower()
            if "access is denied" in lowered or "access denied" in lowered:
                self._disable(
                    "access_denied",
                    "Reading the Windows Security event log requires administrative privileges.",
                )
            elif "could not be found" in lowered or "no events were found" in lowered:
                self._disable(
                    "channel_unavailable",
                    f"Windows event log channel '{self.channel}' is not available.",
                )
            else:
                self._warn(
                    f"Windows event log query exited with code {returncode}: {str(stderr).strip()}"
                )
            return None

        return stdout

    def seed_baseline(self) -> bool:
        """
        Establish the starting point for incremental collection.

        The newest existing record is used as the baseline so that the
        collector reports processes created *after* the monitor started
        instead of replaying the whole event log.
        """
        with self._lock:
            if self._baseline_seeded:
                return True

        query = self.build_query(0)
        stdout = self._run_query(self._build_command(query, reverse=True, count=1))
        if stdout is None:
            return False

        records = self.parser.parse_event_xml(stdout)
        newest = 0
        for record in records:
            if record.record_sequence and record.record_sequence > newest:
                newest = record.record_sequence

        with self._lock:
            self._last_record_id = newest
            self._baseline_seeded = True
            if self._status == TelemetryStatus.UNKNOWN:
                self._status = TelemetryStatus.AVAILABLE

        logger.info(
            f"Process creation telemetry baseline established on channel "
            f"'{self.channel}' (last record id: {newest})."
        )
        return True

    def query_live_events(self) -> List[ProcessCreationTelemetryRecord]:
        """
        Return process-creation records that were not seen before.

        The method fails open: when the channel cannot be read an empty list
        is returned and a clear warning is recorded.
        """
        with self._lock:
            if self._status == TelemetryStatus.UNAVAILABLE:
                return []

        if not self.seed_baseline():
            return []

        query = self.build_query()
        stdout = self._run_query(self._build_command(query))
        if stdout is None:
            return []

        records = self.parser.parse_event_xml(stdout)
        new_records: List[ProcessCreationTelemetryRecord] = []

        with self._lock:
            for record in records:
                if record.record_id in self._seen_record_ids:
                    continue

                if len(self._seen_order) == self._seen_order.maxlen:
                    oldest = self._seen_order[0]
                    self._seen_record_ids.discard(oldest)
                self._seen_order.append(record.record_id)
                self._seen_record_ids.add(record.record_id)

                if record.record_sequence and record.record_sequence > self._last_record_id:
                    self._last_record_id = record.record_sequence

                self._records_collected += 1
                new_records.append(record)

            if self._status == TelemetryStatus.UNKNOWN:
                self._status = TelemetryStatus.AVAILABLE

        return new_records

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def _warn(self, message: str) -> None:
        """Record a recoverable collection problem."""
        with self._lock:
            self._last_error = message
            self._warnings_emitted += 1
            should_log = self._warnings_emitted <= 3
        if should_log:
            logger.warning(f"[PROCESS TELEMETRY] {message}")

    def _disable(self, reason: str, message: str) -> None:
        """Mark the telemetry source as unavailable."""
        with self._lock:
            if self._status == TelemetryStatus.UNAVAILABLE:
                return
            self._status = TelemetryStatus.UNAVAILABLE
            self._unavailable_reason = reason
            self._last_error = message
        logger.warning(
            f"[PROCESS TELEMETRY] {message} "
            f"Process creation telemetry is disabled; polling monitoring continues."
        )


class ProcessTelemetryCorrelator:
    """
    Converts process-creation telemetry records into the standard Event model
    and correlates them with the live psutil process snapshot.
    """

    def __init__(self, path_normalizer: Optional[NTPathNormalizer] = None) -> None:
        self.normalizer = path_normalizer if path_normalizer is not None else NTPathNormalizer()

    def to_process_info(
        self,
        record: ProcessCreationTelemetryRecord,
        running_processes: Optional[Dict[int, Dict[str, Any]]] = None,
        identity_tolerance: float = 5.0,
    ) -> Dict[str, Any]:
        """
        Build a psutil-compatible process information dictionary.

        The creation timestamp of the telemetry record is authoritative for
        the process instance the event describes.  Live process data is only
        merged when the live process is the *same* instance - a recycled PID
        must not inherit the metadata of an unrelated process.
        """
        proc_map = running_processes or {}
        live = proc_map.get(record.pid) if record.pid is not None else None

        process_info = record.to_process_info()

        live_is_same_instance = False
        if live:
            live_create = live.get("create_time")
            if live_create is None or record.timestamp is None:
                live_is_same_instance = True
            else:
                try:
                    live_is_same_instance = abs(float(live_create) - float(record.timestamp)) <= identity_tolerance
                except (TypeError, ValueError):
                    live_is_same_instance = False

        if live_is_same_instance:
            process_info["name"] = live.get("name") or process_info.get("name")
            process_info["parent_name"] = live.get("parent_name")
            process_info["username"] = live.get("username") or process_info.get("username")
            if live.get("cmdline"):
                process_info["cmdline"] = live.get("cmdline")
            if live.get("exe"):
                process_info["exe"] = live.get("exe")
        elif record.ppid:
            process_info["parent_name"] = get_parent_process_name(record.ppid)

        process_info["live_process_matched"] = live_is_same_instance

        return process_info

    def to_event(
        self,
        record: ProcessCreationTelemetryRecord,
        running_processes: Optional[Dict[int, Dict[str, Any]]] = None,
    ) -> Event:
        """Convert a telemetry record into a standard Event."""
        process_info = self.to_process_info(record, running_processes)

        event = Event.from_process_info(process_info)
        event.source = "windows_process_telemetry"
        event.event_type = "process_start"
        event.metadata["telemetry"] = {
            "channel": record.channel,
            "event_id": record.event_id,
            "record_id": record.record_id,
            "record_sequence": record.record_sequence,
            "provider": record.provider,
            "time_created_iso": record.time_created_iso,
            "fields_available": list(record.fields_available),
            "command_line_available": record.command_line is not None,
            "subject_user_sid": record.subject_user_sid,
            "subject_domain": record.subject_domain,
            "subject_logon_id": record.subject_logon_id,
            "token_elevation_type": record.token_elevation_type,
            "mandatory_label": record.mandatory_label,
        }

        return event
