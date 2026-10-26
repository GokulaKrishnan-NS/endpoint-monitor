"""
Sysmon Telemetry Integration Module.

Collects Sysmon Process-Creation (Event ID 1) and Network-Connection (Event ID 3)
records from the Windows Event Log channel 'Microsoft-Windows-Sysmon/Operational',
parses named event-data fields, handles incremental collection, normalizes records
into the standardized Event and Network representations, and integrates with the
detection and correlation pipeline.
"""

from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import logging
import os
import subprocess
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET

from src.detectors.command_detector import detect_command_indicators, split_command_line
from src.detectors.risk_detector import calculate_risk
from src.execution.windows_enforcement import NTPathNormalizer
from src.models.event import Event
from src.monitors.network_monitor import NetworkConnection, NetworkMonitor
from src.monitors.process_monitor import get_parent_process_name


logger = logging.getLogger("endpoint_monitor")

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROCESS_CREATION_EVENT_ID = 1
SYSMON_NETWORK_CONNECT_EVENT_ID = 3


class SysmonTelemetryStatus:
    """Availability states of the Sysmon telemetry source."""

    UNKNOWN = "UNKNOWN"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    DEGRADED = "DEGRADED"


@dataclass
class SysmonProcessRecord:
    """
    Normalized representation of a Sysmon Process Creation (Event ID 1) record.

    Fields missing in the source event remain None so that unavailable values
    are never confused with verified empty values.
    """

    record_id: str
    event_id: int
    channel: str
    timestamp: float
    record_sequence: Optional[int] = None
    time_created_iso: str = ""
    provider: str = ""
    process_guid: Optional[str] = None
    pid: Optional[int] = None
    image: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    current_directory: Optional[str] = None
    user: Optional[str] = None
    logon_guid: Optional[str] = None
    logon_id: Optional[str] = None
    terminal_session_id: Optional[int] = None
    integrity_level: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    hashes_raw: Optional[str] = None
    parent_process_guid: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_image: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_command_line: Optional[str] = None
    parent_user: Optional[str] = None
    rule_name: Optional[str] = None
    original_file_name: Optional[str] = None
    description: Optional[str] = None
    product: Optional[str] = None
    company: Optional[str] = None
    fields_available: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to a JSON-serializable dictionary."""
        return asdict(self)

    def to_process_info(self) -> Dict[str, Any]:
        """Convert record into a psutil-compatible process dictionary."""
        cmdline = None
        if self.command_line:
            cmdline = [token.strip('"') for token in split_command_line(self.command_line)]

        return {
            "pid": self.pid,
            "ppid": self.parent_pid,
            "name": self.process_name,
            "parent_name": self.parent_process_name,
            "username": self.user,
            "cmdline": cmdline,
            "create_time": self.timestamp,
            "exe": self.image,
            "command_line_raw": self.command_line,
            "telemetry_source": "sysmon",
            "telemetry_record_id": self.record_id,
            "process_guid": self.process_guid,
            "parent_process_guid": self.parent_process_guid,
            "parent_command_line": self.parent_command_line,
            "hashes": dict(self.hashes),
            "integrity_level": self.integrity_level,
            "rule_name": self.rule_name,
            "current_directory": self.current_directory,
            "telemetry_fields_available": list(self.fields_available),
        }


@dataclass
class SysmonNetworkRecord:
    """
    Normalized representation of a Sysmon Network Connection (Event ID 3) record.
    """

    record_id: str
    event_id: int
    channel: str
    timestamp: float
    record_sequence: Optional[int] = None
    time_created_iso: str = ""
    provider: str = ""
    process_guid: Optional[str] = None
    pid: Optional[int] = None
    image: Optional[str] = None
    process_name: Optional[str] = None
    user: Optional[str] = None
    protocol: str = "TCP"
    initiated: Optional[bool] = None
    source_is_ipv6: Optional[bool] = None
    source_ip: Optional[str] = None
    source_hostname: Optional[str] = None
    source_port: Optional[int] = None
    source_port_name: Optional[str] = None
    destination_is_ipv6: Optional[bool] = None
    destination_ip: Optional[str] = None
    destination_hostname: Optional[str] = None
    destination_port: Optional[int] = None
    destination_port_name: Optional[str] = None
    rule_name: Optional[str] = None
    fields_available: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to a JSON-serializable dictionary."""
        return asdict(self)

    def to_network_connection(self) -> NetworkConnection:
        """Convert record into a NetworkConnection object."""
        local_ip = self.source_ip or "0.0.0.0"
        local_port = self.source_port or 0
        status = "ESTABLISHED" if self.initiated else "LISTEN"

        return NetworkConnection(
            pid=self.pid,
            protocol=self.protocol,
            local_ip=local_ip,
            local_port=local_port,
            remote_ip=self.destination_ip,
            remote_port=self.destination_port,
            status=status,
            process_name=self.process_name,
            parent_process_name=None,
            process_create_time=None,
            timestamp=self.timestamp,
        )


def _strip_ns(tag: str) -> str:
    """Remove XML namespace prefix if present."""
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def _parse_int_value(raw: Any) -> Optional[int]:
    """Parse an integer from decimal or hexadecimal text."""
    if raw is None or isinstance(raw, bool):
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


def _parse_bool_value(raw: Any) -> Optional[bool]:
    """Parse a boolean value from text or native boolean."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in ("true", "1", "yes"):
        return True
    if text in ("false", "0", "no"):
        return False
    return None


def _parse_timestamp(iso_text: str) -> float:
    """Parse a Windows SystemTime or ISO timestamp into a Unix timestamp."""
    if not iso_text:
        return time.time()

    cleaned = iso_text.strip().rstrip("Z")
    if " " in cleaned and "T" not in cleaned:
        cleaned = cleaned.replace(" ", "T")

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


def _parse_hashes(raw: Optional[str]) -> Dict[str, str]:
    """Parse Sysmon hash string (e.g. 'SHA256=...,MD5=...') into a dictionary."""
    if not raw:
        return {}

    hashes: Dict[str, str] = {}
    normalized = raw.replace(";", ",").replace("\n", ",")
    for part in normalized.split(","):
        part = part.strip()
        if "=" in part:
            algo, _, hval = part.partition("=")
            algo = algo.strip().upper()
            hval = hval.strip()
            if algo and hval:
                hashes[algo] = hval
    return hashes


class SysmonEventParser:
    """
    Parses Windows Event Log XML payloads for Sysmon Operational records.

    Parses named event-data fields to remain resilient against schema changes
    or differing field order across Sysmon versions.
    """

    def __init__(self, path_normalizer: Optional[NTPathNormalizer] = None) -> None:
        self.normalizer = path_normalizer if path_normalizer is not None else NTPathNormalizer()
        self.malformed_count = 0

    def parse_event_xml(self, xml_text: str) -> List[Any]:
        """Parse XML payload into a list of SysmonProcessRecord or SysmonNetworkRecord."""
        records: List[Any] = []
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
            self.malformed_count += 1
            logger.debug(f"Malformed Sysmon event payload XML: {exc}")
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

    def _parse_event_element(self, event_elem: ET.Element) -> Optional[Any]:
        """Convert a single <Event> XML element into a Sysmon record."""
        try:
            system_elem: Optional[ET.Element] = None
            event_data_elem: Optional[ET.Element] = None

            for child in event_elem:
                tag = _strip_ns(child.tag)
                if tag == "System":
                    system_elem = child
                elif tag in ("EventData", "UserData"):
                    event_data_elem = child

            if system_elem is None:
                self.malformed_count += 1
                return None

            event_id: Optional[int] = None
            record_id: str = ""
            record_sequence: Optional[int] = None
            provider_name = ""
            channel_name = SYSMON_CHANNEL
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
                    channel_name = (s_child.text or "").strip() or SYSMON_CHANNEL
                elif s_tag == "TimeCreated":
                    time_created_iso = s_child.attrib.get("SystemTime", "")
                    timestamp = _parse_timestamp(time_created_iso)

            if event_id is None:
                self.malformed_count += 1
                return None

            # Only Process Creation (1) and Network Connection (3) are handled
            if event_id not in (SYSMON_PROCESS_CREATION_EVENT_ID, SYSMON_NETWORK_CONNECT_EVENT_ID):
                return None

            # Parse named EventData fields
            data: Dict[str, str] = {}
            if event_data_elem is not None:
                for d_child in event_data_elem:
                    d_name = d_child.attrib.get("Name")
                    d_value = d_child.text if d_child.text is not None else ""
                    if d_name:
                        data[d_name] = d_value

            # Fallback timestamp from UtcTime if SystemTime was missing
            if not time_created_iso and data.get("UtcTime"):
                time_created_iso = data["UtcTime"]
                timestamp = _parse_timestamp(time_created_iso)

            available: List[str] = [k for k, v in data.items() if v is not None and v != ""]

            # -------------------------------------------------------------
            # Event ID 1: Process Creation
            # -------------------------------------------------------------
            if event_id == SYSMON_PROCESS_CREATION_EVENT_ID:
                process_guid = data.get("ProcessGuid") or None
                pid = _parse_int_value(data.get("ProcessId"))

                raw_image = data.get("Image") or None
                image: Optional[str] = None
                process_name: Optional[str] = None
                if raw_image:
                    image = self.normalizer.normalize_path(raw_image)
                    process_name = os.path.basename(image or raw_image)

                command_line = data.get("CommandLine") or None
                current_directory = data.get("CurrentDirectory") or None
                user = data.get("User") or None
                logon_guid = data.get("LogonGuid") or None
                logon_id = data.get("LogonId") or None
                terminal_session_id = _parse_int_value(data.get("TerminalSessionId"))
                integrity_level = data.get("IntegrityLevel") or None

                hashes_raw = data.get("Hashes") or None
                hashes = _parse_hashes(hashes_raw)

                parent_process_guid = data.get("ParentProcessGuid") or None
                parent_pid = _parse_int_value(data.get("ParentProcessId"))
                raw_parent_image = data.get("ParentImage") or None
                parent_image: Optional[str] = None
                parent_process_name: Optional[str] = None
                if raw_parent_image:
                    parent_image = self.normalizer.normalize_path(raw_parent_image)
                    parent_process_name = os.path.basename(parent_image or raw_parent_image)

                parent_command_line = data.get("ParentCommandLine") or None
                parent_user = data.get("ParentUser") or None
                rule_name = data.get("RuleName") or None
                original_file_name = data.get("OriginalFileName") or None
                description = data.get("Description") or None
                product = data.get("Product") or None
                company = data.get("Company") or None

                return SysmonProcessRecord(
                    record_id=record_id or f"{channel_name}:{record_sequence or 0}",
                    event_id=event_id,
                    channel=channel_name,
                    timestamp=timestamp,
                    record_sequence=record_sequence,
                    time_created_iso=time_created_iso,
                    provider=provider_name,
                    process_guid=process_guid,
                    pid=pid,
                    image=image,
                    process_name=process_name,
                    command_line=command_line,
                    current_directory=current_directory,
                    user=user,
                    logon_guid=logon_guid,
                    logon_id=logon_id,
                    terminal_session_id=terminal_session_id,
                    integrity_level=integrity_level,
                    hashes=hashes,
                    hashes_raw=hashes_raw,
                    parent_process_guid=parent_process_guid,
                    parent_pid=parent_pid,
                    parent_image=parent_image,
                    parent_process_name=parent_process_name,
                    parent_command_line=parent_command_line,
                    parent_user=parent_user,
                    rule_name=rule_name,
                    original_file_name=original_file_name,
                    description=description,
                    product=product,
                    company=company,
                    fields_available=available,
                    raw_data=data,
                )

            # -------------------------------------------------------------
            # Event ID 3: Network Connection
            # -------------------------------------------------------------
            if event_id == SYSMON_NETWORK_CONNECT_EVENT_ID:
                process_guid = data.get("ProcessGuid") or None
                pid = _parse_int_value(data.get("ProcessId"))

                raw_image = data.get("Image") or None
                image = self.normalizer.normalize_path(raw_image) if raw_image else None
                process_name = os.path.basename(image or raw_image) if (image or raw_image) else None

                user = data.get("User") or None
                protocol = (data.get("Protocol") or "TCP").upper()
                initiated = _parse_bool_value(data.get("Initiated"))
                source_is_ipv6 = _parse_bool_value(data.get("SourceIsIpv6"))
                source_ip = data.get("SourceIp") or None
                source_hostname = data.get("SourceHostname") or None
                source_port = _parse_int_value(data.get("SourcePort"))
                source_port_name = data.get("SourcePortName") or None

                destination_is_ipv6 = _parse_bool_value(data.get("DestinationIsIpv6"))
                destination_ip = data.get("DestinationIp") or None
                destination_hostname = data.get("DestinationHostname") or None
                destination_port = _parse_int_value(data.get("DestinationPort"))
                destination_port_name = data.get("DestinationPortName") or None
                rule_name = data.get("RuleName") or None

                return SysmonNetworkRecord(
                    record_id=record_id or f"{channel_name}:{record_sequence or 0}",
                    event_id=event_id,
                    channel=channel_name,
                    timestamp=timestamp,
                    record_sequence=record_sequence,
                    time_created_iso=time_created_iso,
                    provider=provider_name,
                    process_guid=process_guid,
                    pid=pid,
                    image=image,
                    process_name=process_name,
                    user=user,
                    protocol=protocol,
                    initiated=initiated,
                    source_is_ipv6=source_is_ipv6,
                    source_ip=source_ip,
                    source_hostname=source_hostname,
                    source_port=source_port,
                    source_port_name=source_port_name,
                    destination_is_ipv6=destination_is_ipv6,
                    destination_ip=destination_ip,
                    destination_hostname=destination_hostname,
                    destination_port=destination_port,
                    destination_port_name=destination_port_name,
                    rule_name=rule_name,
                    fields_available=available,
                    raw_data=data,
                )

        except Exception as exc:
            self.malformed_count += 1
            logger.debug(f"Failed to parse Sysmon event element: {exc}")
            return None

        return None


class SysmonTelemetryCollector:
    """
    Reads Sysmon events from 'Microsoft-Windows-Sysmon/Operational'.

    Tracks the highest processed EventRecordID to poll incrementally, handles
    channel clear / rollover safely, dedupes records, and maintains health
    diagnostics.
    """

    def __init__(
        self,
        channel: str = SYSMON_CHANNEL,
        enable_process_events: bool = True,
        enable_network_events: bool = True,
        max_events_per_query: int = 200,
        query_timeout: float = 10.0,
        executor: Optional[Callable[..., Any]] = None,
        dedup_capacity: int = 5000,
    ) -> None:
        self.channel = channel or SYSMON_CHANNEL
        self.enable_process_events = bool(enable_process_events)
        self.enable_network_events = bool(enable_network_events)
        self.max_events_per_query = max(1, min(int(max_events_per_query), 1000))
        self.query_timeout = float(query_timeout)
        self._executor = executor if executor is not None else subprocess.run
        self.parser = SysmonEventParser()

        self._lock = threading.RLock()
        self._last_record_id = 0
        self._baseline_seeded = False
        self._seen_record_ids: Set[str] = set()
        self._seen_order: Deque[str] = deque(maxlen=max(1, dedup_capacity))

        self._status = SysmonTelemetryStatus.UNKNOWN
        self._unavailable_reason: Optional[str] = None
        self._last_error: Optional[str] = None
        self._records_collected = 0
        self._process_records_collected = 0
        self._network_records_collected = 0
        self._warnings_emitted = 0
        self._last_success_timestamp: Optional[float] = None

    # ------------------------------------------------------------------
    # Status & Diagnostics
    # ------------------------------------------------------------------

    @property
    def status(self) -> str:
        """Current availability status."""
        with self._lock:
            return self._status

    @property
    def unavailable_reason(self) -> Optional[str]:
        """Reason why collector is unavailable (if any)."""
        with self._lock:
            return self._unavailable_reason

    @property
    def last_error(self) -> Optional[str]:
        """Most recent error message."""
        with self._lock:
            return self._last_error

    @property
    def records_collected(self) -> int:
        """Total records processed."""
        with self._lock:
            return self._records_collected

    @property
    def last_record_id(self) -> int:
        """Highest EventRecordID seen."""
        with self._lock:
            return self._last_record_id

    def get_status_snapshot(self) -> Dict[str, Any]:
        """Return a structured diagnostic snapshot of the Sysmon telemetry source."""
        with self._lock:
            if not self.enable_network_events:
                event_3_status = "DISABLED_BY_CONFIG"
            elif self._network_records_collected > 0:
                event_3_status = "ACTIVE"
            elif self._status == SysmonTelemetryStatus.UNAVAILABLE:
                event_3_status = "UNAVAILABLE"
            else:
                event_3_status = "ENABLED_AWAITING_EVENTS"

            return {
                "enabled": self._status != SysmonTelemetryStatus.UNAVAILABLE,
                "status": self._status,
                "channel": self.channel,
                "process_events_enabled": self.enable_process_events,
                "network_events_enabled": self.enable_network_events,
                "event_id_3_logging_status": event_3_status,
                "unavailable_reason": self._unavailable_reason,
                "last_error": self._last_error,
                "records_collected": self._records_collected,
                "process_records_collected": self._process_records_collected,
                "network_records_collected": self._network_records_collected,
                "malformed_events_count": self.parser.malformed_count,
                "last_record_id": self._last_record_id,
                "last_success_timestamp": self._last_success_timestamp,
                "baseline_seeded": self._baseline_seeded,
            }

    def close(self) -> None:
        """Release in-memory deduplication caches."""
        with self._lock:
            self._seen_record_ids.clear()
            self._seen_order.clear()

    # ------------------------------------------------------------------
    # Query Building
    # ------------------------------------------------------------------

    def build_query(self, last_record_id: Optional[int] = None) -> str:
        """Build the XPath filter for Sysmon event queries."""
        event_ids: List[int] = []
        if self.enable_process_events:
            event_ids.append(SYSMON_PROCESS_CREATION_EVENT_ID)
        if self.enable_network_events:
            event_ids.append(SYSMON_NETWORK_CONNECT_EVENT_ID)

        if not event_ids:
            return "*[System[(EventID=0)]]"

        if len(event_ids) == 1:
            id_clause = f"EventID={event_ids[0]}"
        else:
            id_clause = " or ".join(f"EventID={eid}" for eid in event_ids)
            id_clause = f"({id_clause})"

        if last_record_id is None:
            last_record_id = self._last_record_id

        try:
            sequence = int(last_record_id)
        except (TypeError, ValueError):
            sequence = 0

        if sequence > 0:
            return f"*[System[{id_clause} and (EventRecordID > {sequence})]]"

        return f"*[System[{id_clause}]]"

    def _build_command(self, query: str, reverse: bool = False, count: Optional[int] = None) -> List[str]:
        """Construct the wevtutil query command."""
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
    # Query Execution & Baseline Seeding
    # ------------------------------------------------------------------

    def _run_query(self, command: List[str]) -> Optional[str]:
        """Execute a wevtutil query and handle OS / execution outcomes."""
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
            self._warn("Sysmon event log query timed out.")
            return None
        except Exception as exc:
            self._warn(f"Sysmon event log query failed: {exc}")
            return None

        returncode = getattr(result, "returncode", 0)
        stdout = getattr(result, "stdout", "") or ""
        stderr = getattr(result, "stderr", "") or ""

        if returncode != 0:
            lowered = str(stderr).lower()
            if "access is denied" in lowered or "access denied" in lowered:
                self._disable(
                    "access_denied",
                    f"Reading the Sysmon event log ('{self.channel}') requires administrative or event-log reader privileges.",
                )
            elif (
                "could not be found" in lowered
                or "no events were found" in lowered
                or "the specified channel could not be found" in lowered
            ):
                self._disable(
                    "channel_unavailable",
                    f"Windows event log channel '{self.channel}' is not available. Ensure Sysmon is installed.",
                )
            else:
                self._warn(
                    f"Sysmon event log query exited with code {returncode}: {str(stderr).strip()}"
                )
            return None

        return stdout

    def seed_baseline(self) -> bool:
        """
        Establish incremental bookmark baseline using the newest existing event.

        Prevents replaying historical events upon monitor launch.
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
            seq = getattr(record, "record_sequence", None)
            if seq and seq > newest:
                newest = seq

        with self._lock:
            self._last_record_id = newest
            self._baseline_seeded = True
            self._status = SysmonTelemetryStatus.AVAILABLE
            self._last_success_timestamp = time.time()
            self._last_error = None
            self._unavailable_reason = None

        logger.info(
            f"Sysmon telemetry baseline established on channel '{self.channel}' "
            f"(last record id: {newest})."
        )
        return True

    def query_live_events(self) -> List[Any]:
        """
        Query newly arrived Sysmon events since the previous query.

        Handles channel clear / rollover detection and deduplication.
        """
        with self._lock:
            if self._status == SysmonTelemetryStatus.UNAVAILABLE:
                return []

        if not self.seed_baseline():
            return []

        query = self.build_query()
        stdout = self._run_query(self._build_command(query))
        if stdout is None:
            return []

        records = self.parser.parse_event_xml(stdout)

        # Detect log rollover / clearing if incremental query returned nothing but log sequence reset
        if not records and self._last_record_id > 0:
            probe_query = self.build_query(0)
            probe_stdout = self._run_query(self._build_command(probe_query, reverse=True, count=1))
            if probe_stdout:
                probe_records = self.parser.parse_event_xml(probe_stdout)
                if probe_records:
                    newest_in_log = getattr(probe_records[0], "record_sequence", 0) or 0
                    if 0 < newest_in_log < self._last_record_id:
                        logger.warning(
                            f"[SYSMON TELEMETRY] Log rollover or channel clear detected "
                            f"(bookmark was {self._last_record_id}, newest record is {newest_in_log}). Resetting bookmark."
                        )
                        with self._lock:
                            self._last_record_id = 0
                            self._seen_record_ids.clear()
                            self._seen_order.clear()
                        # Re-run from reset bookmark
                        return self.query_live_events()

        new_records: List[Any] = []

        with self._lock:
            for record in records:
                rec_id = getattr(record, "record_id", None)
                if not rec_id or rec_id in self._seen_record_ids:
                    continue

                if len(self._seen_order) == self._seen_order.maxlen:
                    oldest = self._seen_order[0]
                    self._seen_record_ids.discard(oldest)
                self._seen_order.append(rec_id)
                self._seen_record_ids.add(rec_id)

                seq = getattr(record, "record_sequence", None)
                if seq and seq > self._last_record_id:
                    self._last_record_id = seq

                self._records_collected += 1
                if isinstance(record, SysmonProcessRecord) or getattr(record, "event_id", 0) == 1:
                    self._process_records_collected += 1
                elif isinstance(record, SysmonNetworkRecord) or getattr(record, "event_id", 0) == 3:
                    self._network_records_collected += 1

                new_records.append(record)

            if self._status == SysmonTelemetryStatus.UNKNOWN:
                self._status = SysmonTelemetryStatus.AVAILABLE
            self._last_success_timestamp = time.time()
            self._last_error = None
            self._unavailable_reason = None

        return new_records

    # ------------------------------------------------------------------
    # Diagnostics Logging
    # ------------------------------------------------------------------

    def _warn(self, message: str) -> None:
        """Record a non-fatal warning condition."""
        with self._lock:
            self._last_error = message
            if self._status != SysmonTelemetryStatus.UNAVAILABLE:
                self._status = SysmonTelemetryStatus.DEGRADED
            self._warnings_emitted += 1
            should_log = self._warnings_emitted <= 3
        if should_log:
            logger.warning(f"[SYSMON TELEMETRY] {message}")

    def _disable(self, reason: str, message: str) -> None:
        """Mark the collector as unavailable."""
        with self._lock:
            if self._status == SysmonTelemetryStatus.UNAVAILABLE:
                return
            self._status = SysmonTelemetryStatus.UNAVAILABLE
            self._unavailable_reason = reason
            self._last_error = message
        logger.warning(
            f"[SYSMON TELEMETRY] {message} Sysmon telemetry is disabled; "
            f"polling and other monitoring continue."
        )


class SysmonTelemetryCorrelator:
    """
    Correlates Sysmon process and network records with existing processes and
    normalizes them into standard Event objects.
    """

    def __init__(self, path_normalizer: Optional[NTPathNormalizer] = None) -> None:
        self.normalizer = path_normalizer if path_normalizer is not None else NTPathNormalizer()

    def to_process_info(
        self,
        record: SysmonProcessRecord,
        running_processes: Optional[Dict[int, Dict[str, Any]]] = None,
        identity_tolerance: float = 5.0,
    ) -> Dict[str, Any]:
        """Build a psutil-compatible process dictionary from a SysmonProcessRecord."""
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
                    live_is_same_instance = (
                        abs(float(live_create) - float(record.timestamp)) <= identity_tolerance
                    )
                except (TypeError, ValueError):
                    live_is_same_instance = False

        if live_is_same_instance:
            if not process_info.get("name") and live.get("name"):
                process_info["name"] = live.get("name")
            if not process_info.get("parent_name") and live.get("parent_name"):
                process_info["parent_name"] = live.get("parent_name")
            if not process_info.get("username") and live.get("username"):
                process_info["username"] = live.get("username")
            if not process_info.get("cmdline") and live.get("cmdline"):
                process_info["cmdline"] = live.get("cmdline")
            if not process_info.get("exe") and live.get("exe"):
                process_info["exe"] = live.get("exe")
        elif record.parent_pid and not process_info.get("parent_name"):
            process_info["parent_name"] = get_parent_process_name(record.parent_pid)

        process_info["live_process_matched"] = live_is_same_instance
        return process_info

    def to_event(
        self,
        record: SysmonProcessRecord,
        running_processes: Optional[Dict[int, Dict[str, Any]]] = None,
        process_tree: Any = None,
        tree_analyzer: Any = None,
    ) -> Event:
        """
        Normalize a SysmonProcessRecord into a standard Event, run command
        indicators and process-tree lineage analysis, and calculate combined risk.
        """
        process_info = self.to_process_info(record, running_processes=running_processes)

        event = Event.from_process_info(process_info)
        event.source = "sysmon"
        event.event_type = "process_start"
        event.timestamp = record.timestamp

        # 1. Command Line Indicators Analysis
        event.indicators = detect_command_indicators(event.command_line)

        # 2. Process Tree Analysis if analyzer provided
        tree_analysis = {}
        if tree_analyzer is not None:
            tree_analysis = tree_analyzer.analyze_process(process_info, process_tree)
            event.metadata["process_tree"] = tree_analysis
            for ind in tree_analysis.get("indicators", []):
                if ind not in event.indicators:
                    event.indicators.append(ind)

        # 3. Combined Risk Scoring
        risk_result = calculate_risk(
            event.indicators,
            process_info,
            tree_findings=tree_analysis.get("findings") if tree_analysis else None,
        )

        event.risk_score = risk_result["score"]
        event.risk_level = risk_result["level"]
        event.risk_reasons = risk_result["reasons"]
        event.severity = risk_result["level"]

        # Sysmon telemetry evidence metadata
        event.metadata["telemetry_source"] = "sysmon"
        event.metadata["sysmon"] = {
            "channel": record.channel,
            "event_id": record.event_id,
            "record_id": record.record_id,
            "record_sequence": record.record_sequence,
            "provider": record.provider,
            "time_created_iso": record.time_created_iso,
            "process_guid": record.process_guid,
            "parent_process_guid": record.parent_process_guid,
            "image": record.image,
            "parent_image": record.parent_image,
            "command_line": record.command_line,
            "parent_command_line": record.parent_command_line,
            "current_directory": record.current_directory,
            "user": record.user,
            "hashes": dict(record.hashes),
            "hashes_raw": record.hashes_raw,
            "integrity_level": record.integrity_level,
            "rule_name": record.rule_name,
            "original_file_name": record.original_file_name,
            "description": record.description,
            "product": record.product,
            "company": record.company,
            "logon_guid": record.logon_guid,
            "logon_id": record.logon_id,
            "terminal_session_id": record.terminal_session_id,
            "fields_available": list(record.fields_available),
        }

        return event

    def to_network_event(
        self,
        record: SysmonNetworkRecord,
        findings: Optional[Dict[str, Any]] = None,
        network_monitor: Optional[NetworkMonitor] = None,
        process_tree: Any = None,
    ) -> Event:
        """
        Normalize a SysmonNetworkRecord into a standard network connection Event.
        """
        conn = record.to_network_connection()

        if findings is None and network_monitor is not None:
            proc_info = {
                "pid": record.pid,
                "name": record.process_name,
                "username": record.user,
            }
            findings = network_monitor.evaluate_connection(
                conn, process_info=proc_info, process_tree=process_tree
            )

        findings = findings or {}
        indicators = list(findings.get("indicators", []))

        risk_result = calculate_risk(
            indicators=indicators,
            process_info={"pid": conn.pid, "name": conn.process_name},
            tree_findings=findings.get("findings"),
        )

        event = Event(
            event_type="network_connection",
            source="sysmon",
            severity=risk_result["level"],
            pid=conn.pid,
            process_name=conn.process_name,
            parent_process_name=conn.parent_process_name,
            timestamp=record.timestamp,
            network_info=conn.to_dict(),
            indicators=indicators,
            risk_score=risk_result["score"],
            risk_level=risk_result["level"],
            risk_reasons=risk_result["reasons"],
            metadata={
                "telemetry_source": "sysmon",
                "network_findings": findings,
                "sysmon": {
                    "channel": record.channel,
                    "event_id": record.event_id,
                    "record_id": record.record_id,
                    "record_sequence": record.record_sequence,
                    "provider": record.provider,
                    "time_created_iso": record.time_created_iso,
                    "process_guid": record.process_guid,
                    "protocol": record.protocol,
                    "initiated": record.initiated,
                    "source_ip": record.source_ip,
                    "source_port": record.source_port,
                    "source_hostname": record.source_hostname,
                    "destination_ip": record.destination_ip,
                    "destination_port": record.destination_port,
                    "destination_hostname": record.destination_hostname,
                    "rule_name": record.rule_name,
                    "fields_available": list(record.fields_available),
                },
            },
        )
        return event
