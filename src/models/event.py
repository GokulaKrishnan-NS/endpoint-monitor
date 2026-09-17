from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
import time
import uuid


@dataclass
class Event:
    """
    Standardized security event representation across all monitors and detectors.
    """

    # 1. Base Event Metadata (Required)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    event_type: str = ""        # e.g., "process_start", "resource_anomaly", "file_action"
    source: str = ""            # e.g., "process_monitor", "resource_monitor", "file_monitor"
    severity: str = "LOW"        # "LOW", "MEDIUM", "HIGH"

    # 2. Process Context (Optional - process & command events)
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_name: Optional[str] = None
    parent_process_name: Optional[str] = None
    username: Optional[str] = None
    command_line: Optional[List[str]] = None

    # 3. File Context (Optional - file events)
    file_path: Optional[str] = None
    file_action: Optional[str] = None        # "created", "modified", "deleted", "moved"
    dest_path: Optional[str] = None          # For moved/renamed files

    # 4. Resource Context (Optional - resource anomaly events)
    resource_metrics: Optional[Dict[str, Any]] = None  # CPU %, RAM %, Disk %, Swap %

    # 5. Network Context (Optional - reserved for future network monitoring)
    network_info: Optional[Dict[str, Any]] = None

    # 6. Detection & Risk Intelligence (Optional - populated by detectors)
    indicators: List[str] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"
    risk_reasons: List[str] = field(default_factory=list)

    # 7. Extensibility Metadata (Optional)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event instance to JSON-serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_process_info(cls, process_info: Dict[str, Any]) -> "Event":
        """
        Helper factory method to construct a standard Event from a raw process_info dictionary.
        """
        return cls(
            event_type="process_start",
            source="process_monitor",
            severity="LOW",
            pid=process_info.get("pid"),
            ppid=process_info.get("ppid"),
            process_name=process_info.get("name"),
            parent_process_name=process_info.get("parent_name"),
            username=process_info.get("username"),
            command_line=process_info.get("cmdline"),
        )

    @classmethod
    def from_network_connection(
        cls,
        conn_info: Dict[str, Any],
        process_info: Optional[Dict[str, Any]] = None,
    ) -> "Event":
        """
        Helper factory method to construct a standard Event from a network connection dictionary.
        """
        proc = process_info or {}
        return cls(
            event_type="network_connection",
            source="network_monitor",
            severity="LOW",
            pid=conn_info.get("pid") or proc.get("pid"),
            ppid=proc.get("ppid"),
            process_name=conn_info.get("process_name") or proc.get("name"),
            parent_process_name=conn_info.get("parent_process_name") or proc.get("parent_name"),
            username=proc.get("username"),
            command_line=proc.get("cmdline"),
            network_info=conn_info,
        )
