"""
UI Presentation and Data Adapter Module (Phase 5).

Transforms domain models, process tables, security events, and telemetry
into sanitized, formatted, sortable, and filterable presentation structures.
"""

from datetime import datetime, timezone
import os
from typing import Any, Dict, List, Optional, Tuple

from src.execution.service import redact_string
from src.models.event import Event


# Color mappings for UI severity badges
SEVERITY_COLORS: Dict[str, str] = {
    "HIGH": "#dc3545",       # Bright Red
    "CRITICAL": "#b02a37",   # Dark Red
    "MEDIUM": "#fd7e14",     # Orange
    "LOW": "#198754",        # Green
    "INFO": "#0d6efd",       # Blue
    "UNKNOWN": "#6c757d",    # Gray
}


def format_timestamp(timestamp: Optional[float]) -> str:
    """Format Unix timestamp to human-readable ISO string."""
    if timestamp is None or timestamp <= 0:
        return "N/A"
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"


def format_bytes(num_bytes: Optional[int]) -> str:
    """Format bytes count into human-readable string (KB, MB, GB)."""
    if num_bytes is None or num_bytes < 0:
        return "N/A"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def format_percent(percent: Optional[float]) -> str:
    """Format percentage value to one decimal place."""
    if percent is None:
        return "N/A"
    try:
        return f"{float(percent):.1f}%"
    except (ValueError, TypeError):
        return "N/A"


def get_severity_color(severity: str) -> str:
    """Retrieve corresponding HEX color code for severity level."""
    return SEVERITY_COLORS.get((severity or "").upper(), SEVERITY_COLORS["UNKNOWN"])


def adapt_process_row(
    proc_info: Dict[str, Any],
    event: Optional[Event] = None,
) -> Dict[str, Any]:
    """Transform raw process information and evaluated Event into a presentation row."""
    pid = proc_info.get("pid", 0)
    ppid = proc_info.get("ppid")
    name = proc_info.get("name") or "unknown"
    cmdline = proc_info.get("cmdline") or []
    username = proc_info.get("username") or "N/A"
    cpu = proc_info.get("cpu_percent")
    memory = proc_info.get("memory_percent")

    # Resolve executable path with redaction
    raw_path = proc_info.get("exe") or (cmdline[0] if cmdline else name)
    sanitized_path = redact_string(str(raw_path))

    # Incorporate evaluated Event metadata if present
    risk_score = 0
    risk_level = "LOW"
    risk_reasons: List[str] = []
    lineage_str = ""

    if event:
        risk_score = event.risk_score
        risk_level = event.risk_level
        risk_reasons = event.risk_reasons
        tree_meta = event.metadata.get("process_tree", {})
        if tree_meta.get("lineage"):
            lineage_str = " -> ".join(tree_meta["lineage"])

    return {
        "pid": pid,
        "ppid": ppid if ppid is not None else "N/A",
        "name": name,
        "path": sanitized_path,
        "username": username,
        "cpu_percent": cpu,
        "cpu_str": format_percent(cpu),
        "memory_percent": memory,
        "memory_str": format_percent(memory),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": risk_reasons,
        "reasons_str": "; ".join(risk_reasons) if risk_reasons else "Normal",
        "lineage": lineage_str,
        "raw_info": proc_info,
        "event": event,
    }


def filter_and_sort_processes(
    processes: Dict[int, Dict[str, Any]],
    process_events: Dict[int, Event],
    search_query: str = "",
    severity_filter: str = "ALL",
    sort_column: str = "pid",
    reverse: bool = False,
) -> List[Dict[str, Any]]:
    """Filter and sort process rows for table presentation."""
    query_clean = search_query.strip().lower()
    sev_filter_upper = severity_filter.strip().upper()

    rows: List[Dict[str, Any]] = []

    for pid, proc in processes.items():
        evt = process_events.get(pid)
        row = adapt_process_row(proc, evt)

        # Apply severity filter
        if sev_filter_upper != "ALL" and row["risk_level"].upper() != sev_filter_upper:
            continue

        # Apply search query
        if query_clean:
            haystack = (
                f"{row['pid']} {row['ppid']} {row['name']} {row['path']} "
                f"{row['username']} {row['reasons_str']} {row['lineage']}"
            ).lower()
            if query_clean not in haystack:
                continue

        rows.append(row)

    # Sort rows safely across mixed types
    def _sort_key(item: Dict[str, Any]):
        val = item.get(sort_column)
        if val is None or val == "N/A" or val == "":
            return (1, 0, "")
        if isinstance(val, (int, float)):
            return (0, 0, float(val))
        return (0, 1, str(val).lower())

    try:
        rows.sort(key=_sort_key, reverse=reverse)
    except Exception:
        pass  # Fall back to insertion order if comparisons fail

    return rows


def adapt_event_row(event: Event) -> Dict[str, Any]:
    """Transform a security Event into a standardized table row."""
    time_str = format_timestamp(event.timestamp)
    reasons_str = "; ".join(event.risk_reasons) if event.risk_reasons else "None"
    proc_info_str = f"{event.process_name or 'N/A'} (PID: {event.pid or 'N/A'})"

    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "time_str": time_str,
        "severity": event.severity or "LOW",
        "source": event.source or "unknown",
        "event_type": event.event_type or "unknown",
        "process_name": event.process_name or "N/A",
        "pid": event.pid,
        "proc_info_str": proc_info_str,
        "file_path": redact_string(event.file_path or ""),
        "risk_score": event.risk_score,
        "risk_level": event.risk_level,
        "indicators": event.indicators,
        "reasons": event.risk_reasons,
        "reasons_str": reasons_str,
        "raw_event": event,
    }


def filter_and_sort_events(
    events: List[Event],
    search_query: str = "",
    source_filter: str = "ALL",
    severity_filter: str = "ALL",
    sort_column: str = "timestamp",
    reverse: bool = True,
) -> List[Dict[str, Any]]:
    """Filter and sort security events and alerts."""
    query_clean = search_query.strip().lower()
    source_filter_lower = source_filter.strip().lower()
    sev_filter_upper = severity_filter.strip().upper()

    rows: List[Dict[str, Any]] = []

    for evt in events:
        row = adapt_event_row(evt)

        # Filter by source
        if source_filter_lower != "all" and row["source"].lower() != source_filter_lower:
            continue

        # Filter by severity
        if sev_filter_upper != "ALL" and row["severity"].upper() != sev_filter_upper:
            continue

        # Search query matching
        if query_clean:
            haystack = (
                f"{row['time_str']} {row['severity']} {row['source']} {row['event_type']} "
                f"{row['proc_info_str']} {row['file_path']} {row['reasons_str']}"
            ).lower()
            if query_clean not in haystack:
                continue

        rows.append(row)

    # Sort rows safely across mixed types
    def _sort_key(item: Dict[str, Any]):
        val = item.get(sort_column)
        if val is None or val == "N/A" or val == "":
            return (1, 0, "")
        if isinstance(val, (int, float)):
            return (0, 0, float(val))
        return (0, 1, str(val).lower())

    try:
        rows.sort(key=_sort_key, reverse=reverse)
    except Exception:
        pass

    return rows


def adapt_network_event_row(event: Event) -> Dict[str, Any]:
    """Extract and format network connection metadata from standard Event."""
    net_info = event.network_info or {}
    local_addr = net_info.get("local_address") or "N/A"
    remote_addr = net_info.get("remote_address") or "N/A"
    protocol = net_info.get("protocol") or "TCP"
    is_suspicious = bool(event.indicators or event.risk_score >= 4)

    return {
        "event_id": event.event_id,
        "time_str": format_timestamp(event.timestamp),
        "pid": event.pid or "N/A",
        "process_name": event.process_name or "N/A",
        "protocol": protocol,
        "local_address": local_addr,
        "remote_address": remote_addr,
        "status": "SUSPICIOUS" if is_suspicious else "NORMAL",
        "risk_level": event.risk_level,
        "reasons_str": "; ".join(event.risk_reasons) if event.risk_reasons else "Standard Port",
    }


def adapt_file_event_row(event: Event) -> Dict[str, Any]:
    """Extract and format file system event metadata from standard Event."""
    action = (event.file_action or "modified").upper()
    file_path = redact_string(event.file_path or "N/A")
    dest_path = redact_string(event.dest_path or "")

    return {
        "event_id": event.event_id,
        "time_str": format_timestamp(event.timestamp),
        "action": action,
        "file_path": file_path,
        "dest_path": dest_path if dest_path else "-",
        "severity": event.severity,
    }

