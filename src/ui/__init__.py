"""
UI and Presentation Package (Phase 5).
"""

from src.ui.adapter import (
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
from src.ui.cli import render_terminal_dashboard, run_cli_loop
from src.ui.dashboard import SecurityDashboardApp, is_gui_available
from src.ui.engine import MonitoringEngine, MonitoringEngineStatus

__all__ = [
    "MonitoringEngine",
    "MonitoringEngineStatus",
    "SecurityDashboardApp",
    "is_gui_available",
    "render_terminal_dashboard",
    "run_cli_loop",
    "adapt_process_row",
    "adapt_event_row",
    "adapt_network_event_row",
    "adapt_file_event_row",
    "filter_and_sort_processes",
    "filter_and_sort_events",
    "format_timestamp",
    "format_bytes",
    "format_percent",
    "get_severity_color",
]

