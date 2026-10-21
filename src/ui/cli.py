"""
Command-Line Interface and Terminal Dashboard Module (Phase 5).

Provides a formatted text-based console dashboard for headless server environments
or command-line invocations (--cli). Fully compatible with standard ASCII and
legacy Windows code pages (cp1252).
"""

import os
import sys
import time
from typing import Optional

from src.ui.adapter import format_bytes, format_percent, format_timestamp
from src.ui.engine import MonitoringEngine


def render_terminal_dashboard(engine: MonitoringEngine) -> str:
    """Render a text-based ASCII security dashboard from current engine telemetry."""
    snap = engine.get_state_snapshot()
    status = snap["status"]
    proc_count = snap["process_count"]
    alerts = snap["alert_counts"]
    resources = snap.get("latest_resources", {})
    ce = snap.get("controlled_execution", {})

    cpu_p = resources.get("cpu", {}).get("percent")
    mem_p = resources.get("memory", {}).get("percent")
    mem_str = resources.get("memory", {}).get("formatted", "N/A")
    disk_p = resources.get("disk", {}).get("percent")

    lines = [
        "=" * 78,
        "[+] ENDPOINT SECURITY MONITOR - TERMINAL DASHBOARD",
        "=" * 78,
        f" Engine Status   : {status:<16} Observed Processes : {proc_count}",
        f" Critical Alerts : {alerts.get('HIGH', 0):<16} Total Events        : {alerts.get('TOTAL', 0)}",
        f" Execution Gate  : Dry-Run={ce.get('dry_run', True)} | Active-Execution={ce.get('allow_active_execution', False)}",
        "-" * 78,
        " [*] SYSTEM RESOURCES:",
        f"   CPU Usage     : {format_percent(cpu_p):<12} Memory Usage : {format_percent(mem_p)} ({mem_str})",
        f"   Disk Usage    : {format_percent(disk_p):<12}",
        "-" * 78,
        " [!] RECENT CRITICAL ALERTS:",
    ]

    recent_alerts = engine.get_alerts_snapshot()[-5:]
    if recent_alerts:
        for a in reversed(recent_alerts):
            time_str = format_timestamp(a.timestamp)
            target = a.process_name or a.file_path or "N/A"
            reasons = "; ".join(a.risk_reasons) if a.risk_reasons else "None"
            lines.append(f"   [{time_str}] [{a.severity}] [{a.source}] {target} (Score: {a.risk_score})")
            lines.append(f"     +-- {reasons[:68]}")
    else:
        lines.append("   (No active critical alerts detected)")

    lines.append("-" * 78)
    lines.append(" [*] HIGHEST-RISK OBSERVED PROCESSES:")

    proc_events = engine.get_process_events_snapshot()
    sorted_evts = sorted(proc_events.values(), key=lambda e: e.risk_score, reverse=True)[:5]

    if sorted_evts and sorted_evts[0].risk_score > 0:
        for pe in sorted_evts:
            p_name = pe.process_name or "N/A"
            lines.append(
                f"   PID: {pe.pid:<6} | Name: {p_name:<18} | Risk: {pe.risk_level:<6} ({pe.risk_score})"
            )
            if pe.risk_reasons:
                lines.append(f"     +-- {'; '.join(pe.risk_reasons)[:68]}")
    else:
        lines.append("   (All monitored processes within normal baseline risk)")

    lines.append("=" * 78)
    return "\n".join(lines)


def run_cli_loop(engine: MonitoringEngine, interval: float = 3.0) -> None:
    """Run an interactive terminal refresh loop."""
    print("Starting Endpoint Security Monitor in Terminal Dashboard mode...")
    engine.start()
    try:
        while True:
            # Clear terminal screen (cross-platform)
            os.system("cls" if os.name == "nt" else "clear")
            print(render_terminal_dashboard(engine))
            print("\nPress Ctrl+C to exit dashboard.")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopping Monitoring Engine...")
        engine.stop()
        print("Endpoint Security Monitor stopped cleanly.")

