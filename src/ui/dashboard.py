"""
Desktop Dashboard User Interface Module (Phase 5).

Implements a native desktop graphical user interface using Python's standard library
tkinter and ttk. Provides a complete security monitoring console with real-time process
inspection, alert history, resource utilization, file/network events, and controlled
execution management.
"""

import json
import logging
import os
import sys
import threading
import time
from typing import Any, Dict, List, Optional

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

from src.execution.service import redact_command_line, redact_string
from src.models.execution_request import ExecutionRequest
from src.ui.adapter import (
    SEVERITY_COLORS,
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
from src.ui.engine import MonitoringEngine, MonitoringEngineStatus


logger = logging.getLogger("endpoint_monitor")


def is_gui_available() -> bool:
    """Check if graphical user interface and display environment are available."""
    if not TKINTER_AVAILABLE:
        return False
    # On Unix, check DISPLAY environment variable
    if sys.platform != "win32" and not os.environ.get("DISPLAY"):
        return False
    try:
        test_root = tk.Tk()
        test_root.withdraw()
        test_root.destroy()
        return True
    except Exception:
        return False


class SecurityDashboardApp:
    """
    Main Desktop Security Dashboard Application.
    Connects to MonitoringEngine and provides an interactive, non-blocking UI.
    """

    def __init__(
        self,
        engine: Optional[MonitoringEngine] = None,
        root: Optional[Any] = None,
        auto_start: bool = True,
    ) -> None:
        if not TKINTER_AVAILABLE:
            raise RuntimeError("Tkinter is not available in the current Python environment.")

        self.engine = engine if engine is not None else MonitoringEngine()
        self.root = root if root is not None else tk.Tk()
        self.auto_start = auto_start

        # Window Configuration
        self.root.title("Endpoint Security Monitor — Windows Endpoint Control Console")
        self.root.geometry("1120x740")
        self.root.minsize(880, 560)

        # UI State Variables
        self.search_process_var = tk.StringVar()
        self.filter_process_sev_var = tk.StringVar(value="ALL")
        self.search_events_var = tk.StringVar()
        self.filter_event_source_var = tk.StringVar(value="ALL")
        self.filter_event_sev_var = tk.StringVar(value="ALL")
        self.status_text_var = tk.StringVar(value="Engine: Initializing...")
        self.auto_refresh_var = tk.BooleanVar(value=True)

        # Style configuration
        self._setup_styles()

        # Build UI layout
        self._build_header_toolbar()
        self._build_notebook_tabs()
        self._build_status_bar()

        # Window protocols
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Start monitoring engine if requested
        if self.auto_start:
            self.engine.start()

        # Begin background UI polling cycle (every 1 second)
        self.root.after(500, self._ui_poll_cycle)

    def _setup_styles(self) -> None:
        """Configure ttk styles and fonts."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("SubHeader.TLabel", font=("Segoe UI", 10, "bold"))
        style.configure("StatValue.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("StatLabel.TLabel", font=("Segoe UI", 9))
        style.configure("Card.TFrame", relief="solid", borderwidth=1)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    # -------------------------------------------------------------------------
    # UI Layout Construction
    # -------------------------------------------------------------------------

    def _build_header_toolbar(self) -> None:
        """Top action bar containing system controls and status summary."""
        toolbar = ttk.Frame(self.root, padding="10 8 10 8")
        toolbar.pack(side=tk.TOP, fill=tk.X)

        # App Title & Icon
        title_box = ttk.Frame(toolbar)
        title_box.pack(side=tk.LEFT)
        title_label = ttk.Label(
            title_box,
            text="🛡️ ENDPOINT SECURITY MONITOR",
            style="Header.TLabel",
        )
        title_label.pack(anchor=tk.W)

        subtitle_label = ttk.Label(
            title_box,
            text="Passive Telemetry • Process Trees • Controlled Execution Gating • Windows Application Control",
            font=("Segoe UI", 8),
            foreground="#555555",
        )
        subtitle_label.pack(anchor=tk.W)

        # Action Buttons
        btn_box = ttk.Frame(toolbar)
        btn_box.pack(side=tk.RIGHT, padx=5)

        self.btn_start = ttk.Button(btn_box, text="▶ Start", command=self._action_start, width=9)
        self.btn_start.pack(side=tk.LEFT, padx=3)

        self.btn_pause = ttk.Button(btn_box, text="⏸ Pause", command=self._action_pause, width=9)
        self.btn_pause.pack(side=tk.LEFT, padx=3)

        self.btn_stop = ttk.Button(btn_box, text="⏹ Stop", command=self._action_stop, width=9)
        self.btn_stop.pack(side=tk.LEFT, padx=3)

        self.btn_refresh = ttk.Button(btn_box, text="🔄 Refresh", command=self._action_refresh, width=10)
        self.btn_refresh.pack(side=tk.LEFT, padx=3)

        # Auto-refresh checkbox
        chk_refresh = ttk.Checkbutton(btn_box, text="Live Updates", variable=self.auto_refresh_var)
        chk_refresh.pack(side=tk.LEFT, padx=8)

    def _build_notebook_tabs(self) -> None:
        """Create the central tabbed views."""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Tab 1: Overview Dashboard
        self.tab_dashboard = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_dashboard, text=" 📊 Overview Dashboard ")
        self._build_dashboard_tab()

        # Tab 2: Process Explorer
        self.tab_processes = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_processes, text=" 🔍 Process Explorer ")
        self._build_process_tab()

        # Tab 3: Alerts & Event History
        self.tab_alerts = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_alerts, text=" ⚠️ Alerts & Events ")
        self._build_alerts_tab()

        # Tab 4: System Resources
        self.tab_resources = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_resources, text=" 📈 System Resources ")
        self._build_resources_tab()

        # Tab 5: Network & File Activity
        self.tab_activity = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_activity, text=" 🌐 Network & File Activity ")
        self._build_activity_tab()

        # Tab 6: Controlled Execution Console
        self.tab_execution = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_execution, text=" 🔒 Controlled Execution ")
        self._build_execution_tab()

    def _build_status_bar(self) -> None:
        """Bottom operational status line."""
        status_bar = ttk.Frame(self.root, relief="sunken", padding="5 3 5 3")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        status_lbl = ttk.Label(status_bar, textvariable=self.status_text_var, font=("Segoe UI", 9))
        status_lbl.pack(side=tk.LEFT)

        safety_badge = ttk.Label(
            status_bar,
            text="🛡️ Safety Defaults Active: Dry-Run=True | Active Execution=Disabled",
            foreground="#198754",
            font=("Segoe UI", 9, "bold"),
        )
        safety_badge.pack(side=tk.RIGHT)

    # -------------------------------------------------------------------------
    # TAB 1: Main Overview Dashboard
    # -------------------------------------------------------------------------

    def _build_dashboard_tab(self) -> None:
        """Summary cards, quick gauges, and recent alerts."""
        # Top KPI Cards Row
        cards_frame = ttk.Frame(self.tab_dashboard)
        cards_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))

        # Card 1: Observed Processes
        c1 = ttk.LabelFrame(cards_frame, text=" Observed Processes ", padding=10)
        c1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
        self.lbl_card_procs = ttk.Label(c1, text="0", style="StatValue.TLabel", foreground="#0d6efd")
        self.lbl_card_procs.pack()
        ttk.Label(c1, text="Active Monitored PIDs", style="StatLabel.TLabel").pack()

        # Card 2: High Severity Alerts
        c2 = ttk.LabelFrame(cards_frame, text=" Critical Alerts ", padding=10)
        c2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
        self.lbl_card_high_alerts = ttk.Label(c2, text="0", style="StatValue.TLabel", foreground="#dc3545")
        self.lbl_card_high_alerts.pack()
        ttk.Label(c2, text="High Risk & Lineage Anomaly", style="StatLabel.TLabel").pack()

        # Card 3: Medium / Total Alerts
        c3 = ttk.LabelFrame(cards_frame, text=" Total Events ", padding=10)
        c3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
        self.lbl_card_total_events = ttk.Label(c3, text="0", style="StatValue.TLabel", foreground="#fd7e14")
        self.lbl_card_total_events.pack()
        ttk.Label(c3, text="Ingested Security Events", style="StatLabel.TLabel").pack()

        # Card 4: Controlled Execution Gate
        c4 = ttk.LabelFrame(cards_frame, text=" Execution Gate ", padding=10)
        c4.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
        self.lbl_card_gate = ttk.Label(c4, text="DRY-RUN", style="StatValue.TLabel", foreground="#198754")
        self.lbl_card_gate.pack()
        ttk.Label(c4, text="Active Spawn: Blocked", style="StatLabel.TLabel").pack()

        # Middle Split: Resource Gauges & OS Policy Status
        middle_frame = ttk.Frame(self.tab_dashboard)
        middle_frame.pack(side=tk.TOP, fill=tk.X, pady=5)

        # Resource Mini-Gauges Box
        res_box = ttk.LabelFrame(middle_frame, text=" Live Resource Telemetry ", padding=10)
        res_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)

        # CPU Progress Bar
        ttk.Label(res_box, text="CPU Utilization:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.bar_cpu = ttk.Progressbar(res_box, length=200, mode="determinate")
        self.bar_cpu.grid(row=0, column=1, sticky=tk.EW, padx=8, pady=2)
        self.lbl_cpu_val = ttk.Label(res_box, text="0.0%", width=8)
        self.lbl_cpu_val.grid(row=0, column=2, sticky=tk.W)

        # Memory Progress Bar
        ttk.Label(res_box, text="Memory Utilization:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.bar_mem = ttk.Progressbar(res_box, length=200, mode="determinate")
        self.bar_mem.grid(row=1, column=1, sticky=tk.EW, padx=8, pady=2)
        self.lbl_mem_val = ttk.Label(res_box, text="0.0%", width=8)
        self.lbl_mem_val.grid(row=1, column=2, sticky=tk.W)

        # Disk Progress Bar
        ttk.Label(res_box, text="Disk Utilization:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.bar_disk = ttk.Progressbar(res_box, length=200, mode="determinate")
        self.bar_disk.grid(row=2, column=1, sticky=tk.EW, padx=8, pady=2)
        self.lbl_disk_val = ttk.Label(res_box, text="0.0%", width=8)
        self.lbl_disk_val.grid(row=2, column=2, sticky=tk.W)

        res_box.columnconfigure(1, weight=1)

        # OS Policy Integration Status Box
        os_box = ttk.LabelFrame(middle_frame, text=" OS Application Control Status ", padding=10)
        os_box.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=4)

        self.lbl_os_status = ttk.Label(
            os_box,
            text="• WDAC / Code Integrity Event Telemetry: Ready\n• AppLocker Event Telemetry: Ready\n• OS Kernel Enforcement: Static Baseline Policy\n• Dynamic Risk Pre-Execution Interception: Inactive (Requires Kernel Driver)",
            font=("Segoe UI", 9),
            foreground="#333333",
        )
        self.lbl_os_status.pack(anchor=tk.W)

        # Bottom: Recent Critical Alerts Table
        recent_box = ttk.LabelFrame(self.tab_dashboard, text=" Recent Critical Alerts ", padding=8)
        recent_box.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, pady=(5, 0))

        cols = ("time", "severity", "source", "process", "score", "reasons")
        self.tree_recent_alerts = ttk.Treeview(recent_box, columns=cols, show="headings", height=6)
        self.tree_recent_alerts.heading("time", text="Timestamp")
        self.tree_recent_alerts.heading("severity", text="Severity")
        self.tree_recent_alerts.heading("source", text="Source")
        self.tree_recent_alerts.heading("process", text="Target / Process")
        self.tree_recent_alerts.heading("score", text="Score")
        self.tree_recent_alerts.heading("reasons", text="Detection Reasons")

        self.tree_recent_alerts.column("time", width=140, anchor=tk.W)
        self.tree_recent_alerts.column("severity", width=80, anchor=tk.CENTER)
        self.tree_recent_alerts.column("source", width=130, anchor=tk.W)
        self.tree_recent_alerts.column("process", width=150, anchor=tk.W)
        self.tree_recent_alerts.column("score", width=60, anchor=tk.CENTER)
        self.tree_recent_alerts.column("reasons", width=400, anchor=tk.W)

        self.tree_recent_alerts.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(recent_box, orient=tk.VERTICAL, command=self.tree_recent_alerts.yview)
        self.tree_recent_alerts.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    # -------------------------------------------------------------------------
    # TAB 2: Process Explorer
    # -------------------------------------------------------------------------

    def _build_process_tab(self) -> None:
        """Searchable and sortable process hierarchy view."""
        # Filter Bar
        filter_bar = ttk.Frame(self.tab_processes)
        filter_bar.pack(side=tk.TOP, fill=tk.X, pady=(0, 6))

        ttk.Label(filter_bar, text="Search:").pack(side=tk.LEFT, padx=(0, 4))
        ent_search = ttk.Entry(filter_bar, textvariable=self.search_process_var, width=28)
        ent_search.pack(side=tk.LEFT, padx=(0, 10))
        ent_search.bind("<KeyRelease>", lambda e: self._refresh_process_tree())

        ttk.Label(filter_bar, text="Severity:").pack(side=tk.LEFT, padx=(0, 4))
        cb_sev = ttk.Combobox(
            filter_bar,
            textvariable=self.filter_process_sev_var,
            values=["ALL", "HIGH", "MEDIUM", "LOW"],
            state="readonly",
            width=10,
        )
        cb_sev.pack(side=tk.LEFT, padx=(0, 10))
        cb_sev.bind("<<ComboboxSelected>>", lambda e: self._refresh_process_tree())

        btn_clear = ttk.Button(filter_bar, text="Clear Filters", command=self._clear_process_filters)
        btn_clear.pack(side=tk.LEFT, padx=5)

        self.lbl_proc_filter_count = ttk.Label(filter_bar, text="", foreground="#666666")
        self.lbl_proc_filter_count.pack(side=tk.RIGHT)

        # Process Treeview Table
        table_frame = ttk.Frame(self.tab_processes)
        table_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        cols = ("pid", "ppid", "name", "path", "score", "severity", "user", "reasons")
        self.tree_processes = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_processes.heading("pid", text="PID", command=lambda: self._sort_processes_by("pid"))
        self.tree_processes.heading("ppid", text="PPID", command=lambda: self._sort_processes_by("ppid"))
        self.tree_processes.heading("name", text="Process Name", command=lambda: self._sort_processes_by("name"))
        self.tree_processes.heading("path", text="Executable Path (Sanitized)", command=lambda: self._sort_processes_by("path"))
        self.tree_processes.heading("score", text="Score", command=lambda: self._sort_processes_by("risk_score"))
        self.tree_processes.heading("severity", text="Risk Level", command=lambda: self._sort_processes_by("risk_level"))
        self.tree_processes.heading("user", text="User Context", command=lambda: self._sort_processes_by("username"))
        self.tree_processes.heading("reasons", text="Detection Reasons")

        self.tree_processes.column("pid", width=70, anchor=tk.CENTER)
        self.tree_processes.column("ppid", width=70, anchor=tk.CENTER)
        self.tree_processes.column("name", width=140, anchor=tk.W)
        self.tree_processes.column("path", width=260, anchor=tk.W)
        self.tree_processes.column("score", width=60, anchor=tk.CENTER)
        self.tree_processes.column("severity", width=80, anchor=tk.CENTER)
        self.tree_processes.column("user", width=130, anchor=tk.W)
        self.tree_processes.column("reasons", width=280, anchor=tk.W)

        self.tree_processes.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree_processes.yview)
        self.tree_processes.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree_processes.bind("<<TreeviewSelect>>", self._on_process_selected)

        # Process Details Card
        self.proc_detail_box = ttk.LabelFrame(self.tab_processes, text=" Selected Process Details & Lineage ", padding=8)
        self.proc_detail_box.pack(side=tk.BOTTOM, fill=tk.X, pady=(6, 0))

        self.lbl_proc_details = ttk.Label(
            self.proc_detail_box,
            text="Select a process from the table to view lineage, arguments, and threat analysis.",
            font=("Segoe UI", 9),
            wraplength=1050,
        )
        self.lbl_proc_details.pack(anchor=tk.W)

    # -------------------------------------------------------------------------
    # TAB 3: Alerts & Event History
    # -------------------------------------------------------------------------

    def _build_alerts_tab(self) -> None:
        """Central security alerts, audit records, and event browser."""
        filter_bar = ttk.Frame(self.tab_alerts)
        filter_bar.pack(side=tk.TOP, fill=tk.X, pady=(0, 6))

        ttk.Label(filter_bar, text="Search:").pack(side=tk.LEFT, padx=(0, 4))
        ent_search = ttk.Entry(filter_bar, textvariable=self.search_events_var, width=24)
        ent_search.pack(side=tk.LEFT, padx=(0, 10))
        ent_search.bind("<KeyRelease>", lambda e: self._refresh_alerts_tree())

        ttk.Label(filter_bar, text="Source:").pack(side=tk.LEFT, padx=(0, 4))
        cb_source = ttk.Combobox(
            filter_bar,
            textvariable=self.filter_event_source_var,
            values=["ALL", "process_monitor", "network_monitor", "file_monitor", "windows_enforcement", "execution_service"],
            state="readonly",
            width=18,
        )
        cb_source.pack(side=tk.LEFT, padx=(0, 10))
        cb_source.bind("<<ComboboxSelected>>", lambda e: self._refresh_alerts_tree())

        ttk.Label(filter_bar, text="Severity:").pack(side=tk.LEFT, padx=(0, 4))
        cb_sev = ttk.Combobox(
            filter_bar,
            textvariable=self.filter_event_sev_var,
            values=["ALL", "HIGH", "MEDIUM", "LOW"],
            state="readonly",
            width=10,
        )
        cb_sev.pack(side=tk.LEFT, padx=(0, 10))
        cb_sev.bind("<<ComboboxSelected>>", lambda e: self._refresh_alerts_tree())

        btn_clear = ttk.Button(filter_bar, text="Clear Filters", command=self._clear_event_filters)
        btn_clear.pack(side=tk.LEFT, padx=5)

        # Alerts Table
        table_frame = ttk.Frame(self.tab_alerts)
        table_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        cols = ("time", "severity", "source", "type", "target", "score", "reasons")
        self.tree_alerts = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.tree_alerts.heading("time", text="Timestamp")
        self.tree_alerts.heading("severity", text="Severity")
        self.tree_alerts.heading("source", text="Source Module")
        self.tree_alerts.heading("type", text="Event Category")
        self.tree_alerts.heading("target", text="Target / PID")
        self.tree_alerts.heading("score", text="Score")
        self.tree_alerts.heading("reasons", text="Detection & Policy Reasons")

        self.tree_alerts.column("time", width=140, anchor=tk.W)
        self.tree_alerts.column("severity", width=80, anchor=tk.CENTER)
        self.tree_alerts.column("source", width=140, anchor=tk.W)
        self.tree_alerts.column("type", width=160, anchor=tk.W)
        self.tree_alerts.column("target", width=150, anchor=tk.W)
        self.tree_alerts.column("score", width=60, anchor=tk.CENTER)
        self.tree_alerts.column("reasons", width=360, anchor=tk.W)

        self.tree_alerts.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree_alerts.yview)
        self.tree_alerts.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree_alerts.bind("<<TreeviewSelect>>", self._on_alert_selected)

        # Event Detail Inspector
        inspect_frame = ttk.LabelFrame(self.tab_alerts, text=" Event Inspector & Raw Metadata ", padding=8)
        inspect_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(6, 0))

        self.txt_alert_inspector = tk.Text(inspect_frame, height=5, font=("Consolas", 9), wrap=tk.WORD)
        self.txt_alert_inspector.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        txt_sb = ttk.Scrollbar(inspect_frame, orient=tk.VERTICAL, command=self.txt_alert_inspector.yview)
        self.txt_alert_inspector.configure(yscrollcommand=txt_sb.set)
        txt_sb.pack(side=tk.RIGHT, fill=tk.Y)

    # -------------------------------------------------------------------------
    # TAB 4: System Resources
    # -------------------------------------------------------------------------

    def _build_resources_tab(self) -> None:
        """Detailed resource health, threshold violations, and swap metrics."""
        grid_frame = ttk.Frame(self.tab_resources, padding=10)
        grid_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # CPU Group
        cpu_grp = ttk.LabelFrame(grid_frame, text=" CPU Subsystem ", padding=12)
        cpu_grp.grid(row=0, column=0, sticky=tk.NSEW, padx=6, pady=6)
        self.lbl_res_cpu_detailed = ttk.Label(cpu_grp, text="Checking CPU...", font=("Segoe UI", 10))
        self.lbl_res_cpu_detailed.pack(anchor=tk.W)

        # Memory Group
        mem_grp = ttk.LabelFrame(grid_frame, text=" Memory (RAM) Subsystem ", padding=12)
        mem_grp.grid(row=0, column=1, sticky=tk.NSEW, padx=6, pady=6)
        self.lbl_res_mem_detailed = ttk.Label(mem_grp, text="Checking Memory...", font=("Segoe UI", 10))
        self.lbl_res_mem_detailed.pack(anchor=tk.W)

        # Disk Group
        disk_grp = ttk.LabelFrame(grid_frame, text=" Storage / Disk Subsystem ", padding=12)
        disk_grp.grid(row=1, column=0, sticky=tk.NSEW, padx=6, pady=6)
        self.lbl_res_disk_detailed = ttk.Label(disk_grp, text="Checking Disk...", font=("Segoe UI", 10))
        self.lbl_res_disk_detailed.pack(anchor=tk.W)

        # Swap / Pagefile Group
        swap_grp = ttk.LabelFrame(grid_frame, text=" Swap / Virtual Memory ", padding=12)
        swap_grp.grid(row=1, column=1, sticky=tk.NSEW, padx=6, pady=6)
        self.lbl_res_swap_detailed = ttk.Label(swap_grp, text="Checking Swap...", font=("Segoe UI", 10))
        self.lbl_res_swap_detailed.pack(anchor=tk.W)

        grid_frame.columnconfigure(0, weight=1)
        grid_frame.columnconfigure(1, weight=1)
        grid_frame.rowconfigure(0, weight=1)
        grid_frame.rowconfigure(1, weight=1)

    # -------------------------------------------------------------------------
    # TAB 5: Network & File Activity
    # -------------------------------------------------------------------------

    def _build_activity_tab(self) -> None:
        """Split view displaying real-time network sockets and file modifications."""
        # Top half: Network Activity
        net_frame = ttk.LabelFrame(self.tab_activity, text=" Network Socket Telemetry ", padding=6)
        net_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=(0, 6))

        cols = ("time", "pid", "proc", "proto", "local", "remote", "status")
        self.tree_network = ttk.Treeview(net_frame, columns=cols, show="headings", height=8)
        self.tree_network.heading("time", text="Timestamp")
        self.tree_network.heading("pid", text="PID")
        self.tree_network.heading("proc", text="Process")
        self.tree_network.heading("proto", text="Proto")
        self.tree_network.heading("local", text="Local Socket")
        self.tree_network.heading("remote", text="Remote Endpoint")
        self.tree_network.heading("status", text="Port Assessment")

        self.tree_network.column("time", width=140, anchor=tk.W)
        self.tree_network.column("pid", width=65, anchor=tk.CENTER)
        self.tree_network.column("proc", width=130, anchor=tk.W)
        self.tree_network.column("proto", width=60, anchor=tk.CENTER)
        self.tree_network.column("local", width=180, anchor=tk.W)
        self.tree_network.column("remote", width=180, anchor=tk.W)
        self.tree_network.column("status", width=130, anchor=tk.CENTER)

        self.tree_network.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_net = ttk.Scrollbar(net_frame, orient=tk.VERTICAL, command=self.tree_network.yview)
        self.tree_network.configure(yscrollcommand=sb_net.set)
        sb_net.pack(side=tk.RIGHT, fill=tk.Y)

        # Bottom half: File Activity
        file_frame = ttk.LabelFrame(self.tab_activity, text=" File System Modifications (Monitored Folder) ", padding=6)
        file_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        f_cols = ("time", "action", "path", "dest", "sev")
        self.tree_files = ttk.Treeview(file_frame, columns=f_cols, show="headings", height=8)
        self.tree_files.heading("time", text="Timestamp")
        self.tree_files.heading("action", text="Action")
        self.tree_files.heading("path", text="Source Path")
        self.tree_files.heading("dest", text="Destination Path")
        self.tree_files.heading("sev", text="Severity")

        self.tree_files.column("time", width=140, anchor=tk.W)
        self.tree_files.column("action", width=90, anchor=tk.CENTER)
        self.tree_files.column("path", width=350, anchor=tk.W)
        self.tree_files.column("dest", width=250, anchor=tk.W)
        self.tree_files.column("sev", width=80, anchor=tk.CENTER)

        self.tree_files.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_file = ttk.Scrollbar(file_frame, orient=tk.VERTICAL, command=self.tree_files.yview)
        self.tree_files.configure(yscrollcommand=sb_file.set)
        sb_file.pack(side=tk.RIGHT, fill=tk.Y)

    # -------------------------------------------------------------------------
    # TAB 6: Controlled Execution Console
    # -------------------------------------------------------------------------

    def _build_execution_tab(self) -> None:
        """Interactive test harness for ControlledExecutionService evaluation."""
        # Top: Request Input Form
        input_frame = ttk.LabelFrame(self.tab_execution, text=" Submit Execution Request (Pre-Launch Risk Evaluation) ", padding=10)
        input_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 8))

        row1 = ttk.Frame(input_frame)
        row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="Executable:", width=14).pack(side=tk.LEFT)
        self.ent_exec_target = ttk.Entry(row1, width=45)
        self.ent_exec_target.insert(0, "powershell.exe")
        self.ent_exec_target.pack(side=tk.LEFT, padx=5)

        ttk.Label(row1, text="Parent PID:", width=12).pack(side=tk.LEFT, padx=(10, 0))
        self.ent_exec_ppid = ttk.Entry(row1, width=10)
        self.ent_exec_ppid.insert(0, str(os.getpid()))
        self.ent_exec_ppid.pack(side=tk.LEFT, padx=5)

        row2 = ttk.Frame(input_frame)
        row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="Arguments:", width=14).pack(side=tk.LEFT)
        self.ent_exec_args = ttk.Entry(row2, width=65)
        self.ent_exec_args.insert(0, "-NoProfile -Command whoami")
        self.ent_exec_args.pack(side=tk.LEFT, padx=5)

        btn_eval = ttk.Button(row2, text="🛡️ Evaluate Policy", command=self._action_evaluate_request)
        btn_eval.pack(side=tk.LEFT, padx=10)

        # Evaluated Decision Card
        self.exec_decision_card = ttk.LabelFrame(self.tab_execution, text=" Policy Gate Decision ", padding=10)
        self.exec_decision_card.pack(side=tk.TOP, fill=tk.X, pady=4)

        self.lbl_exec_decision_res = ttk.Label(
            self.exec_decision_card,
            text="No execution request submitted yet. Enter parameters above and click 'Evaluate Policy'.",
            font=("Segoe UI", 9),
            wraplength=1050,
        )
        self.lbl_exec_decision_res.pack(anchor=tk.W)

        # Bottom: Historical Execution Records Table
        hist_frame = ttk.LabelFrame(self.tab_execution, text=" Recent Controlled Execution Requests ", padding=8)
        hist_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, pady=(6, 0))

        cols = ("req_id", "target", "decision", "status", "score", "reasons")
        self.tree_exec_history = ttk.Treeview(hist_frame, columns=cols, show="headings", height=8)
        self.tree_exec_history.heading("req_id", text="Request ID")
        self.tree_exec_history.heading("target", text="Target Executable")
        self.tree_exec_history.heading("decision", text="Policy Decision")
        self.tree_exec_history.heading("status", text="Outcome Status")
        self.tree_exec_history.heading("score", text="Score")
        self.tree_exec_history.heading("reasons", text="Evaluation Reasons")

        self.tree_exec_history.column("req_id", width=160, anchor=tk.W)
        self.tree_exec_history.column("target", width=180, anchor=tk.W)
        self.tree_exec_history.column("decision", width=110, anchor=tk.CENTER)
        self.tree_exec_history.column("status", width=110, anchor=tk.CENTER)
        self.tree_exec_history.column("score", width=60, anchor=tk.CENTER)
        self.tree_exec_history.column("reasons", width=380, anchor=tk.W)

        self.tree_exec_history.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb_ex = ttk.Scrollbar(hist_frame, orient=tk.VERTICAL, command=self.tree_exec_history.yview)
        self.tree_exec_history.configure(yscrollcommand=sb_ex.set)
        sb_ex.pack(side=tk.RIGHT, fill=tk.Y)

    # -------------------------------------------------------------------------
    # UI Polling and Refresh Logic
    # -------------------------------------------------------------------------

    def _ui_poll_cycle(self) -> None:
        """Periodic UI update triggered by root.after."""
        if self.auto_refresh_var.get() and self.engine.is_running():
            self._update_all_views()

        # Schedule next poll cycle in 1000ms
        self.root.after(1000, self._ui_poll_cycle)

    def _update_all_views(self) -> None:
        """Fetch engine snapshots and refresh UI components."""
        snap = self.engine.get_state_snapshot()

        # 1. Update Header Buttons and Status Line
        curr_status = snap["status"]
        self.status_text_var.set(
            f"Engine: {curr_status} | Observed PIDs: {snap['process_count']} | "
            f"High Alerts: {snap['alert_counts']['HIGH']} | Updated: {time.strftime('%H:%M:%S')}"
        )

        # 2. Update Dashboard Overview Cards
        self.lbl_card_procs.config(text=str(snap["process_count"]))
        self.lbl_card_high_alerts.config(text=str(snap["alert_counts"]["HIGH"]))
        self.lbl_card_total_events.config(text=str(snap["alert_counts"]["TOTAL"]))

        ce_info = snap["controlled_execution"]
        if ce_info.get("dry_run"):
            self.lbl_card_gate.config(text="DRY-RUN", foreground="#198754")
        else:
            self.lbl_card_gate.config(text="ACTIVE", foreground="#dc3545")

        # 3. Update Resource Progress Bars
        res = snap.get("latest_resources", {})
        cpu_val = res.get("cpu", {}).get("percent", 0.0)
        mem_val = res.get("memory", {}).get("percent", 0.0)
        disk_val = res.get("disk", {}).get("percent", 0.0)

        self.bar_cpu["value"] = cpu_val
        self.lbl_cpu_val.config(text=format_percent(cpu_val))

        self.bar_mem["value"] = mem_val
        self.lbl_mem_val.config(text=format_percent(mem_val))

        self.bar_disk["value"] = disk_val
        self.lbl_disk_val.config(text=format_percent(disk_val))

        # 4. Update Tab Views based on which tab is selected
        selected_tab = self.notebook.tab(self.notebook.select(), "text").strip()
        if "Overview" in selected_tab:
            self._refresh_recent_alerts_table()
        elif "Process" in selected_tab:
            self._refresh_process_tree()
        elif "Alerts" in selected_tab:
            self._refresh_alerts_tree()
        elif "Resources" in selected_tab:
            self._refresh_resources_detailed(res)
        elif "Network" in selected_tab:
            self._refresh_activity_tables()
        elif "Controlled" in selected_tab:
            self._refresh_execution_history_table()

    def _refresh_recent_alerts_table(self) -> None:
        """Populate recent alerts on overview tab."""
        alerts = self.engine.get_alerts_snapshot()[-6:]
        self.tree_recent_alerts.delete(*self.tree_recent_alerts.get_children())
        for a in reversed(alerts):
            time_str = format_timestamp(a.timestamp)
            target = a.process_name or a.file_path or "N/A"
            reasons = "; ".join(a.risk_reasons) if a.risk_reasons else "None"
            self.tree_recent_alerts.insert(
                "",
                tk.END,
                values=(time_str, a.severity, a.source, target, a.risk_score, reasons),
            )

    def _refresh_process_tree(self) -> None:
        """Filter, sort, and render process explorer tree."""
        procs = self.engine.get_processes_snapshot()
        proc_events = self.engine.get_process_events_snapshot()
        query = self.search_process_var.get()
        sev_filter = self.filter_process_sev_var.get()

        rows = filter_and_sort_processes(
            processes=procs,
            process_events=proc_events,
            search_query=query,
            severity_filter=sev_filter,
            sort_column="risk_score",
            reverse=True,
        )

        self.tree_processes.delete(*self.tree_processes.get_children())
        for r in rows:
            self.tree_processes.insert(
                "",
                tk.END,
                values=(
                    r["pid"],
                    r["ppid"],
                    r["name"],
                    r["path"],
                    r["risk_score"],
                    r["risk_level"],
                    r["username"],
                    r["reasons_str"],
                ),
            )

        self.lbl_proc_filter_count.config(text=f"Showing {len(rows)} of {len(procs)} processes")

    def _refresh_alerts_tree(self) -> None:
        """Filter, sort, and render alerts and events tab."""
        events = self.engine.get_events_snapshot()
        query = self.search_events_var.get()
        src_filter = self.filter_event_source_var.get()
        sev_filter = self.filter_event_sev_var.get()

        rows = filter_and_sort_events(
            events=events,
            search_query=query,
            source_filter=src_filter,
            severity_filter=sev_filter,
            sort_column="timestamp",
            reverse=True,
        )

        self.tree_alerts.delete(*self.tree_alerts.get_children())
        for r in rows[:200]:  # Cap rendering at 200 rows for smoothness
            self.tree_alerts.insert(
                "",
                tk.END,
                values=(
                    r["time_str"],
                    r["severity"],
                    r["source"],
                    r["event_type"],
                    r["proc_info_str"],
                    r["risk_score"],
                    r["reasons_str"],
                ),
            )

    def _refresh_resources_detailed(self, res: Dict[str, Any]) -> None:
        """Render detailed resource subsystem statistics."""
        if not res:
            return

        cpu = res.get("cpu", {})
        mem = res.get("memory", {})
        disk = res.get("disk", {})
        swap = res.get("swap", {})

        cpu_text = (
            f"• Utilization: {format_percent(cpu.get('percent'))}\n"
            f"• Logic Cores: {os.cpu_count() or 'N/A'}\n"
            f"• High Usage Threshold: {cpu.get('high_threshold', 90.0)}%\n"
            f"• Anomaly Status: {'ELEVATED' if cpu.get('percent', 0) > 70 else 'NORMAL'}"
        )
        self.lbl_res_cpu_detailed.config(text=cpu_text)

        mem_text = (
            f"• Utilization: {format_percent(mem.get('percent'))}\n"
            f"• Used / Total: {mem.get('formatted', 'N/A')}\n"
            f"• Available RAM: {format_bytes(mem.get('available'))}\n"
            f"• High Usage Threshold: {mem.get('high_threshold', 90.0)}%"
        )
        self.lbl_res_mem_detailed.config(text=mem_text)

        disk_text = (
            f"• Utilization: {format_percent(disk.get('percent'))}\n"
            f"• Used / Total: {disk.get('formatted', 'N/A')}\n"
            f"• Mount Point: {disk.get('mount_point', 'Default')}\n"
            f"• Free Space: {format_bytes(disk.get('free'))}"
        )
        self.lbl_res_disk_detailed.config(text=disk_text)

        swap_text = (
            f"• Utilization: {format_percent(swap.get('percent'))}\n"
            f"• Used / Total: {swap.get('formatted', 'N/A')}\n"
            f"• Free Virtual Memory: {format_bytes(swap.get('free'))}"
        )
        self.lbl_res_swap_detailed.config(text=swap_text)

    def _refresh_activity_tables(self) -> None:
        """Render network connections and file activity."""
        net_events = self.engine.get_network_events_snapshot()
        self.tree_network.delete(*self.tree_network.get_children())
        for ne in net_events[-40:]:
            r = adapt_network_event_row(ne)
            self.tree_network.insert(
                "",
                tk.END,
                values=(
                    r["time_str"],
                    r["pid"],
                    r["process_name"],
                    r["protocol"],
                    r["local_address"],
                    r["remote_address"],
                    r["status"],
                ),
            )

        file_events = self.engine.get_file_events_snapshot()
        self.tree_files.delete(*self.tree_files.get_children())
        for fe in file_events[-40:]:
            r = adapt_file_event_row(fe)
            self.tree_files.insert(
                "",
                tk.END,
                values=(r["time_str"], r["action"], r["file_path"], r["dest_path"], r["severity"]),
            )

    def _refresh_execution_history_table(self) -> None:
        """Render controlled execution submission history."""
        records = self.engine.get_execution_records_snapshot()
        self.tree_exec_history.delete(*self.tree_exec_history.get_children())
        for rec in reversed(records[-40:]):
            reasons_str = "; ".join(rec.get("reasons", [])) if rec.get("reasons") else "None"
            self.tree_exec_history.insert(
                "",
                tk.END,
                values=(
                    rec.get("request_id"),
                    rec.get("executable"),
                    rec.get("decision"),
                    rec.get("status"),
                    rec.get("risk_score"),
                    reasons_str,
                ),
            )

    # -------------------------------------------------------------------------
    # Event Handlers & User Actions
    # -------------------------------------------------------------------------

    def _action_start(self) -> None:
        self.engine.start()
        self._update_all_views()

    def _action_pause(self) -> None:
        if self.engine.is_paused():
            self.engine.resume()
            self.btn_pause.config(text="⏸ Pause")
        else:
            self.engine.pause()
            self.btn_pause.config(text="▶ Resume")
        self._update_all_views()

    def _action_stop(self) -> None:
        self.engine.stop()
        self._update_all_views()

    def _action_refresh(self) -> None:
        self.engine.refresh_once()
        self._update_all_views()

    def _clear_process_filters(self) -> None:
        self.search_process_var.set("")
        self.filter_process_sev_var.set("ALL")
        self._refresh_process_tree()

    def _clear_event_filters(self) -> None:
        self.search_events_var.set("")
        self.filter_event_source_var.set("ALL")
        self.filter_event_sev_var.set("ALL")
        self._refresh_alerts_tree()

    def _sort_processes_by(self, col: str) -> None:
        # Sorting toggle can be implemented here
        self._refresh_process_tree()

    def _on_process_selected(self, event: Any) -> None:
        selected = self.tree_processes.selection()
        if not selected:
            return
        item = self.tree_processes.item(selected[0])
        pid = item["values"][0]

        procs = self.engine.get_processes_snapshot()
        proc_events = self.engine.get_process_events_snapshot()

        proc_info = procs.get(int(pid), {})
        evt = proc_events.get(int(pid))

        cmdline = proc_info.get("cmdline") or []
        cmdline_str = " ".join(redact_command_line(cmdline)) if cmdline else "N/A"
        lineage = "Direct spawn"
        if evt:
            tree_meta = evt.metadata.get("process_tree", {})
            if tree_meta.get("lineage"):
                lineage = " -> ".join(tree_meta["lineage"])

        details = (
            f"PID: {pid} | PPID: {proc_info.get('ppid')} | Name: '{proc_info.get('name')}' | "
            f"User: {proc_info.get('username')}\n"
            f"Lineage: {lineage}\n"
            f"Command Line: {cmdline_str}\n"
            f"Risk Assessment: Level={evt.risk_level if evt else 'LOW'} | Score={evt.risk_score if evt else 0} | "
            f"Reasons: {'; '.join(evt.risk_reasons) if evt and evt.risk_reasons else 'Normal activity'}"
        )
        self.lbl_proc_details.config(text=details)

    def _on_alert_selected(self, event: Any) -> None:
        selected = self.tree_alerts.selection()
        if not selected:
            return
        item = self.tree_alerts.item(selected[0])
        time_val = item["values"][0]
        target_val = item["values"][4]

        events = self.engine.get_events_snapshot()
        for evt in events:
            if format_timestamp(evt.timestamp) == time_val:
                self.txt_alert_inspector.delete("1.0", tk.END)
                try:
                    payload = json.dumps(evt.to_dict(), indent=2)
                except Exception:
                    payload = str(evt)
                self.txt_alert_inspector.insert(tk.END, payload)
                break

    def _action_evaluate_request(self) -> None:
        """Submit interactive ExecutionRequest through the execution service."""
        target = self.ent_exec_target.get().strip()
        args_raw = self.ent_exec_args.get().strip()
        ppid_str = self.ent_exec_ppid.get().strip()

        if not target:
            messagebox.showwarning("Input Error", "Executable target path is required.")
            return

        cmdline = [target]
        if args_raw:
            cmdline.extend(args_raw.split())

        ppid_val = 0
        if ppid_str.isdigit():
            ppid_val = int(ppid_str)

        req = ExecutionRequest(
            executable=target,
            command_line=cmdline,
            parent_pid=ppid_val,
        )

        result = self.engine.submit_execution_request(req)
        dec = result.decision

        dec_text = (
            f"Decision: {dec.decision if dec else 'REJECTED'} | "
            f"Status: {result.status} | "
            f"Risk Score: {dec.risk_score if dec else 'N/A'} ({dec.risk_level if dec else 'N/A'})\n"
            f"Executed: {result.executed} (Dry-Run Safety Active)\n"
            f"Policy Reasons: {'; '.join(dec.reasons) if dec and dec.reasons else 'Approved by policy'}\n"
            f"Error / Gate Note: {result.error or 'None'}"
        )
        self.lbl_exec_decision_res.config(text=dec_text)
        self._refresh_execution_history_table()

    def on_close(self) -> None:
        """Clean shutdown handler."""
        try:
            self.engine.stop()
        except Exception as e:
            logger.debug(f"Error stopping engine during UI close: {e}")
        finally:
            self.root.destroy()

    def run(self) -> None:
        """Start the Tkinter event loop."""
        self.root.mainloop()

