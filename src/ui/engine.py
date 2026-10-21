"""
Monitoring Engine Module (Phase 5).

Provides a thread-safe, non-blocking monitoring controller that coordinates
background process, resource, network, file, and Windows enforcement monitoring.
Aggregates telemetry and dispatches normalized events to UI presentation layers.
"""

from collections import deque
from dataclasses import asdict
import logging
import os
import queue
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

from watchdog.observers import Observer

from src.analysis.process_tree import ProcessTree, ProcessTreeAnalyzer
from src.baseline.baseline_engine import BaselineEngine
from src.detectors.command_detector import detect_command_indicators
from src.detectors.risk_detector import calculate_risk
from src.execution.config import load_execution_config
from src.execution.service import (
    ControlledExecutionService,
    ExecutionServiceResult,
    redact_command_line,
    redact_string,
)
from src.execution.windows_enforcement import (
    WindowsEnforcementCollector,
    WindowsEnforcementCorrelator,
)
from src.models.event import Event
from src.models.execution_request import ExecutionRequest
from src.monitors.file_monitor import FileMonitor
from src.monitors.login_monitor import LoginMonitor
from src.monitors.network_monitor import NetworkMonitor
from src.monitors.process_monitor import get_new_processes, get_running_processes
from src.monitors.resource_monitor import ResourceMonitor


logger = logging.getLogger("endpoint_monitor")


class MonitoringEngineStatus:
    """Status enumeration for the background monitoring lifecycle."""
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPING = "STOPPING"
    ERROR = "ERROR"


class MonitoringEngine:
    """
    Central controller orchestrating all background monitoring subsystems.
    Safely coordinates collection loops on worker threads and exposes bounded,
    thread-safe telemetry snapshots for UI presentation without blocking.
    """

    def __init__(
        self,
        config_path: str = "config/config.json",
        poll_interval: float = 3.0,
        max_events_capacity: int = 1000,
        max_alerts_capacity: int = 500,
        max_queue_size: int = 500,
    ) -> None:
        self.config_path = config_path
        self.poll_interval = max(1.0, float(poll_interval))
        self.max_events_capacity = max(1, max_events_capacity)
        self.max_alerts_capacity = max(1, max_alerts_capacity)

        # Thread synchronization primitives
        self._lock = threading.RLock()
        self._status = MonitoringEngineStatus.STOPPED
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._file_observer: Optional[Observer] = None

        # Real-time event communication queue (for UI subscribers)
        self.event_queue: queue.Queue[Event] = queue.Queue(maxsize=max_queue_size)

        # Telemetry data stores
        self._processes: Dict[int, Dict[str, Any]] = {}
        self._process_events: Dict[int, Event] = {}
        self._alerts: Deque[Event] = deque(maxlen=self.max_alerts_capacity)
        self._events: Deque[Event] = deque(maxlen=self.max_events_capacity)
        self._network_events: Deque[Event] = deque(maxlen=self.max_events_capacity)
        self._file_events: Deque[Event] = deque(maxlen=self.max_events_capacity)
        self._windows_events: Deque[Event] = deque(maxlen=self.max_events_capacity)
        self._login_events: Deque[Event] = deque(maxlen=self.max_events_capacity)
        self._execution_records: Deque[Dict[str, Any]] = deque(maxlen=200)
        self._resource_history: Deque[Dict[str, Any]] = deque(maxlen=100)
        self._latest_resources: Dict[str, Any] = {}
        self._errors: Deque[str] = deque(maxlen=50)

        # Subsystem engines
        self.config = load_execution_config(self.config_path)
        self.tree_analyzer = ProcessTreeAnalyzer()
        self.baseline_engine = BaselineEngine()
        self.resource_monitor = ResourceMonitor(logger=logger)
        self.network_monitor = NetworkMonitor(logger=logger)
        self.login_monitor = LoginMonitor(logger=logger)
        self.execution_service = ControlledExecutionService(config=self.config)

        # Windows OS Application Control Telemetry
        we_cfg = self.config.get("windows_enforcement", {})
        self.windows_collector = WindowsEnforcementCollector(
            channels=we_cfg.get("channels"),
            max_events_per_query=we_cfg.get("max_events_per_query", 50),
        )
        self.windows_correlator = WindowsEnforcementCorrelator(
            alert_on_blocks=we_cfg.get("alert_on_blocks", True),
            alert_callback=self._handle_alert_emission,
        )

    # -------------------------------------------------------------------------
    # Lifecycle Management
    # -------------------------------------------------------------------------

    @property
    def status(self) -> str:
        """Get current engine lifecycle status."""
        with self._lock:
            return self._status

    def is_running(self) -> bool:
        """Check if background monitoring is active."""
        with self._lock:
            return self._status in (MonitoringEngineStatus.RUNNING, MonitoringEngineStatus.PAUSED)

    def is_paused(self) -> bool:
        """Check if monitoring is temporarily paused."""
        with self._lock:
            return self._status == MonitoringEngineStatus.PAUSED

    def start(self) -> bool:
        """
        Start the background monitoring worker thread and file observer.
        Guarantees idempotency: returns True immediately if already running.
        """
        with self._lock:
            if self.is_running():
                return True

            self._status = MonitoringEngineStatus.STARTING
            self._stop_event.clear()
            self._pause_event.clear()

            # Start background monitoring loop
            self._worker_thread = threading.Thread(
                target=self._monitoring_loop,
                name="EndpointMonitorWorker",
                daemon=True,
            )
            self._worker_thread.start()

            # Start file monitoring observer if folder exists
            try:
                monitored_folder = "monitored_folder"
                os.makedirs(monitored_folder, exist_ok=True)
                file_handler = _EngineFileEventHandler(self._handle_file_event)
                self._file_observer = Observer()
                self._file_observer.schedule(file_handler, monitored_folder, recursive=True)
                self._file_observer.start()
            except Exception as e:
                self._record_error(f"Failed to start file observer: {e}")

            self._status = MonitoringEngineStatus.RUNNING
            logger.info("MonitoringEngine started.")
            return True

    def stop(self, timeout: float = 1.0) -> bool:
        """
        Signal background workers to stop and wait for clean termination.
        Guarantees clean resource release without hanging.
        """
        with self._lock:
            if not self.is_running() and self._status == MonitoringEngineStatus.STOPPED:
                return True

            self._status = MonitoringEngineStatus.STOPPING
            self._stop_event.set()
            self._pause_event.set()

        # Join worker thread without holding lock
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=min(timeout, 0.2))

        # Stop file system observer
        if self._file_observer and self._file_observer.is_alive():
            try:
                self._file_observer.stop()
                self._file_observer.join(timeout=0.1)
            except Exception as e:
                logger.debug(f"Error stopping file observer: {e}")
            finally:
                self._file_observer = None

        with self._lock:
            self._status = MonitoringEngineStatus.STOPPED
            self._worker_thread = None

        # Save baseline profiles on shutdown
        try:
            self.baseline_engine.save_baseline()
        except Exception as e:
            logger.debug(f"Error saving baseline on shutdown: {e}")

        logger.info("MonitoringEngine stopped cleanly.")
        return True

    def pause(self) -> None:
        """Pause monitoring cycles without terminating worker threads."""
        with self._lock:
            if self._status == MonitoringEngineStatus.RUNNING:
                self._status = MonitoringEngineStatus.PAUSED
                self._pause_event.set()
                logger.info("MonitoringEngine paused.")

    def resume(self) -> None:
        """Resume active monitoring cycles."""
        with self._lock:
            if self._status == MonitoringEngineStatus.PAUSED:
                self._status = MonitoringEngineStatus.RUNNING
                self._pause_event.clear()
                logger.info("MonitoringEngine resumed.")

    # -------------------------------------------------------------------------
    # Background Worker Loop
    # -------------------------------------------------------------------------

    def _monitoring_loop(self) -> None:
        """Continuous background execution cycle."""
        # Initial snapshot
        self.refresh_once()

        while not self._stop_event.is_set():
            # Wait for next cycle or stop signal
            if self._stop_event.wait(timeout=self.poll_interval):
                break

            # Handle pause state
            if self._pause_event.is_set():
                time.sleep(0.5)
                continue

            try:
                self._cycle_execution()
            except Exception as e:
                self._record_error(f"Error in monitoring cycle: {e}")
                time.sleep(1.0)

    def refresh_once(self) -> None:
        """Execute a single synchronized monitoring evaluation cycle."""
        try:
            self._cycle_execution()
        except Exception as e:
            self._record_error(f"Error during refresh_once: {e}")

    def _cycle_execution(self) -> None:
        """Single full cycle across all active monitoring domains."""
        # 1. System Resource Monitoring
        try:
            res_result = self.resource_monitor.check_resources()
            with self._lock:
                self._latest_resources = res_result.get("metrics", {})
                self._resource_history.append(
                    {
                        "timestamp": time.time(),
                        "metrics": self._latest_resources,
                        "status": res_result.get("status"),
                    }
                )
        except Exception as e:
            self._record_error(f"Resource monitor check failed: {e}")

        # 2. Process Monitoring & Process Tree Analysis
        try:
            current_processes = get_running_processes()
            with self._lock:
                prev_processes = dict(self._processes)
                self._processes = current_processes

            new_processes = get_new_processes(prev_processes, current_processes)
            process_tree = ProcessTree.build(current_processes)

            # Evaluate each newly detected process (or all on initial cycle)
            targets = new_processes if prev_processes else list(current_processes.values())

            for proc in targets:
                event = self._evaluate_process_event(proc, current_processes, process_tree)
                self._ingest_event(event)

        except Exception as e:
            self._record_error(f"Process monitoring cycle failed: {e}")
            current_processes = {}
            process_tree = None

        # 3. Network Monitoring Check
        try:
            net_result = self.network_monitor.check_connections(
                processes=current_processes,
                process_tree=process_tree,
                new_only=bool(prev_processes),
            )
            for net_event in net_result.get("suspicious_events", []):
                self._ingest_event(net_event)
                with self._lock:
                    self._network_events.append(net_event)
        except Exception as e:
            self._record_error(f"Network monitor cycle failed: {e}")

        # 4. Windows OS Enforcement Telemetry Check (if enabled)
        we_cfg = self.config.get("windows_enforcement", {})
        if we_cfg.get("enabled", False):
            try:
                win_records = self.windows_collector.query_live_events()
                if win_records:
                    win_events = self.windows_correlator.correlate_records(
                        win_records, running_processes=current_processes
                    )
                    for w_evt in win_events:
                        self._ingest_event(w_evt)
                        with self._lock:
                            self._windows_events.append(w_evt)
            except Exception as e:
                self._record_error(f"Windows enforcement telemetry check failed: {e}")

        # 5. User Logon & Session Monitoring Check
        try:
            logon_events = self.login_monitor.check_logon_events()
            for l_evt in logon_events:
                self._ingest_event(l_evt)
                with self._lock:
                    self._login_events.append(l_evt)
        except Exception as e:
            self._record_error(f"User logon monitor cycle failed: {e}")

    def _evaluate_process_event(
        self,
        process_info: Dict[str, Any],
        process_map: Dict[int, Dict[str, Any]],
        process_tree: Optional[ProcessTree],
    ) -> Event:
        """Construct standard Event, evaluate command indicators, tree lineage, and risk."""
        event = Event.from_process_info(process_info)
        cmdline = event.command_line

        # Command indicator analysis
        event.indicators = detect_command_indicators(cmdline)

        # Process tree analysis
        tree_analysis = self.tree_analyzer.analyze_process(process_info, process_tree)
        event.metadata["process_tree"] = tree_analysis

        for ind in tree_analysis.get("indicators", []):
            if ind not in event.indicators:
                event.indicators.append(ind)

        # Calculate combined risk
        risk_result = calculate_risk(
            event.indicators,
            process_info,
            tree_findings=tree_analysis.get("findings"),
        )
        event.risk_score = risk_result["score"]
        event.risk_level = risk_result["level"]
        event.risk_reasons = risk_result["reasons"]
        event.severity = risk_result["level"]

        # Behavioral baseline check
        try:
            anomaly_result = self.baseline_engine.analyze_event(event)
            event.metadata["baseline_anomaly"] = anomaly_result
            self.baseline_engine.collect_event(event)
            if anomaly_result.get("is_anomaly"):
                for reason in anomaly_result.get("reasons", []):
                    if reason not in event.risk_reasons:
                        event.risk_reasons.append(reason)
        except Exception as e:
            logger.debug(f"Baseline engine error on PID {event.pid}: {e}")

        # Track evaluated event for process
        if event.pid is not None:
            with self._lock:
                self._process_events[event.pid] = event

        return event

    # -------------------------------------------------------------------------
    # Ingestion and Alert Handlers
    # -------------------------------------------------------------------------

    def _ingest_event(self, event: Event) -> None:
        """Store event in bounded queues and notify UI subscribers."""
        with self._lock:
            self._events.append(event)
            if event.severity in ("HIGH", "MEDIUM") or event.indicators:
                self._alerts.append(event)

        # Dispatch non-blockingly to queue
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            pass  # Avoid queue backpressure blocking worker

    def _handle_alert_emission(self, alert_text: str) -> None:
        """Callback for external alerts (e.g. from windows_enforcement)."""
        logger.warning(f"[ENGINE ALERT] {alert_text}")

    def _handle_file_event(self, event: Event) -> None:
        """Callback triggered by FileMonitor watchdog observer."""
        with self._lock:
            self._file_events.append(event)
        self._ingest_event(event)

    def _record_error(self, message: str) -> None:
        """Record operational error without throwing."""
        logger.debug(message)
        with self._lock:
            self._errors.append(f"[{time.strftime('%H:%M:%S')}] {message}")

    # -------------------------------------------------------------------------
    # Controlled Execution Interface Integration
    # -------------------------------------------------------------------------

    def submit_execution_request(self, request: ExecutionRequest) -> ExecutionServiceResult:
        """
        Submit an ExecutionRequest through ControlledExecutionService.
        Records result metadata safely with sensitive parameter redaction.
        """
        result = self.execution_service.execute(request)

        # Record result in bounded history
        record = {
            "request_id": request.request_id,
            "executable": redact_string(request.executable),
            "command_line": redact_command_line(request.command_line),
            "status": result.status,
            "decision": result.decision.decision if result.decision else "UNKNOWN",
            "risk_score": result.decision.risk_score if result.decision else 0,
            "risk_level": result.decision.risk_level if result.decision else "LOW",
            "reasons": result.decision.reasons if result.decision else [],
            "executed": result.executed,
            "error": result.error,
            "timestamp": time.time(),
        }

        with self._lock:
            self._execution_records.append(record)

        # Ingest decision events if present
        if result.events:
            for evt in result.events:
                self._ingest_event(evt)

        return result

    # -------------------------------------------------------------------------
    # Thread-Safe Telemetry Snapshots
    # -------------------------------------------------------------------------

    def get_processes_snapshot(self) -> Dict[int, Dict[str, Any]]:
        """Return a copy of the current process table."""
        with self._lock:
            return dict(self._processes)

    def get_process_events_snapshot(self) -> Dict[int, Event]:
        """Return a copy of evaluated process events."""
        with self._lock:
            return dict(self._process_events)

    def get_alerts_snapshot(self) -> List[Event]:
        """Return a list of recent active alerts."""
        with self._lock:
            return list(self._alerts)

    def get_events_snapshot(self) -> List[Event]:
        """Return a list of recent observed security events."""
        with self._lock:
            return list(self._events)

    def get_network_events_snapshot(self) -> List[Event]:
        """Return a list of recent network events."""
        with self._lock:
            return list(self._network_events)

    def get_file_events_snapshot(self) -> List[Event]:
        """Return a list of recent file modification events."""
        with self._lock:
            return list(self._file_events)

    def get_login_events_snapshot(self) -> List[Event]:
        """Return a list of recent user session / logon events."""
        with self._lock:
            return list(self._login_events)

    def get_execution_records_snapshot(self) -> List[Dict[str, Any]]:
        """Return a list of controlled execution request records."""
        with self._lock:
            return list(self._execution_records)

    def get_latest_resources(self) -> Dict[str, Any]:
        """Return latest system resource metrics."""
        with self._lock:
            return dict(self._latest_resources)

    def poll_new_events(self, max_items: int = 50) -> List[Event]:
        """Consume available events from queue non-blockingly."""
        pulled: List[Event] = []
        for _ in range(max_items):
            try:
                evt = self.event_queue.get_nowait()
                pulled.append(evt)
                self.event_queue.task_done()
            except queue.Empty:
                break
        return pulled

    def get_state_snapshot(self) -> Dict[str, Any]:
        """
        Return an atomic snapshot of high-level dashboard metrics and status.
        """
        with self._lock:
            total_procs = len(self._processes)
            alerts_list = list(self._alerts)
            high_count = sum(1 for a in alerts_list if a.severity == "HIGH")
            med_count = sum(1 for a in alerts_list if a.severity == "MEDIUM")
            low_count = sum(1 for a in alerts_list if a.severity == "LOW")

            we_cfg = self.config.get("windows_enforcement", {})
            ce_cfg = self.config

            return {
                "status": self._status,
                "process_count": total_procs,
                "alert_counts": {
                    "HIGH": high_count,
                    "MEDIUM": med_count,
                    "LOW": low_count,
                    "TOTAL": len(alerts_list),
                },
                "latest_resources": dict(self._latest_resources),
                "controlled_execution": {
                    "enabled": ce_cfg.get("enabled", True),
                    "dry_run": ce_cfg.get("dry_run", True),
                    "allow_active_execution": ce_cfg.get("launcher", {}).get(
                        "allow_active_execution", False
                    ),
                    "interception_enabled": ce_cfg.get("interception_enabled", False),
                },
                "windows_enforcement": {
                    "enabled": we_cfg.get("enabled", False),
                    "channels": list(we_cfg.get("channels", [])),
                },
                "recent_alerts": alerts_list[-5:] if alerts_list else [],
                "errors": list(self._errors),
            }


class _EngineFileEventHandler(FileMonitor):
    """Bridge FileMonitor watchdog callbacks into MonitoringEngine."""

    def __init__(self, callback: Callable[[Event], None]) -> None:
        super().__init__()
        self._callback = callback

    def on_created(self, event):
        evt = super().on_created(event)
        if evt:
            self._callback(evt)

    def on_modified(self, event):
        evt = super().on_modified(event)
        if evt:
            self._callback(evt)

    def on_deleted(self, event):
        evt = super().on_deleted(event)
        if evt:
            self._callback(evt)

    def on_moved(self, event):
        evt = super().on_moved(event)
        if evt:
            self._callback(evt)
