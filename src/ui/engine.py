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
    ExecutionServiceStatus,
    redact_command_line,
    redact_string,
)
from src.execution.service_foundation import EndpointSecurityService
from src.execution.windows_enforcement import (
    WindowsEnforcementCollector,
    WindowsEnforcementCorrelator,
)
from src.models.event import Event
from src.models.execution_request import (
    DecisionStatus,
    EnforcementStatus,
    ExecutionDecision,
    ExecutionRequest,
    OperationType,
)
from src.monitors.file_monitor import FileMonitor
from src.monitors.login_monitor import LoginMonitor
from src.monitors.network_monitor import NetworkMonitor
from src.monitors.process_monitor import (
    ProcessIdentityRegistry,
    get_new_processes,
    get_running_processes,
)
from src.monitors.resource_monitor import ResourceMonitor
from src.monitors.windows_process_telemetry import (
    ProcessTelemetryCorrelator,
    WindowsProcessTelemetryCollector,
)


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
        max_process_events_capacity: int = 2000,
        baseline_path: Optional[str] = None,
    ) -> None:
        self.config_path = config_path
        self.poll_interval = max(1.0, float(poll_interval))
        self.max_events_capacity = max(1, max_events_capacity)
        self.max_alerts_capacity = max(1, max_alerts_capacity)
        self.max_queue_size = max(1, max_queue_size)
        self.max_process_events_capacity = max(1, max_process_events_capacity)

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
        self._network_snapshot: List[Dict[str, Any]] = []
        self._network_health: Dict[str, Any] = {
            "enabled": True,
            "status": "NOT_YET_COLLECTED",
            "last_success_timestamp": None,
            "last_error": None,
        }
        self._active_baseline_anomalies: Set[str] = set()
        self._errors: Deque[str] = deque(maxlen=50)
        self._dropped_notifications = 0
        self._command_detector_invocations = 0
        self._snapshot_generation = 0
        self._last_process_poll_timestamp: Optional[float] = None
        self._last_process_poll_success: Optional[float] = None
        self._last_process_poll_error: Optional[str] = None
        self._process_polling_count: int = 0

        # Subsystem engines
        self.config = load_execution_config(self.config_path)
        self.tree_analyzer = ProcessTreeAnalyzer()
        self.baseline_engine = BaselineEngine() if baseline_path is None else BaselineEngine(baseline_path)
        self.resource_monitor = ResourceMonitor(config_path=self.config_path, logger=logger)
        self.network_monitor = NetworkMonitor(config_path=self.config_path, logger=logger)
        self.login_monitor = LoginMonitor(logger=logger)
        self.execution_service = ControlledExecutionService(config=self.config)
        self.security_service = EndpointSecurityService(
            config=self.config,
            config_path=self.config_path,
            enable_ipc=False,
            logger_instance=logger,
        )

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

        # Windows Process Creation Telemetry (Security event 4688).
        # Disabled by default; polling monitoring stays fully functional when
        # the source is disabled or unavailable.
        wpt_cfg = self.config.get("windows_process_telemetry", {}) or {}
        self.process_telemetry_enabled = bool(wpt_cfg.get("enabled", False))
        self.process_telemetry_collector = WindowsProcessTelemetryCollector(
            channel=wpt_cfg.get("channel", "Security"),
            event_id=wpt_cfg.get("event_id", 4688),
            max_events_per_query=wpt_cfg.get("max_events_per_query", 200),
            query_timeout=wpt_cfg.get("query_timeout_seconds", 10.0),
        )
        self.process_telemetry_correlator = ProcessTelemetryCorrelator()

        # Process identity registry: shared by the polling monitor and the
        # Windows process-creation telemetry source so that the same process
        # instance is never reported twice.
        self.process_identities = ProcessIdentityRegistry(
            tolerance=float(wpt_cfg.get("dedup_tolerance_seconds", 5.0) or 5.0),
            capacity=max(self.max_process_events_capacity, 1000),
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

        # Join worker thread without holding lock.  The budget is bounded so
        # that shutdown stays fast even while a monitoring cycle is running.
        if self._worker_thread and self._worker_thread.is_alive():
            join_budget = min(max(float(timeout), 0.0), 0.45)
            self._worker_thread.join(timeout=join_budget)

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

        # Release the process creation telemetry collector
        try:
            self.process_telemetry_collector.close()
        except Exception as e:
            logger.debug(f"Error closing process telemetry collector: {e}")

        # Stop privileged security service
        try:
            self.security_service.stop()
        except Exception as e:
            logger.debug(f"Error stopping security service on engine shutdown: {e}")

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
                        "status": res_result.get("overall_severity"),
                    }
                )
            self._ingest_resource_alerts(res_result)
            self._evaluate_resource_baseline(res_result.get("metrics", {}))
        except Exception as e:
            self._record_error(f"Resource monitor check failed: {e}")

        if self._stop_event.is_set():
            return

        # 2. Process Monitoring & Process Tree Analysis
        with self._lock:
            self._last_process_poll_timestamp = time.time()
            prev_processes = dict(self._processes)
        current_processes = dict(prev_processes)
        process_tree = None
        try:
            current_processes = get_running_processes()

            # Avoid wiping out live process state on an unexpected scan failure
            if not current_processes and prev_processes:
                self._record_error("Process enumeration returned unexpected empty snapshot; retaining live state.")
                current_processes = prev_processes

            new_processes = get_new_processes(prev_processes, current_processes)
            process_tree = ProcessTree.build(current_processes)

            # Evaluate each newly detected process (or all on initial cycle)
            targets = new_processes if prev_processes else list(current_processes.values())

            for proc in targets:
                pid = proc.get("pid")
                create_time = proc.get("create_time")

                # A process instance that was already reported through the
                # Windows process-creation telemetry must not be reported a
                # second time by the polling monitor.
                already_reported = self.process_identities.matches(pid, create_time)

                event = self._evaluate_process_event(proc, current_processes, process_tree)

                if already_reported:
                    event.metadata["duplicate_suppressed"] = True
                    if event.pid is not None:
                        with self._lock:
                            self._process_events[event.pid] = event
                    continue

                self._ingest_event(event)
                self.process_identities.register(pid, create_time, source="polling")

            # Evict process state for processes that are gone.  A failed or
            # empty collection never removes live process state.
            self._prune_process_events(current_processes)

            # Publish the newly evaluated process snapshot atomically ONLY after
            # all target events have been evaluated and ingested for this cycle.
            with self._lock:
                self._processes = current_processes
                self._snapshot_generation += 1
                self._last_process_poll_success = time.time()
                self._process_polling_count += 1
                self._last_process_poll_error = None

        except Exception as e:
            err_msg = str(e)
            self._record_error(f"Process monitoring cycle failed: {err_msg}")
            with self._lock:
                self._last_process_poll_error = err_msg
                current_processes = dict(self._processes)
            process_tree = None

        # 3. Network Monitoring Check
        if self._stop_event.is_set():
            return

        try:
            if self.network_monitor.enabled:
                net_result = self.network_monitor.check_connections(
                    processes=current_processes,
                    process_tree=process_tree,
                    new_only=bool(prev_processes),
                )
                with self._lock:
                    self._network_snapshot = list(net_result.get("active_connections", []))
                    self._network_health = {
                        "enabled": True,
                        "status": net_result.get("collection_status", "UNKNOWN"),
                        "last_success_timestamp": net_result.get("last_success_timestamp"),
                        "last_error": net_result.get("last_error"),
                    }
                for net_event in net_result.get("suspicious_events", []):
                    self._ingest_event(net_event)
                    with self._lock:
                        self._network_events.append(net_event)
            else:
                with self._lock:
                    self._network_snapshot = []
                    self._network_health = {
                        "enabled": False,
                        "status": "DISABLED",
                        "last_success_timestamp": None,
                        "last_error": None,
                    }
        except Exception as e:
            self._record_error(f"Network monitor cycle failed: {e}")

        # 4. Windows OS Enforcement Telemetry Check (if enabled)
        if self._stop_event.is_set():
            return

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
        if self._stop_event.is_set():
            return

        try:
            logon_events = self.login_monitor.check_logon_events(new_only=True)
            for l_evt in logon_events:
                self._ingest_event(l_evt)
                with self._lock:
                    self._login_events.append(l_evt)
        except Exception as e:
            self._record_error(f"User logon monitor cycle failed: {e}")

        # 6. Windows Process Creation Telemetry (if enabled)
        if self.process_telemetry_enabled and not self._stop_event.is_set():
            try:
                self._collect_process_telemetry(current_processes, process_tree)
            except Exception as e:
                self._record_error(f"Windows process creation telemetry check failed: {e}")

    def _collect_process_telemetry(
        self,
        current_processes: Dict[int, Dict[str, Any]],
        process_tree: Optional[ProcessTree],
    ) -> None:
        """
        Collect Windows process-creation records and normalize them into the
        standard event model.

        Records that describe a process instance that was already observed
        through the polling monitor are correlated instead of duplicated.
        """
        records = self.process_telemetry_collector.query_live_events()
        if not records:
            return

        for record in records:
            process_info = self.process_telemetry_correlator.to_process_info(
                record, running_processes=current_processes
            )

            pid = process_info.get("pid")
            create_time = process_info.get("create_time")

            if self.process_identities.matches(pid, create_time):
                # Already known through polling - attach the telemetry
                # evidence to the existing event instead of duplicating it.
                existing = self.get_process_events_snapshot().get(pid) if pid is not None else None
                if existing is not None:
                    ex_create = existing.metadata.get("create_time")
                    if (
                        ex_create is None
                        or create_time is None
                        or abs(float(ex_create) - float(create_time)) <= self.process_identities.tolerance
                    ):
                        existing.metadata.setdefault("telemetry_confirmed", True)
                        existing.metadata.setdefault(
                            "telemetry_record_id", record.record_id
                        )
                continue

            event = self._evaluate_process_event(
                process_info, current_processes, process_tree
            )
            event.source = "windows_process_telemetry"
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

            self._ingest_event(event)
            self.process_identities.register(pid, create_time, source="telemetry")

    def _prune_process_events(self, current_processes: Dict[int, Dict[str, Any]]) -> None:
        """
        Evict process state for processes that no longer exist.

        The cache is bounded so that long running sessions cannot grow it
        without limit.  Alert history is preserved in the bounded alert
        history, and an empty snapshot (a failed collection) never removes
        live process state.
        """
        if not current_processes:
            return

        with self._lock:
            stale_pids = []
            for pid, evt in self._process_events.items():
                if pid not in current_processes:
                    stale_pids.append(pid)
                else:
                    curr_create = current_processes[pid].get("create_time")
                    evt_create = evt.metadata.get("create_time")
                    if (
                        curr_create is not None
                        and evt_create is not None
                        and abs(float(curr_create) - float(evt_create)) > 1e-6
                    ):
                        stale_pids.append(pid)

            for pid in stale_pids:
                self._process_events.pop(pid, None)

            overflow = len(self._process_events) - self.max_process_events_capacity
            if overflow > 0:
                ordered = sorted(
                    self._process_events.items(),
                    key=lambda item: getattr(item[1], "timestamp", 0) or 0,
                )
                for pid, _event in ordered[:overflow]:
                    self._process_events.pop(pid, None)

    def _evaluate_process_event(
        self,
        process_info: Dict[str, Any],
        process_map: Dict[int, Dict[str, Any]],
        process_tree: Optional[ProcessTree],
    ) -> Event:
        """Construct standard Event, evaluate command indicators, tree lineage, and risk."""
        event = Event.from_process_info(process_info)
        event.metadata["create_time"] = process_info.get("create_time")
        cmdline = event.command_line

        # Command indicator analysis.  The parent context allows detection of
        # shell pipelines whose operators were consumed by the parent shell.
        parent_info = {}
        parent_pid = process_info.get("ppid")
        if parent_pid is not None and parent_pid in process_map:
            parent_entry = process_map.get(parent_pid) or {}
            parent_info = {
                "parent_name": parent_entry.get("name"),
                "parent_cmdline": parent_entry.get("cmdline"),
            }

        try:
            event.indicators = detect_command_indicators(cmdline, context=parent_info)
            event.metadata["command_detector_invoked"] = True
            with self._lock:
                self._command_detector_invocations += 1
        except Exception as e:
            event.metadata["command_detector_invoked"] = False
            event.indicators = []
            logger.error(f"Command detector failed for PID {event.pid}: {e}")

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
            if anomaly_result.get("anomaly_score", 0):
                for reason in anomaly_result.get("reasons", []):
                    if reason not in event.risk_reasons:
                        event.risk_reasons.append(reason)
                event.risk_score += int(anomaly_result["anomaly_score"])
                event.risk_level = (
                    "HIGH" if event.risk_score >= 7 else
                    "MEDIUM" if event.risk_score >= 3 else "LOW"
                )
                event.severity = event.risk_level
            self.baseline_engine.collect_event(event)
        except Exception as e:
            logger.debug(f"Baseline engine error on PID {event.pid}: {e}")

        # Track evaluated event for process
        if event.pid is not None:
            with self._lock:
                self._process_events[event.pid] = event

        return event

    def _ingest_resource_alerts(self, result: Dict[str, Any]) -> None:
        """Publish actionable resource state transitions, not every metric sample."""
        for alert in result.get("alerts", []):
            severity = alert.get("severity", "LOW")
            score = {"LOW": 1, "MEDIUM": 4, "HIGH": 7}.get(severity, 0)
            event = Event(
                event_type="resource_recovery" if alert.get("type") == "RECOVERY" else "resource_anomaly",
                source="resource_monitor",
                severity=severity,
                risk_score=score,
                risk_level=severity,
                indicators=["resource_state_transition"],
                risk_reasons=[alert.get("message", "Resource state changed")],
                resource_metrics=result.get("metrics"),
                metadata={
                    "resource": alert.get("resource"),
                    "usage": alert.get("usage"),
                    "alert_type": alert.get("type"),
                    "is_sustained": alert.get("is_sustained", False),
                    "threshold_status": result.get("overall_severity"),
                },
            )
            self._ingest_event(event)

    def _evaluate_resource_baseline(self, metrics: Dict[str, Any]) -> None:
        """Score resource samples and emit one event per baseline anomaly transition."""
        sample = Event(
            event_type="resource_sample",
            source="resource_monitor",
            resource_metrics=metrics,
        )
        try:
            result = self.baseline_engine.analyze_event(sample)
            self.baseline_engine.collect_event(sample)
        except Exception as exc:
            self._record_error(f"Resource baseline evaluation failed: {exc}")
            return

        reasons = result.get("reasons", [])
        anomaly_key = "|".join(reasons)
        if result.get("is_anomaly") and anomaly_key:
            if anomaly_key not in self._active_baseline_anomalies:
                score = int(result.get("anomaly_score", 0))
                level = result.get("anomaly_level", "LOW")
                self._ingest_event(
                    Event(
                        event_type="resource_baseline_anomaly",
                        source="behavioral_baseline",
                        severity=level,
                        risk_score=score,
                        risk_level=level,
                        indicators=["resource_baseline_anomaly"],
                        risk_reasons=list(reasons),
                        resource_metrics=metrics,
                        metadata={"baseline_status": result.get("status")},
                    )
                )
            self._active_baseline_anomalies.add(anomaly_key)
        else:
            self._active_baseline_anomalies.clear()

    # -------------------------------------------------------------------------
    # Ingestion and Alert Handlers
    # -------------------------------------------------------------------------

    def _ingest_event(self, event: Event) -> None:
        """Store event in bounded queues and notify UI subscribers."""
        with self._lock:
            self._events.append(event)
            if event.severity in ("HIGH", "MEDIUM") or event.indicators:
                self._alerts.append(event)

        # Dispatch non-blockingly to the real-time notification queue
        self._publish_event(event)

    def _publish_event(self, event: Event) -> None:
        """
        Publish an event to the subscriber queue without blocking the worker.

        The queue is a transient notification channel; the authoritative
        bounded history is kept in the event and alert deques.  When the queue
        is saturated the oldest notification is dropped so that the newest
        event is never lost, and the drop is counted for diagnostics.
        """
        try:
            self.event_queue.put_nowait(event)
            return
        except queue.Full:
            pass

        try:
            self.event_queue.get_nowait()
            self.event_queue.task_done()
            self.event_queue.put_nowait(event)
        except queue.Empty:
            self._record_dropped_notification()
        except queue.Full:
            self._record_dropped_notification()

    def _record_dropped_notification(self) -> None:
        """Count and report a dropped real-time notification."""
        with self._lock:
            self._dropped_notifications += 1
            dropped = self._dropped_notifications
        if dropped <= 5 or dropped % 100 == 0:
            logger.warning(
                f"Real-time event notification dropped (total: {dropped}). "
                "The event remains available in the bounded event history."
            )

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
        Submit an ExecutionRequest through ControlledExecutionService and EndpointSecurityService.
        Records result metadata safely with sensitive parameter redaction.
        """
        # Coordinate with privileged security service
        sec_decision = self.security_service.submit_request(request)

        result = self.execution_service.execute(request)
        if sec_decision.decision == DecisionStatus.REQUIRE_APPROVAL:
            result.status = ExecutionServiceStatus.GATE_BLOCKED
            if sec_decision.reasons:
                result.reasons = list(sec_decision.reasons)
            result.decision = sec_decision

        # Record result in bounded history
        record = {
            "request_id": request.request_id,
            "executable": redact_string(request.executable),
            "command_line": redact_command_line(request.command_line),
            "status": result.status,
            "decision": sec_decision.decision if sec_decision else (result.decision.decision if result.decision else "UNKNOWN"),
            "risk_score": sec_decision.risk_score if sec_decision else 0,
            "risk_level": sec_decision.risk_level if sec_decision else "LOW",
            "reasons": sec_decision.reasons if sec_decision else (result.decision.reasons if result.decision else []),
            "executed": result.executed,
            "error": result.error,
            "timestamp": time.time(),
            "approval_id": sec_decision.approval_id,
            "enforcement_status": sec_decision.enforcement_status,
        }

        with self._lock:
            self._execution_records.append(record)

        # Ingest decision events if present
        if result.events:
            for evt in result.events:
                self._ingest_event(evt)

        return result

    def submit_enforcement_request(self, request: ExecutionRequest) -> ExecutionDecision:
        """Submit a process or network operation request directly to the enforcement policy engine."""
        return self.security_service.submit_request(request)

    def get_service_health(self) -> Dict[str, Any]:
        """Report local policy state separately from the absent privileged IPC service."""
        health = self.security_service.get_health()
        health["service_connection"] = {
            "status": "NOT_CONNECTED",
            "mode": "IN_PROCESS_POLICY_ONLY",
            "ipc_enabled": bool(self.security_service.enable_ipc),
            "service_running": bool(self.security_service.is_running()),
        }
        return health

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Fetch list of pending approval requests from ApprovalManager."""
        return self.security_service.get_pending_approvals()

    def approve_request(
        self,
        approval_id: str,
        approver: str = "gui_user",
        reason: str = "Approved from GUI console",
    ) -> Tuple[bool, str]:
        """Approve a pending request and record authorization token."""
        success, rec, err = self.security_service.approve_request(approval_id, approver=approver, reason=reason)
        if success and rec:
            return True, (
                f"Request {approval_id} successfully approved. Its single-use authorization remains internal "
                "to the controlled retry path."
            )
        return False, err or "Failed to approve request."

    def deny_request(
        self,
        approval_id: str,
        approver: str = "gui_user",
        reason: str = "Denied from GUI console",
    ) -> Tuple[bool, str]:
        """Deny a pending request."""
        success, rec, err = self.security_service.deny_request(approval_id, approver=approver, reason=reason)
        if success:
            return True, f"Request {approval_id} denied."
        return False, err or "Failed to deny request."

    def retry_approved_request(
        self,
        approval_id: str,
        token: Optional[str] = None,
    ) -> Any:
        """Execute a controlled retry for an approved process request using its single-use token."""
        appr = self.security_service.approval_manager.get_request(approval_id)
        if not appr:
            from src.execution.launcher import LaunchResult
            dummy_dec = ExecutionDecision(
                request_id=approval_id,
                decision=DecisionStatus.BLOCK,
                reasons=[f"Approval record '{approval_id}' not found"],
                enforcement_status=EnforcementStatus.VERIFIED_BLOCKED,
            )
            return LaunchResult(
                request_id=approval_id,
                decision=dummy_dec,
                executed=False,
                error=f"Approval record '{approval_id}' not found",
                enforcement_status=EnforcementStatus.VERIFIED_BLOCKED,
            )

        auth_token = token or appr.single_use_token
        if appr.operation_type == OperationType.NETWORK:
            from src.execution.launcher import LaunchResult
            decision = self.security_service.wfp_manager.evaluate_network_connection(
                remote_ip=appr.remote_ip,
                remote_port=appr.remote_port,
                protocol=appr.protocol or "TCP",
                process_id=appr.pid,
                process_create_time=appr.process_create_time,
                executable=appr.executable,
                approval_id=approval_id,
                approval_token=auth_token,
            )
            is_allowed = decision.decision == DecisionStatus.ALLOW
            return LaunchResult(
                request_id=appr.request_id,
                decision=decision,
                executed=is_allowed,
                error=decision.error if not is_allowed else None,
                enforcement_status=decision.enforcement_status,
            )

        req = ExecutionRequest(
            operation_type=appr.operation_type,
            executable=appr.executable,
            command_line=appr.command_line,
            parent_pid=appr.pid,
            metadata={"approval_id": approval_id, "approval_token": auth_token},
        )
        return self.security_service.process_manager.launch_controlled(req)

    def get_decision_history(self) -> List[Dict[str, Any]]:
        """Fetch recent decision records from EndpointSecurityService."""
        return self.security_service.get_decision_history()

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

    def get_network_snapshot(self) -> List[Dict[str, Any]]:
        """Return the latest sampled socket snapshot (not a connection history)."""
        with self._lock:
            return [dict(connection) for connection in self._network_snapshot]

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
                "total_events": len(self._events),
                "total_alerts": len(alerts_list),
                "alert_counts": {
                    "HIGH": high_count,
                    "MEDIUM": med_count,
                    "LOW": low_count,
                    "TOTAL": len(alerts_list),
                },
                "process_polling": self.get_process_polling_status(),
                "latest_resources": dict(self._latest_resources),
                "network_health": dict(self._network_health),
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
                "process_telemetry": self.get_process_telemetry_status(),
                "service_health": self.get_service_health(),
                "pending_approvals": self.get_pending_approvals(),
                "pending_approvals_count": len(self.get_pending_approvals()),
                "decision_history": self.get_decision_history(),
                "recent_alerts": alerts_list[-5:] if alerts_list else [],
                "errors": list(self._errors),
                "command_detector_invocations": self._command_detector_invocations,
                "snapshot_generation": self._snapshot_generation,
            }

    def get_command_detector_invocations(self) -> int:
        """Return count of successful command detector invocations in this engine."""
        with self._lock:
            return self._command_detector_invocations

    def get_snapshot_generation(self) -> int:
        """Return the current process snapshot generation / version."""
        with self._lock:
            return self._snapshot_generation

    def get_process_polling_status(self) -> Dict[str, Any]:
        """Return diagnostic health and performance of the process polling monitor."""
        with self._lock:
            is_active = self.is_running() and not self.is_paused()
            status_str = "RUNNING" if is_active else ("PAUSED" if self.is_paused() else self._status)
            return {
                "running": is_active,
                "status": status_str,
                "last_poll_timestamp": self._last_process_poll_timestamp,
                "last_success_timestamp": self._last_process_poll_success,
                "last_error": self._last_process_poll_error,
                "total_polls": self._process_polling_count,
                "observed_processes": len(self._processes),
            }

    def get_process_telemetry_status(self) -> Dict[str, Any]:
        """Return the diagnostic status of the Windows process-creation source."""
        snapshot = self.process_telemetry_collector.get_status_snapshot()
        snapshot["configured"] = bool(self.process_telemetry_enabled)
        snapshot["enabled"] = bool(self.process_telemetry_enabled)
        if not self.process_telemetry_enabled:
            snapshot["status"] = "DISABLED"
            snapshot["unavailable_reason"] = None
        with self._lock:
            snapshot["dropped_notifications"] = self._dropped_notifications
            snapshot["tracked_process_identities"] = len(self.process_identities)
        return snapshot


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
