"""
Process Enforcement Management Module (Phase 2).

Manages system-wide independent process interception, coordination with the
Windows native kernel driver (PsSetCreateProcessNotifyRoutineEx), and integration
with ControlledLauncher. Explicitly separates requested policy decisions from
actual verified operating system enforcement.
"""

import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from src.execution.approval_manager import ApprovalManager
from src.execution.audit import SecurityAuditLogger
from src.execution.launcher import ControlledLauncher, LaunchResult
from src.execution.policy import ExecutionPolicy
from src.models.execution_request import (
    DecisionProvenance,
    DecisionStatus,
    EnforcementStatus,
    ExecutionDecision,
    ExecutionRequest,
    OperationType,
)

logger = logging.getLogger("endpoint_monitor")

DEVICE_NAME = r"\\.\EndpointSecurityDriver"

# IOCTL definitions matching EndpointSecurityDriver.h
ENDPOINT_SECURITY_DEVICE_TYPE = 0x8000
IOCTL_ENDPOINT_SECURITY_HEARTBEAT = (
    (ENDPOINT_SECURITY_DEVICE_TYPE << 16) | (0 << 14) | (0x800 << 2) | 0
)
IOCTL_ENDPOINT_SECURITY_GET_STATUS = (
    (ENDPOINT_SECURITY_DEVICE_TYPE << 16) | (0 << 14) | (0x801 << 2) | 0
)


@dataclass
class ProcessEnforcementDiagnostics:
    """Real-time operational diagnostics for process enforcement components."""
    driver_available: bool = False
    driver_device_opened: bool = False
    driver_service_connected: bool = False
    process_notify_callback_active: bool = False
    total_processes_evaluated: int = 0
    total_processes_blocked: int = 0
    controlled_launcher_active: bool = True
    independent_interception_active: bool = False
    status_message: str = "Driver not installed. Independent process creation is observed only."
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProcessEnforcementManager:
    """
    Coordinates process execution policy enforcement across:
    1. Application-controlled launches via ControlledLauncher.
    2. System-wide independent process creation via native kernel driver.
    """

    def __init__(
        self,
        policy: Optional[ExecutionPolicy] = None,
        approval_manager: Optional[ApprovalManager] = None,
        audit_logger: Optional[SecurityAuditLogger] = None,
        config: Optional[Dict[str, Any]] = None,
        logger_instance: Optional[logging.Logger] = None,
    ) -> None:
        self.logger = logger_instance if logger_instance is not None else logger
        self.policy = policy if policy is not None else ExecutionPolicy(config=config)
        self.approval_manager = approval_manager
        self.audit_logger = audit_logger
        self._lock = threading.RLock()

        # Controlled launcher initialized with approval manager & audit logger
        self.launcher = ControlledLauncher(
            policy=self.policy,
            approval_manager=self.approval_manager,
            audit_logger=self.audit_logger,
            config=config,
        )

        self._driver_handle: Optional[wintypes.HANDLE] = None
        self._probe_driver_device()

    def _probe_driver_device(self) -> bool:
        """
        Inspect whether the native driver device object is available on Windows.
        Does not install unverified drivers.
        """
        if os.name != "nt":
            return False

        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.CreateFileW.restype = wintypes.HANDLE
            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            OPEN_EXISTING = 3
            FILE_ATTRIBUTE_NORMAL = 0x80
            INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

            handle = kernel32.CreateFileW(
                DEVICE_NAME,
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )

            is_valid = bool(
                handle
                and handle != INVALID_HANDLE_VALUE
                and handle != -1
                and handle != 0
            )

            if is_valid:
                self._driver_handle = handle
                self.logger.info("Native process enforcement driver device successfully opened.")
                return True
            else:
                self._driver_handle = None
                return False
        except Exception as e:
            self.logger.debug(f"Driver probe encountered exception: {e}")
            self._driver_handle = None
            return False

    def is_driver_available(self) -> bool:
        """Check if native kernel driver device is currently open and communicating."""
        with self._lock:
            if not self._driver_handle:
                self._probe_driver_device()
            return self._driver_handle is not None

    def launch_controlled(
        self,
        request: ExecutionRequest,
        timeout: Optional[float] = None,
        capture_output: bool = True,
        env: Optional[Dict[str, str]] = None,
    ) -> LaunchResult:
        """
        Execute an application-controlled process launch with full policy gating.
        """
        return self.launcher.launch(
            request=request,
            timeout=timeout,
            capture_output=capture_output,
            env=env,
        )

    def evaluate_independent_process(
        self,
        process_id: int,
        parent_pid: Optional[int],
        executable: str,
        command_line: Optional[List[str]] = None,
        create_time: Optional[float] = None,
        username: Optional[str] = None,
    ) -> ExecutionDecision:
        """
        Evaluate policy for an independent process creation event observed or
        intercepted outside ControlledLauncher.
        """
        cmd = list(command_line) if command_line else [executable]
        req = ExecutionRequest(
            operation_type=OperationType.PROCESS,
            executable=executable,
            command_line=cmd,
            process_id=process_id,
            parent_pid=parent_pid,
            process_create_time=create_time or time.time(),
            username=username,
        )

        decision = self.policy.evaluate(req)

        # A device handle is not evidence that a policy decision reached a
        # process-creation callback or changed the operating-system outcome.
        decision.enforcement_status = EnforcementStatus.NOT_ENFORCED

        # Record structured audit log
        if self.audit_logger:
            self.audit_logger.record_decision(req, decision)

        return decision

    def get_diagnostics(self) -> ProcessEnforcementDiagnostics:
        """Return live health diagnostics inspecting actual component state."""
        with self._lock:
            driver_avail = self.is_driver_available()
            if driver_avail:
                msg = (
                    "Driver device is open, but no verified policy channel or process-blocking "
                    "integration is active."
                )
            else:
                msg = (
                    "Native kernel driver not loaded. Application-controlled launches are strictly "
                    "enforced via ControlledLauncher; host-wide independent processes are observed."
                )

            return ProcessEnforcementDiagnostics(
                driver_available=driver_avail,
                driver_device_opened=driver_avail,
                driver_service_connected=False,
                process_notify_callback_active=False,
                controlled_launcher_active=True,
                independent_interception_active=False,
                status_message=msg,
            )

    def close(self) -> None:
        """Close driver device handle cleanly."""
        with self._lock:
            if self._driver_handle and os.name == "nt":
                try:
                    ctypes.windll.kernel32.CloseHandle(self._driver_handle)
                except Exception:
                    pass
                self._driver_handle = None

    def evaluate_process_creation(
        self,
        request_or_pid: Any,
        parent_pid: Optional[int] = None,
        executable: Optional[str] = None,
        command_line: Optional[List[str]] = None,
        create_time: Optional[float] = None,
        username: Optional[str] = None,
    ) -> ExecutionDecision:
        """
        Evaluate policy for an independent process creation event.
        Accepts either an ExecutionRequest instance or individual parameters.
        """
        if isinstance(request_or_pid, ExecutionRequest):
            req = request_or_pid
            return self.evaluate_independent_process(
                process_id=req.process_id or 0,
                parent_pid=req.parent_pid,
                executable=req.executable,
                command_line=req.command_line,
                create_time=req.process_create_time,
                username=req.username,
            )
        return self.evaluate_independent_process(
            process_id=int(request_or_pid),
            parent_pid=parent_pid,
            executable=executable or "",
            command_line=command_line,
            create_time=create_time,
            username=username,
        )
