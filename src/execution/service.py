"""
Controlled Execution Service Module (Phase 3).

Coordinates execution request validation, security policy evaluation, dual-gate
safety checks, controlled process launching, event generation, alert emission,
and structured security audit logging.
"""

import collections
from dataclasses import asdict, dataclass, field
import logging
import os
import re
import threading
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

from src.alerts.alert_manager import show_alert
from src.execution.config import load_execution_config
from src.execution.launcher import ControlledLauncher, LaunchResult
from src.execution.policy import ExecutionPolicy
from src.models.event import Event
from src.models.execution_request import (
    DecisionStatus,
    ExecutionDecision,
    ExecutionRequest,
)


class ExecutionServiceStatus:
    """Distinct outcome statuses returned by ControlledExecutionService."""
    VALIDATION_FAILED = "VALIDATION_FAILED"
    POLICY_DENIED = "POLICY_DENIED"
    DRY_RUN = "DRY_RUN"
    GATE_BLOCKED = "GATE_BLOCKED"
    COMPLETED = "COMPLETED"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    SERVICE_ERROR = "SERVICE_ERROR"


class ExecutionEventType:
    """Standardized event types emitted by ControlledExecutionService."""
    REJECTED = "execution_rejected"
    DENIED = "execution_denied"
    DRY_RUN = "execution_dry_run"
    GATE_BLOCKED = "execution_gate_blocked"
    # Emitted before calling the launcher (pre-spawn attempt record).
    LAUNCH_ATTEMPTED = "execution_launch_attempted"
    # Emitted only when subprocess.Popen confirms the child process was created.
    LAUNCHED = "execution_launched"
    COMPLETED = "execution_completed"
    FAILED = "execution_failed"
    TIMEOUT = "execution_timeout"
    ERROR = "execution_error"
    INTERCEPTION_BLOCKED = "execution_interception_blocked"


# Set of flags whose immediate subsequent parameter value should be redacted
SENSITIVE_FLAGS: Set[str] = {
    "-p",
    "--password",
    "--passwd",
    "--pwd",
    "-t",
    "--token",
    "--access-token",
    "--auth-token",
    "-s",
    "--secret",
    "--client-secret",
    "--api-key",
    "--apikey",
    "--key",
    "-u",
    "--user",
    "--username",
    "--auth",
    "--authorization",
    "--bearer",
    "--cert",
    "--private-key",
}

# Regex for inline flags e.g. --password=secret, -p=secret
INLINE_SECRET_PATTERN = re.compile(
    r"^(--?[a-zA-Z0-9_-]*(?:password|passwd|pwd|token|secret|api[_-]?key|auth|bearer)[a-zA-Z0-9_-]*=)(.+)$",
    re.IGNORECASE,
)

# Regex for variable assignments e.g. PASSWORD=secret, API_KEY=xyz
ASSIGNMENT_SECRET_PATTERN = re.compile(
    r"^([a-zA-Z0-9_-]*(?:password|passwd|pwd|token|secret|api[_-]?key|auth|bearer)[a-zA-Z0-9_-]*=)(.+)$",
    re.IGNORECASE,
)

# Generic sensitive markers. Use a blanket redaction when a string contains
# a secret-bearing term, because reason strings or exception messages may
# contain attacker-controlled values in free-form text.
SENSITIVE_KEYWORD_PATTERN = re.compile(
    r"(?i)(?:password|passwd|pwd|token|secret|credential|api[-_]?key|authorization|bearer|private[-_]?key|client[-_]?secret|auth)"
)

# Regex for embedded URL credentials e.g. https://user:pass@host
URL_CREDENTIAL_PATTERN = re.compile(
    r"(://[^:/@\s]+:)([^@/\s]+)(@)",
    re.IGNORECASE,
)

# Regex for Bearer tokens e.g. Bearer abc123def
BEARER_PATTERN = re.compile(
    r"(\bBearer\s+)(\S+)",
    re.IGNORECASE,
)


def redact_string(val: str) -> str:
    """Redact embedded credentials, bearer tokens, or sensitive assignments in a string."""
    if not isinstance(val, str):
        return str(val)
    m_inline = INLINE_SECRET_PATTERN.match(val)
    if m_inline:
        return f"{m_inline.group(1)}[REDACTED]"
    m_assign = ASSIGNMENT_SECRET_PATTERN.match(val)
    if m_assign:
        return f"{m_assign.group(1)}[REDACTED]"
    val = URL_CREDENTIAL_PATTERN.sub(r"\1[REDACTED]\3", val)
    val = BEARER_PATTERN.sub(r"\1[REDACTED]", val)
    if "[REDACTED]" in val:
        return val
    if SENSITIVE_KEYWORD_PATTERN.search(val):
        return "[REDACTED]"
    return val


def _sanitize_serializable_value(value: Any) -> Any:
    """Sanitize strings in event/result payloads without altering the underlying business logic."""
    if isinstance(value, dict):
        return {str(k): _sanitize_serializable_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_serializable_value(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_serializable_value(v) for v in value)
    if isinstance(value, str):
        return redact_string(value)
    return value


def _sanitize_string_list(values: Optional[List[str]]) -> List[str]:
    """Return a redacted copy of a list of string values without mutating the original list."""
    if not isinstance(values, list):
        return []
    return [redact_string(v) if isinstance(v, str) else v for v in values]


def _sanitize_event_dict(event: Event) -> Event:
    """Return a sanitized copy of an Event, leaving the original object untouched."""
    if not isinstance(event, Event):
        return event

    ev = asdict(event)
    ev["command_line"] = redact_command_line(ev.get("command_line")) if ev.get("command_line") else None
    ev["risk_reasons"] = _sanitize_string_list(ev.get("risk_reasons", []))
    ev["indicators"] = _sanitize_string_list(ev.get("indicators", []))
    ev["metadata"] = _sanitize_serializable_value(ev.get("metadata", {}))
    return Event(**ev)


def _sanitize_decision(decision: ExecutionDecision) -> ExecutionDecision:
    """Return a sanitized copy of an ExecutionDecision without mutating the original object."""
    if not isinstance(decision, ExecutionDecision):
        return decision

    dec = asdict(decision)
    dec["reasons"] = _sanitize_string_list(dec.get("reasons", []))
    dec["indicators"] = _sanitize_string_list(dec.get("indicators", []))
    dec["error"] = redact_string(dec["error"]) if isinstance(dec.get("error"), str) else dec.get("error")
    return ExecutionDecision(**dec)


def redact_command_line(cmdline: Optional[List[str]]) -> List[str]:
    """
    Sanitize command-line arguments to prevent credential or secret leakage.
    Redacts:
    - Values following sensitive flags (e.g., -p, --password, --token, --api-key).
    - Inline assignments (e.g., --password=secret, API_KEY=secret).
    - URL credentials (e.g., http://user:pass@host).
    - Bearer tokens.
    """
    if not isinstance(cmdline, list):
        return []

    redacted: List[str] = []
    redact_next = False

    for arg in cmdline:
        if not isinstance(arg, str):
            redacted.append(str(arg))
            redact_next = False
            continue

        if redact_next:
            redacted.append("[REDACTED]")
            redact_next = False
            continue

        clean_arg = arg.strip()
        lower_arg = clean_arg.lower()

        if lower_arg in SENSITIVE_FLAGS:
            redacted.append(arg)
            redact_next = True
            continue

        redacted.append(redact_string(arg))

    return redacted


@dataclass
class ExecutionServiceResult:
    """
    Structured outcome returned by ControlledExecutionService.
    Distinguishes validation failures, policy denials, dry-run simulations,
    gate blocks, completed executions, timeouts, launch failures, and service errors.
    """
    request_id: str
    status: str
    executed: bool = False
    decision: Optional[ExecutionDecision] = None
    launch_result: Optional[LaunchResult] = None
    event: Optional[Event] = None
    events: List[Event] = field(default_factory=list)
    error: Optional[str] = None
    reasons: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        """Return sanitized copies so live objects do not leak raw sensitive information."""
        self.decision = _sanitize_decision(self.decision) if self.decision is not None else None
        self.event = _sanitize_event_dict(self.event) if self.event is not None else None
        self.events = [_sanitize_event_dict(e) for e in self.events]
        self.reasons = _sanitize_string_list(self.reasons)
        self.error = redact_string(self.error) if isinstance(self.error, str) else self.error

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to a JSON-serializable dictionary."""
        payload = {
            "request_id": self.request_id,
            "status": self.status,
            "executed": self.executed,
            "decision": self.decision.to_dict() if self.decision else None,
            "launch_result": self.launch_result.to_dict() if self.launch_result else None,
            "event": self.event.to_dict() if self.event else None,
            "events": [e.to_dict() for e in self.events],
            "error": self.error,
            "reasons": list(self.reasons),
            "timestamp": self.timestamp,
        }
        return _sanitize_serializable_value(payload)


class ControlledExecutionService:
    """
    Isolated service layer that coordinates controlled execution requests with
    the project's event, alert, and security-audit infrastructure.

    Safety Guarantees:
    - Mandatory defaults: dry_run=True, allow_active_execution=False, interception_enabled=False.
    - Process creation requires both explicit configuration AND policy authorization.
    - Fails closed on invalid requests, policy exceptions, or configuration errors.
    - Never intercepts arbitrary operating-system process creation.
    - Passive monitoring remains completely observational and decoupled.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: str = "config/config.json",
        policy: Optional[ExecutionPolicy] = None,
        launcher: Optional[ControlledLauncher] = None,
        alert_handler: Optional[Callable[[str], Any]] = None,
        event_handler: Optional[Callable[[Event], Any]] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self._config_valid = True
        self._config_error: Optional[str] = None

        if config is not None:
            if not isinstance(config, dict):
                self._config_valid = False
                self._config_error = "Configuration must be a dictionary"
                self.config: Dict[str, Any] = {}
            else:
                self.config = config
        else:
            try:
                self.config = load_execution_config(config_path)
            except Exception as e:
                self._config_valid = False
                self._config_error = f"Failed to load configuration: {type(e).__name__}"
                self.config = {}

        # Enforce fail-closed safety defaults
        dry_run_val = self.config.get("dry_run", True)
        self.dry_run: bool = dry_run_val if isinstance(dry_run_val, bool) else True

        interception_val = self.config.get("interception_enabled", False)
        self.interception_enabled: bool = (
            interception_val if isinstance(interception_val, bool) else False
        )

        launcher_cfg = self.config.get("launcher", {})
        if not isinstance(launcher_cfg, dict):
            launcher_cfg = {}
        allow_active_val = launcher_cfg.get("allow_active_execution", False)
        self.allow_active_execution: bool = (
            allow_active_val if isinstance(allow_active_val, bool) else False
        )

        self.logger: logging.Logger = (
            logger if logger is not None else logging.getLogger("endpoint_monitor")
        )
        self.alert_handler: Callable[[str], Any] = (
            alert_handler if alert_handler is not None else show_alert
        )
        self.event_handler: Optional[Callable[[Event], Any]] = event_handler

        # Policy initialization
        try:
            self.policy: Optional[ExecutionPolicy] = (
                policy if policy is not None else ExecutionPolicy(config=self.config, config_path=config_path)
            )
        except Exception as e:
            self.policy = None
            self._config_valid = False
            self._config_error = f"Failed to initialize ExecutionPolicy: {type(e).__name__}"

        # Launcher initialization
        try:
            self.launcher: Optional[ControlledLauncher] = (
                launcher
                if launcher is not None
                else ControlledLauncher(policy=self.policy, config=self.config, config_path=config_path)
            )
        except Exception as e:
            self.launcher = None
            self._config_valid = False
            self._config_error = f"Failed to initialize ControlledLauncher: {type(e).__name__}"

        # Bounded deduplication cache for alerts.
        # Stores (request_id, event_type) tuples up to _ALERT_CACHE_MAX_SIZE entries.
        # Oldest entries are evicted when the limit is reached.
        _ALERT_CACHE_MAX_SIZE = 4096
        self._alert_cache_max_size: int = _ALERT_CACHE_MAX_SIZE
        # Use a deque as an ordered ring so we can evict the oldest entry.
        self._alert_cache_order: Deque[Tuple[str, str]] = collections.deque()
        self._alert_cache_set: set = set()
        # Lock protects only cache mutation, not external alert delivery.
        self._alert_cache_lock: threading.Lock = threading.Lock()

    def clear_alert_cache(self) -> None:
        """Clear the alert deduplication cache."""
        with self._alert_cache_lock:
            self._alert_cache_order.clear()
            self._alert_cache_set.clear()

    def _create_event(
        self,
        event_type: str,
        request_id: str,
        executable: str,
        command_line: Optional[List[str]],
        severity: str = "LOW",
        pid: Optional[int] = None,
        ppid: Optional[int] = None,
        username: Optional[str] = None,
        risk_score: int = 0,
        risk_level: str = "LOW",
        indicators: Optional[List[str]] = None,
        reasons: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Event:
        """Construct a standardized security Event with sanitized attributes."""
        redacted_cmd = redact_command_line(command_line) if command_line else None
        proc_name = os.path.basename(executable) if executable else None

        meta = dict(metadata) if metadata else {}
        meta["request_id"] = request_id
        if executable:
            meta["executable"] = redact_string(os.path.basename(executable))

        sanitized_meta = {
            key: redact_string(str(value)) if isinstance(value, str) else value
            for key, value in meta.items()
        }
        sanitized_reasons = _sanitize_string_list(list(reasons) if reasons else [])

        return Event(
            event_type=event_type,
            source="controlled_execution_service",
            severity=severity,
            pid=pid,
            ppid=ppid,
            process_name=proc_name,
            username=username,
            command_line=redacted_cmd,
            indicators=_sanitize_string_list(list(indicators) if indicators else []),
            risk_score=risk_score,
            risk_level=risk_level,
            risk_reasons=sanitized_reasons,
            metadata=sanitized_meta,
        )

    def _emit_event(self, event: Event) -> None:
        """Safely dispatch an event to the registered event handler."""
        if self.event_handler:
            try:
                self.event_handler(event)
            except Exception as e:
                self._safe_log_error(f"Event handler failed for event {event.event_id}: {e}")

    def _maybe_send_alert(self, request_id: str, event_type: str, message: str) -> None:
        """
        Deliver alert through alert handler with bounded, thread-safe deduplication.

        The deduplication lock is held only during cache mutation, not during
        external alert delivery, to avoid holding the lock over slow I/O.
        Alert delivery failure is logged without raising, retrying, or altering
        any execution state.
        """
        alert_key = (request_id, event_type)

        # Check and update cache under lock.
        should_send = False
        with self._alert_cache_lock:
            if alert_key not in self._alert_cache_set:
                # Evict oldest entry if at capacity.
                if len(self._alert_cache_order) >= self._alert_cache_max_size:
                    oldest = self._alert_cache_order.popleft()
                    self._alert_cache_set.discard(oldest)
                self._alert_cache_order.append(alert_key)
                self._alert_cache_set.add(alert_key)
                should_send = True

        # Deliver outside the lock.
        if should_send:
            try:
                if self.alert_handler:
                    self.alert_handler(message)
            except Exception as e:
                self._safe_log_error(
                    f"Alert delivery failed for request {request_id} ({event_type}): "
                    f"{type(e).__name__}"
                )

    def _safe_log_info(self, message: str) -> None:
        """Log info message catching any logging infrastructure errors."""
        try:
            self.logger.info(message)
        except Exception:
            pass

    def _safe_log_warning(self, message: str) -> None:
        """Log warning message catching any logging infrastructure errors."""
        try:
            self.logger.warning(message)
        except Exception:
            pass

    def _safe_log_error(self, message: str) -> None:
        """Log error message catching any logging infrastructure errors."""
        try:
            self.logger.error(message)
        except Exception:
            pass

    def execute(
        self,
        request: ExecutionRequest,
        timeout: Optional[float] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> ExecutionServiceResult:
        """
        Process an explicit execution request through validation, policy gating,
        safety defaults, launcher dispatch, event emission, and audit logging.

        Fails closed on any validation, policy, configuration, or initialization error.
        Subprocess creation requires both allow_active_execution=True and policy ALLOW.
        """
        events_list: List[Event] = []

        # 1. Request intake & type validation
        if not isinstance(request, ExecutionRequest):
            err = f"Invalid request type: expected ExecutionRequest, got {type(request).__name__}"
            self._safe_log_warning(f"[SERVICE] REJECTED request: {err}")
            event = self._create_event(
                event_type=ExecutionEventType.REJECTED,
                request_id="",
                executable="",
                command_line=[],
                severity="HIGH",
                reasons=[err],
                metadata={"error": err},
            )
            self._emit_event(event)
            return ExecutionServiceResult(
                request_id="",
                status=ExecutionServiceStatus.VALIDATION_FAILED,
                executed=False,
                event=event,
                events=[event],
                error=err,
                reasons=[err],
            )

        # 2. Request schema and data validation
        is_valid, val_err = request.validate()
        if not is_valid:
            err = val_err or "Request validation failed"
            safe_executable = redact_string(request.executable)
            self._safe_log_warning(
                f"[SERVICE] REJECTED request {request.request_id} for '{safe_executable}': {redact_string(err)}"
            )
            event = self._create_event(
                event_type=ExecutionEventType.REJECTED,
                request_id=request.request_id,
                executable=request.executable,
                command_line=request.command_line,
                username=request.username,
                ppid=request.parent_pid,
                severity="HIGH",
                reasons=[err],
                metadata={"error": err, "request_id": request.request_id},
            )
            self._emit_event(event)
            return ExecutionServiceResult(
                request_id=request.request_id,
                status=ExecutionServiceStatus.VALIDATION_FAILED,
                executed=False,
                event=event,
                events=[event],
                error=err,
                reasons=[err],
            )

        # 3. Fail-closed configuration and component health check
        if not self._config_valid or self.policy is None or self.launcher is None:
            err = self._config_error or "Service configuration or required components invalid"
            self._safe_log_error(
                f"[SERVICE] Service error for request {request.request_id}: {err}"
            )
            event = self._create_event(
                event_type=ExecutionEventType.ERROR,
                request_id=request.request_id,
                executable=request.executable,
                command_line=request.command_line,
                username=request.username,
                ppid=request.parent_pid,
                severity="HIGH",
                reasons=[err],
                metadata={"error": err, "request_id": request.request_id},
            )
            self._emit_event(event)
            return ExecutionServiceResult(
                request_id=request.request_id,
                status=ExecutionServiceStatus.SERVICE_ERROR,
                executed=False,
                event=event,
                events=[event],
                error=err,
                reasons=[err],
            )

        # 4. Policy evaluation
        try:
            decision = self.policy.evaluate(request)
        except Exception as e:
            # Log only the exception class name, not the full exception string,
            # to avoid leaking untrusted content (e.g., from user-supplied paths).
            exc_class = type(e).__name__
            err = f"Policy evaluation error: {exc_class}"
            self._safe_log_error(
                f"[SERVICE] Policy evaluation exception for request {request.request_id} "
                f"(executable class: {type(request).__name__}): {exc_class}"
            )
            event = self._create_event(
                event_type=ExecutionEventType.ERROR,
                request_id=request.request_id,
                executable=request.executable,
                command_line=request.command_line,
                username=request.username,
                ppid=request.parent_pid,
                severity="HIGH",
                reasons=[err],
                metadata={"error": err, "request_id": request.request_id},
            )
            self._emit_event(event)
            return ExecutionServiceResult(
                request_id=request.request_id,
                status=ExecutionServiceStatus.SERVICE_ERROR,
                executed=False,
                event=event,
                events=[event],
                error=err,
                reasons=[err],
            )

        # 5. Strict policy output validation.
        # A malformed or unknown decision value is a SERVICE_ERROR, not a policy denial,
        # to prevent misclassification from hiding bugs in the policy engine.
        _VALID_DECISION_VALUES = frozenset({DecisionStatus.ALLOW, DecisionStatus.BLOCK})

        if not isinstance(decision, ExecutionDecision):
            err = (
                f"Policy returned invalid object type: {type(decision).__name__}; "
                "expected ExecutionDecision. Failing closed."
            )
            self._safe_log_error(
                f"[SERVICE] Malformed policy output for request {request.request_id}: "
                f"{type(decision).__name__}"
            )
            event = self._create_event(
                event_type=ExecutionEventType.ERROR,
                request_id=request.request_id,
                executable=request.executable,
                command_line=request.command_line,
                username=request.username,
                ppid=request.parent_pid,
                severity="HIGH",
                reasons=[err],
                metadata={"error": err, "request_id": request.request_id},
            )
            self._emit_event(event)
            return ExecutionServiceResult(
                request_id=request.request_id,
                status=ExecutionServiceStatus.SERVICE_ERROR,
                executed=False,
                event=event,
                events=[event],
                error=err,
                reasons=[err],
            )

        if decision.decision not in _VALID_DECISION_VALUES:
            err = (
                f"Policy returned unrecognized decision value. "
                "Failing closed."
            )
            self._safe_log_error(
                f"[SERVICE] Unrecognized policy decision for request {request.request_id}; "
                "failing closed."
            )
            event = self._create_event(
                event_type=ExecutionEventType.ERROR,
                request_id=request.request_id,
                executable=request.executable,
                command_line=request.command_line,
                username=request.username,
                ppid=request.parent_pid,
                severity="HIGH",
                reasons=[err],
                metadata={"error": err, "request_id": request.request_id},
            )
            self._emit_event(event)
            return ExecutionServiceResult(
                request_id=request.request_id,
                status=ExecutionServiceStatus.SERVICE_ERROR,
                executed=False,
                event=event,
                events=[event],
                error=err,
                reasons=[err],
            )

        # 5b. Normal BLOCK decision from a valid, well-formed ExecutionDecision.
        if decision.decision != DecisionStatus.ALLOW:
            reasons = list(decision.reasons) if decision.reasons else ["Policy decision is BLOCK"]
            risk_score = decision.risk_score
            risk_level = decision.risk_level
            indicators = list(decision.indicators) if decision.indicators else []

            # Log only safe scalar fields; do not log raw policy reasons which
            # may contain untrusted user-supplied path fragments or command arguments.
            self._safe_log_warning(
                f"[SERVICE] POLICY DENIED request {request.request_id}. "
                f"Score: {risk_score}, Level: {risk_level}, "
                f"Reasons count: {len(reasons)}"
            )

            event = self._create_event(
                event_type=ExecutionEventType.DENIED,
                request_id=request.request_id,
                executable=request.executable,
                command_line=request.command_line,
                username=request.username,
                ppid=request.parent_pid,
                severity=risk_level if risk_level in ("LOW", "MEDIUM", "HIGH") else "HIGH",
                risk_score=risk_score,
                risk_level=risk_level,
                indicators=indicators,
                reasons=reasons,
                metadata={
                    "request_id": request.request_id,
                    "policy_decision": DecisionStatus.BLOCK,
                    "dry_run": self.dry_run,
                    "executed": False,
                },
            )
            self._emit_event(event)

            alert_msg = (
                f"Execution blocked for '{os.path.basename(request.executable)}' "
                f"(Request {request.request_id}). "
                f"Risk Score: {risk_score}, Level: {risk_level}. "
                f"Reason count: {len(reasons)}"
            )
            self._maybe_send_alert(request.request_id, ExecutionEventType.DENIED, alert_msg)

            return ExecutionServiceResult(
                request_id=request.request_id,
                status=ExecutionServiceStatus.POLICY_DENIED,
                executed=False,
                decision=decision,
                event=event,
                events=[event],
                reasons=reasons,
            )

        # 6. Safety Gate 1: Dry-Run mode
        if self.dry_run:
            self._safe_log_info(
                f"[SERVICE] DRY-RUN: Execution permitted by policy for request {request.request_id} "
                f"('{request.executable}'), but process launch suppressed by dry-run mode."
            )

            decision.dry_run = True
            decision.executed = False

            event = self._create_event(
                event_type=ExecutionEventType.DRY_RUN,
                request_id=request.request_id,
                executable=request.executable,
                command_line=request.command_line,
                username=request.username,
                ppid=request.parent_pid,
                severity="LOW",
                risk_score=decision.risk_score,
                risk_level=decision.risk_level,
                indicators=decision.indicators,
                reasons=["Execution permitted by policy but suppressed by dry-run mode"],
                metadata={
                    "request_id": request.request_id,
                    "policy_decision": DecisionStatus.ALLOW,
                    "dry_run": True,
                    "executed": False,
                    "simulated": True,
                },
            )
            self._emit_event(event)

            return ExecutionServiceResult(
                request_id=request.request_id,
                status=ExecutionServiceStatus.DRY_RUN,
                executed=False,
                decision=decision,
                event=event,
                events=[event],
                reasons=["Dry-run mode active; execution simulated"],
            )

        # 7. Safety Gate 2: Active execution gate
        if not self.allow_active_execution:
            self._safe_log_warning(
                f"[SERVICE] GATE BLOCKED: Request {request.request_id} "
                f"approved by policy, but allow_active_execution is false."
            )

            decision.dry_run = False
            decision.executed = False

            reasons = ["Active execution is disabled in configuration"]
            event = self._create_event(
                event_type=ExecutionEventType.GATE_BLOCKED,
                request_id=request.request_id,
                executable=request.executable,
                command_line=request.command_line,
                username=request.username,
                ppid=request.parent_pid,
                severity="MEDIUM",
                risk_score=decision.risk_score,
                risk_level=decision.risk_level,
                indicators=decision.indicators,
                reasons=reasons,
                metadata={
                    "request_id": request.request_id,
                    "policy_decision": DecisionStatus.ALLOW,
                    "dry_run": False,
                    "allow_active_execution": False,
                    "executed": False,
                },
            )
            self._emit_event(event)

            alert_msg = (
                f"Execution gated for '{os.path.basename(request.executable)}' "
                f"(Request {request.request_id}): Active execution disabled."
            )
            self._maybe_send_alert(request.request_id, ExecutionEventType.GATE_BLOCKED, alert_msg)

            return ExecutionServiceResult(
                request_id=request.request_id,
                status=ExecutionServiceStatus.GATE_BLOCKED,
                executed=False,
                decision=decision,
                event=event,
                events=[event],
                reasons=reasons,
            )

        # 7b. Interception-enabled gate.
        # interception_enabled=False (default) means this service's dispatch interface
        # is disabled and no process launches will be dispatched. It does NOT implement
        # any OS-wide interception, shell hooks, or terminal monkey-patching.
        # interception_enabled=True permits the service dispatch interface.
        # Missing or non-boolean values default to False (fail closed).
        if not self.interception_enabled:
            self._safe_log_warning(
                f"[SERVICE] INTERCEPTION BLOCKED: Request {request.request_id} "
                f"blocked because interception_enabled is false."
            )

            decision.executed = False
            reasons_interception = ["Service dispatch interface is disabled (interception_enabled=false)"]
            interception_event = self._create_event(
                event_type=ExecutionEventType.INTERCEPTION_BLOCKED,
                request_id=request.request_id,
                executable=request.executable,
                command_line=request.command_line,
                username=request.username,
                ppid=request.parent_pid,
                severity="MEDIUM",
                risk_score=decision.risk_score,
                risk_level=decision.risk_level,
                indicators=decision.indicators,
                reasons=reasons_interception,
                metadata={
                    "request_id": request.request_id,
                    "policy_decision": DecisionStatus.ALLOW,
                    "interception_enabled": False,
                    "executed": False,
                },
            )
            self._emit_event(interception_event)
            return ExecutionServiceResult(
                request_id=request.request_id,
                status=ExecutionServiceStatus.GATE_BLOCKED,
                executed=False,
                decision=decision,
                event=interception_event,
                events=[interception_event],
                reasons=reasons_interception,
            )

        # 8. All gates pass & policy ALLOW -> Invoke ControlledLauncher.
        # Emit LAUNCH_ATTEMPTED before calling the launcher (pre-spawn audit record).
        # LAUNCHED is emitted only after confirming process creation succeeded.
        attempt_event = self._create_event(
            event_type=ExecutionEventType.LAUNCH_ATTEMPTED,
            request_id=request.request_id,
            executable=request.executable,
            command_line=request.command_line,
            username=request.username,
            ppid=request.parent_pid,
            severity="LOW",
            risk_score=decision.risk_score,
            risk_level=decision.risk_level,
            indicators=decision.indicators,
            reasons=["Process launch attempted"],
            metadata={
                "request_id": request.request_id,
                "policy_decision": DecisionStatus.ALLOW,
                "dry_run": False,
                "allow_active_execution": True,
                "interception_enabled": True,
            },
        )
        self._emit_event(attempt_event)
        events_list.append(attempt_event)

        try:
            launch_result = self.launcher.launch(
                request=request,
                timeout=timeout,
                capture_output=True,
                env=env,
            )
        except Exception as e:
            # Log only the exception class name; the message may contain
            # untrusted path fragments or OS error details.
            exc_class = type(e).__name__
            err = f"Launcher raised {exc_class} during process creation"
            self._safe_log_error(
                f"[SERVICE] Launcher exception for request {request.request_id}: {exc_class}"
            )
            error_event = self._create_event(
                event_type=ExecutionEventType.ERROR,
                request_id=request.request_id,
                executable=request.executable,
                command_line=request.command_line,
                username=request.username,
                ppid=request.parent_pid,
                severity="HIGH",
                reasons=[err],
                metadata={"error": err, "error_type": exc_class, "request_id": request.request_id},
            )
            self._emit_event(error_event)
            events_list.append(error_event)

            return ExecutionServiceResult(
                request_id=request.request_id,
                status=ExecutionServiceStatus.SERVICE_ERROR,
                executed=False,
                decision=decision,
                event=error_event,
                events=events_list,
                error=err,
                reasons=[err],
            )

        # Emit LAUNCHED only when Popen confirmed the child process was created.
        if launch_result.executed:
            launched_event = self._create_event(
                event_type=ExecutionEventType.LAUNCHED,
                request_id=request.request_id,
                executable=request.executable,
                command_line=request.command_line,
                username=request.username,
                ppid=request.parent_pid,
                pid=launch_result.pid,
                severity="LOW",
                risk_score=decision.risk_score,
                risk_level=decision.risk_level,
                indicators=decision.indicators,
                reasons=["Child process created successfully"],
                metadata={
                    "request_id": request.request_id,
                    "pid": launch_result.pid,
                    "policy_decision": DecisionStatus.ALLOW,
                },
            )
            self._emit_event(launched_event)
            events_list.append(launched_event)

        # 9. Translate LaunchResult into service status, event, and alert
        if launch_result.timed_out:
            status = ExecutionServiceStatus.TIMEOUT
            event_type = ExecutionEventType.TIMEOUT
            severity = "HIGH"
            outcome_reasons = [
                f"Process execution timed out after {launch_result.execution_time_seconds:.2f}s"
            ]
        elif not launch_result.executed:
            status = ExecutionServiceStatus.FAILED
            event_type = ExecutionEventType.FAILED
            severity = "HIGH"
            outcome_reasons = [launch_result.error or "Process execution failed to start"]
        elif launch_result.returncode != 0:
            status = ExecutionServiceStatus.FAILED
            event_type = ExecutionEventType.FAILED
            severity = "MEDIUM"
            outcome_reasons = [
                f"Process exited with non-zero return code {launch_result.returncode}"
            ]
        else:
            status = ExecutionServiceStatus.COMPLETED
            event_type = ExecutionEventType.COMPLETED
            severity = "LOW"
            outcome_reasons = ["Process execution completed successfully"]

        outcome_event = self._create_event(
            event_type=event_type,
            request_id=request.request_id,
            executable=request.executable,
            command_line=request.command_line,
            username=request.username,
            ppid=request.parent_pid,
            pid=launch_result.pid,
            severity=severity,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level,
            indicators=decision.indicators,
            reasons=outcome_reasons,
            metadata={
                "request_id": request.request_id,
                "policy_decision": DecisionStatus.ALLOW,
                "dry_run": False,
                "executed": launch_result.executed,
                "pid": launch_result.pid,
                "returncode": launch_result.returncode,
                "timed_out": launch_result.timed_out,
                "execution_time_seconds": launch_result.execution_time_seconds,
                "stdout_truncated": launch_result.stdout_truncated,
                "stderr_truncated": launch_result.stderr_truncated,
                "error": launch_result.error,
            },
        )
        self._emit_event(outcome_event)
        events_list.append(outcome_event)

        # Alert for non-completed or exceptional outcomes
        if status in (ExecutionServiceStatus.TIMEOUT, ExecutionServiceStatus.FAILED):
            alert_msg = (
                f"Execution outcome alert: {status} for '{request.executable}' "
                f"(PID: {launch_result.pid}, returncode: {launch_result.returncode}). "
                f"Reason: {', '.join(outcome_reasons)}"
            )
            self._maybe_send_alert(request.request_id, event_type, alert_msg)

        # Log only safe scalar diagnostics; do not include executable path
        # or return-code string from child process stdout/stderr.
        self._safe_log_info(
            f"[SERVICE] Outcome {status} for request {request.request_id}: "
            f"executed={launch_result.executed}, "
            f"returncode={launch_result.returncode}, "
            f"timed_out={launch_result.timed_out}"
        )

        return ExecutionServiceResult(
            request_id=request.request_id,
            status=status,
            executed=launch_result.executed,
            decision=decision,
            launch_result=launch_result,
            event=outcome_event,
            events=events_list,
            error=launch_result.error,
            reasons=outcome_reasons,
        )
