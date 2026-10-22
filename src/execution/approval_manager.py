"""
Approval Manager Module (Phase 1 Enforcement Foundation).

Provides a concurrency-safe, bounded, and auditable approval manager for
intermediate-risk execution and network requests.

Guarantees:
- Unique request identifiers.
- Bounded pending-request capacity (fail-closed if full).
- Expiry and timeout handling.
- Duplicate request suppression.
- Explicit approve and deny operations.
- Single-use and narrowly scoped approval tokens (replay prevention).
- PID reuse and stale process identity protection.
- Safe shutdown behavior (automatic cancellation of pending requests).
"""

from collections import deque
from dataclasses import asdict, dataclass, field
import logging
import os
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Tuple
import uuid

from src.models.execution_request import ExecutionRequest, OperationType


logger = logging.getLogger("endpoint_monitor")


class ApprovalStatus:
    """Distinct lifecycle states of an approval request."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


class ApprovalCapacityExceededError(RuntimeError):
    """Raised when the approval queue has reached its configured capacity limit."""
    pass


@dataclass
class ApprovalRequest:
    """
    Structured record representing a pending, approved, denied, or consumed authorization.
    """
    approval_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = ""
    operation_type: str = OperationType.PROCESS
    identity_key: str = ""
    executable: str = ""
    command_line: List[str] = field(default_factory=list)
    pid: Optional[int] = None
    process_create_time: Optional[float] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: Optional[str] = None
    risk_score: int = 0
    risk_level: str = "MEDIUM"
    reasons: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    status: str = ApprovalStatus.PENDING
    decided_by: Optional[str] = None
    decision_reason: Optional[str] = None
    decided_at: Optional[float] = None
    single_use_token: Optional[str] = None
    consumed: bool = False
    consumed_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self, now: Optional[float] = None) -> bool:
        """Check if request has timed out."""
        current_time = now if now is not None else time.time()
        return current_time >= self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Convert approval record to dictionary."""
        return asdict(self)


def _compute_identity_key(req: ExecutionRequest) -> str:
    """
    Compute a deterministic scoping key for duplicate suppression and identity matching.
    """
    if req.operation_type == OperationType.NETWORK:
        remote_ip = (req.remote_ip or "").strip().lower()
        remote_port = req.remote_port or 0
        proto = (req.protocol or "TCP").upper()
        pid = req.process_id or 0
        return f"net:{remote_ip}:{remote_port}:{proto}:{pid}"
    else:
        exe_name = os.path.basename(req.executable).lower() if req.executable else ""
        pid = req.process_id if req.process_id is not None else ""
        create_time = req.process_create_time if req.process_create_time is not None else ""
        cmdline_str = " ".join(req.command_line) if req.command_line else ""
        return f"proc:{exe_name}:{pid}:{create_time}:{cmdline_str}"


class ApprovalManager:
    """
    Thread-safe coordinator for execution and network operation approvals.
    """

    def __init__(
        self,
        default_timeout_seconds: float = 60.0,
        max_pending: int = 100,
        logger_instance: Optional[logging.Logger] = None,
    ) -> None:
        self.default_timeout_seconds = max(0.01, float(default_timeout_seconds))
        self.max_pending = max(1, int(max_pending))
        self.logger = logger_instance if logger_instance is not None else logger

        self._lock = threading.RLock()
        self._pending: Dict[str, ApprovalRequest] = {}
        self._approved: Dict[str, ApprovalRequest] = {}
        self._identity_to_approval_id: Dict[str, str] = {}
        self._history: Deque[ApprovalRequest] = deque(maxlen=500)
        self._is_shutdown = False

    def _cleanup_expired_locked(self, now: Optional[float] = None) -> None:
        """Sweep expired requests and move them to history (called under lock)."""
        current_time = now if now is not None else time.time()
        expired_ids = [
            appr_id
            for appr_id, req in self._pending.items()
            if req.is_expired(current_time)
        ]
        for appr_id in expired_ids:
            req = self._pending.pop(appr_id)
            req.status = ApprovalStatus.EXPIRED
            req.decided_by = "timeout"
            req.decision_reason = "Approval request expired without response"
            req.decided_at = current_time
            self._identity_to_approval_id.pop(req.identity_key, None)
            self._history.append(req)
            self.logger.info(f"Approval request {appr_id} expired and removed from pending queue.")

        expired_approved = [
            appr_id
            for appr_id, req in self._approved.items()
            if req.is_expired(current_time)
        ]
        for appr_id in expired_approved:
            req = self._approved.pop(appr_id)
            req.status = ApprovalStatus.EXPIRED
            req.decided_by = "timeout"
            req.decision_reason = "Approved request expired before single-use token was consumed"
            req.decided_at = current_time
            self._history.append(req)
            self.logger.info(f"Approved request {appr_id} expired and removed from approved queue.")

    def create_request(
        self,
        request: ExecutionRequest,
        risk_score: int,
        risk_level: str = "MEDIUM",
        reasons: Optional[List[str]] = None,
        timeout_seconds: Optional[float] = None,
    ) -> ApprovalRequest:
        """
        Create a new approval request or return an existing active pending request
        (duplicate suppression).
        """
        with self._lock:
            if self._is_shutdown:
                raise RuntimeError("Cannot submit approval request: ApprovalManager is shut down")

            self._cleanup_expired_locked()

            identity_key = _compute_identity_key(request)

            # Duplicate suppression: if an identical pending request already exists and is active, return it
            existing_id = self._identity_to_approval_id.get(identity_key)
            if existing_id and existing_id in self._pending:
                existing_req = self._pending[existing_id]
                if existing_req.status == ApprovalStatus.PENDING and not existing_req.is_expired():
                    self.logger.debug(
                        f"Duplicate approval request detected for {identity_key}; reusing existing {existing_id}"
                    )
                    return existing_req

            # Bounded capacity check
            if len(self._pending) >= self.max_pending:
                err_msg = f"Approval queue capacity exceeded ({len(self._pending)}/{self.max_pending})"
                self.logger.warning(err_msg)
                raise ApprovalCapacityExceededError(err_msg)

            timeout = timeout_seconds if timeout_seconds is not None else self.default_timeout_seconds
            now = time.time()
            appr = ApprovalRequest(
                approval_id=str(uuid.uuid4()),
                request_id=request.request_id,
                operation_type=request.operation_type,
                identity_key=identity_key,
                executable=request.executable,
                command_line=list(request.command_line),
                pid=request.process_id or request.parent_pid,
                process_create_time=request.process_create_time,
                remote_ip=request.remote_ip,
                remote_port=request.remote_port,
                protocol=request.protocol,
                risk_score=risk_score,
                risk_level=risk_level,
                reasons=list(reasons) if reasons else [],
                created_at=now,
                expires_at=now + timeout,
                status=ApprovalStatus.PENDING,
                metadata=dict(request.metadata),
            )

            self._pending[appr.approval_id] = appr
            self._identity_to_approval_id[identity_key] = appr.approval_id
            self.logger.info(
                f"Created approval request {appr.approval_id} for {identity_key} (timeout: {timeout}s)"
            )
            return appr

    def approve(
        self,
        approval_id: str,
        approver: str = "user",
        reason: str = "Approved by operator",
    ) -> Tuple[bool, Optional[ApprovalRequest], Optional[str]]:
        """
        Explicitly approve a pending request. Issues a single-use authorization token.
        """
        with self._lock:
            if self._is_shutdown:
                return False, None, "ApprovalManager is shut down"

            self._cleanup_expired_locked()

            req = self._pending.get(approval_id)
            if not req:
                # Check history to provide accurate failure reason (e.g. expired or denied)
                for h in self._history:
                    if h.approval_id == approval_id:
                        if h.status == ApprovalStatus.EXPIRED:
                            return False, h, "Cannot approve: approval request has expired"
                        elif h.status == ApprovalStatus.DENIED:
                            return False, h, f"Cannot approve: request was already denied ({h.decision_reason})"
                        elif h.status == ApprovalStatus.CONSUMED:
                            return False, h, "Cannot approve: request was already consumed"
                        else:
                            return False, h, f"Cannot approve: request is in status {h.status}"
                if approval_id in self._approved:
                    return False, self._approved[approval_id], "Request has already been approved"
                return False, None, f"Approval request '{approval_id}' not found in active pending queue"

            if req.status != ApprovalStatus.PENDING:
                return False, req, f"Cannot approve: request is already {req.status}"

            if req.is_expired():
                req.status = ApprovalStatus.EXPIRED
                self._pending.pop(approval_id, None)
                self._identity_to_approval_id.pop(req.identity_key, None)
                self._history.append(req)
                return False, req, "Cannot approve: approval request has expired"

            req.status = ApprovalStatus.APPROVED
            req.decided_by = approver
            req.decision_reason = reason
            req.decided_at = time.time()
            req.single_use_token = str(uuid.uuid4())

            # Transition out of pending into approved queue
            self._pending.pop(approval_id, None)
            self._identity_to_approval_id.pop(req.identity_key, None)
            self._approved[approval_id] = req

            self.logger.info(
                f"Approval request {approval_id} APPROVED by '{approver}'. Single-use token issued."
            )
            return True, req, None

    def deny(
        self,
        approval_id: str,
        approver: str = "user",
        reason: str = "Denied by operator",
    ) -> Tuple[bool, Optional[ApprovalRequest], Optional[str]]:
        """
        Explicitly deny a pending request.
        """
        with self._lock:
            if self._is_shutdown:
                return False, None, "ApprovalManager is shut down"

            self._cleanup_expired_locked()

            req = self._pending.pop(approval_id, None)
            if not req:
                if approval_id in self._approved:
                    req = self._approved.pop(approval_id)
                else:
                    for h in self._history:
                        if h.approval_id == approval_id:
                            if h.status == ApprovalStatus.EXPIRED:
                                return False, h, "Approval request has expired"
                            return False, h, f"Cannot deny: request is in status {h.status}"
                    return False, None, f"Approval request '{approval_id}' not found in active pending queue"

            self._identity_to_approval_id.pop(req.identity_key, None)

            if req.is_expired():
                req.status = ApprovalStatus.EXPIRED
                self._history.append(req)
                return False, req, "Request was already expired"

            req.status = ApprovalStatus.DENIED
            req.decided_by = approver
            req.decision_reason = reason
            req.decided_at = time.time()
            self._history.append(req)

            self.logger.info(f"Approval request {approval_id} DENIED by '{approver}': {reason}")
            return True, req, None

    def consume_approval(
        self,
        approval_id: str,
        single_use_token: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Consume a granted approval.
        Validates:
        - Request exists and status is APPROVED.
        - Has not already been consumed (replay prevention).
        - Has not expired.
        - Single-use token matches.
        - Process identity and creation time match (PID reuse protection).
        """
        with self._lock:
            self._cleanup_expired_locked()

            # Find the request either in approved or pending or history
            req = self._approved.get(approval_id) or self._pending.get(approval_id)
            if not req:
                for h in self._history:
                    if h.approval_id == approval_id:
                        req = h
                        break

            if not req:
                return False, f"Approval record '{approval_id}' not found"

            if req.consumed:
                return False, "Replay rejected: single-use approval token has already been consumed"

            if req.status != ApprovalStatus.APPROVED:
                return False, f"Cannot consume approval: record is in state '{req.status}', expected 'APPROVED'"

            if req.is_expired():
                req.status = ApprovalStatus.EXPIRED
                self._approved.pop(approval_id, None)
                self._pending.pop(approval_id, None)
                if req not in self._history:
                    self._history.append(req)
                return False, "Approval token has expired"

            if not req.single_use_token or req.single_use_token != single_use_token:
                return False, "Invalid single-use authorization token"

            # Context validation and PID reuse protection
            if context:
                # 1. PID match check
                if req.pid is not None and "pid" in context and context["pid"] is not None:
                    if int(context["pid"]) != int(req.pid):
                        return False, f"Scoping mismatch: context PID {context['pid']} does not match approved PID {req.pid}"

                # 2. PID reuse check via process create_time
                if req.process_create_time is not None and "create_time" in context and context["create_time"] is not None:
                    try:
                        ctx_create_time = float(context["create_time"])
                        req_create_time = float(req.process_create_time)
                        if abs(ctx_create_time - req_create_time) > 0.05:
                            return (
                                False,
                                f"PID reuse detected: process creation time ({ctx_create_time}) "
                                f"does not match authorized process creation time ({req_create_time})",
                            )
                    except (ValueError, TypeError):
                        return False, "PID reuse validation failed: invalid process creation time format"

                # 3. Executable path scope check
                if req.executable and "executable" in context and context["executable"]:
                    ctx_exe = os.path.basename(str(context["executable"])).lower()
                    req_exe = os.path.basename(req.executable).lower()
                    if ctx_exe != req_exe:
                        return False, f"Executable scope mismatch: '{ctx_exe}' does not match approved '{req_exe}'"

                # 4. Network destination IP, port, and protocol scope check
                if req.operation_type == OperationType.NETWORK or req.remote_ip is not None:
                    if req.remote_ip and "remote_ip" in context and context["remote_ip"]:
                        if str(context["remote_ip"]).strip().lower() != str(req.remote_ip).strip().lower():
                            return (
                                False,
                                f"Network destination IP scope mismatch: '{context['remote_ip']}' does not match approved '{req.remote_ip}'",
                            )
                    if req.remote_port is not None and "remote_port" in context and context["remote_port"] is not None:
                        if int(context["remote_port"]) != int(req.remote_port):
                            return (
                                False,
                                f"Network destination port scope mismatch: {context['remote_port']} does not match approved {req.remote_port}",
                            )
                    if req.protocol and "protocol" in context and context["protocol"]:
                        if str(context["protocol"]).upper() != str(req.protocol).upper():
                            return (
                                False,
                                f"Network protocol scope mismatch: '{context['protocol']}' does not match approved '{req.protocol}'",
                            )

            # Consume the approval token
            req.consumed = True
            req.consumed_at = time.time()
            req.status = ApprovalStatus.CONSUMED

            # Move from approved/pending to history
            self._approved.pop(approval_id, None)
            self._pending.pop(approval_id, None)
            self._identity_to_approval_id.pop(req.identity_key, None)
            self._history.append(req)

            self.logger.info(f"Approval request {approval_id} successfully CONSUMED.")
            return True, None

    def get_pending_requests(self) -> List[Dict[str, Any]]:
        """Return snapshot of current active pending requests."""
        with self._lock:
            self._cleanup_expired_locked()
            return [req.to_dict() for req in self._pending.values() if req.status == ApprovalStatus.PENDING]

    def get_history(self) -> List[Dict[str, Any]]:
        """Return historical approval decisions."""
        with self._lock:
            return [req.to_dict() for req in self._history]

    def get_request(self, approval_id: str) -> Optional[ApprovalRequest]:
        """Fetch request by ID."""
        with self._lock:
            self._cleanup_expired_locked()
            req = self._pending.get(approval_id) or self._approved.get(approval_id)
            if req:
                return req
            for h in self._history:
                if h.approval_id == approval_id:
                    return h
            return None

    def shutdown(self) -> None:
        """
        Safely shutdown approval manager: cancel all pending and approved requests with
        fail-closed DENIED status.
        """
        with self._lock:
            self._is_shutdown = True
            now = time.time()
            for appr_id, req in list(self._pending.items()):
                req.status = ApprovalStatus.DENIED
                req.decided_by = "service_shutdown"
                req.decision_reason = "Service shutdown with pending requests"
                req.decided_at = now
                self._history.append(req)
                self.logger.warning(
                    f"Approval request {appr_id} automatically DENIED due to service shutdown."
                )
            for appr_id, req in list(self._approved.items()):
                req.status = ApprovalStatus.DENIED
                req.decided_by = "service_shutdown"
                req.decision_reason = "Service shutdown with unconsumed approved requests"
                req.decided_at = now
                self._history.append(req)

            self._pending.clear()
            self._approved.clear()
            self._identity_to_approval_id.clear()
