"""
Privileged Service Foundation Module (Phase 1 Enforcement Foundation).

Implements the central security service architecture owning:
- Security policy configuration and threshold evaluation.
- Approval workflow coordination and single-use token lifecycle.
- Structured audit event logging and correlation.
- Subsystem health diagnostics and real-time status reporting.
- Local authenticated IPC endpoint for GUI and CLI consoles.
- Clear separation between requested decisions and actual OS kernel enforcement.
"""

from dataclasses import asdict
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from src.execution.approval_manager import ApprovalCapacityExceededError, ApprovalManager, ApprovalStatus
from src.execution.audit import SecurityAuditLogger
from src.execution.config import load_execution_config
from src.execution.ipc import LocalSocketIPCClient, LocalSocketIPCServer
from src.execution.policy import ExecutionPolicy
from src.execution.process_enforcement import ProcessEnforcementManager
from src.execution.wfp_enforcement import WFPEnforcementManager
from src.models.execution_request import (
    DecisionProvenance,
    DecisionStatus,
    EnforcementStatus,
    ExecutionDecision,
    ExecutionRequest,
    OperationType,
)


logger = logging.getLogger("endpoint_monitor")


class EndpointSecurityService:
    """
    Privileged core security service for Windows Endpoint Monitor.
    Coordinates security policies, approval queue, audit trails, and IPC listeners.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: str = "config/config.json",
        policy: Optional[ExecutionPolicy] = None,
        approval_manager: Optional[ApprovalManager] = None,
        audit_logger: Optional[SecurityAuditLogger] = None,
        ipc_port: int = 0,
        enable_ipc: bool = True,
        logger_instance: Optional[logging.Logger] = None,
    ) -> None:
        self.logger = logger_instance if logger_instance is not None else logger
        self.config_path = config_path
        self.config = config if config is not None else load_execution_config(config_path)

        # 1. Initialize Policy Engine
        self.policy: ExecutionPolicy = (
            policy if policy is not None else ExecutionPolicy(config=self.config, config_path=config_path)
        )

        # 2. Initialize Approval Manager
        appr_cfg = self.config.get("approval_manager", {})
        timeout_sec = appr_cfg.get("timeout_seconds", 60.0)
        max_pending = appr_cfg.get("max_pending", 100)
        self.approval_manager: ApprovalManager = (
            approval_manager
            if approval_manager is not None
            else ApprovalManager(
                default_timeout_seconds=timeout_sec,
                max_pending=max_pending,
                logger_instance=self.logger,
            )
        )

        # 3. Initialize Structured Audit Logger
        self.audit_logger: SecurityAuditLogger = (
            audit_logger if audit_logger is not None else SecurityAuditLogger(logger_instance=self.logger)
        )

        # 4. Initialize Process and Network Enforcement Subsystems
        self.process_manager = ProcessEnforcementManager(
            policy=self.policy,
            approval_manager=self.approval_manager,
            audit_logger=self.audit_logger,
            config=self.config,
            logger_instance=self.logger,
        )
        self.wfp_manager = WFPEnforcementManager(
            policy=self.policy,
            approval_manager=self.approval_manager,
            audit_logger=self.audit_logger,
            config=self.config,
            logger_instance=self.logger,
        )

        # 5. In-memory recent decisions buffer for query interfaces
        self._lock = threading.RLock()
        self._decision_history: List[Dict[str, Any]] = []
        self._max_history = 200

        # 6. Initialize IPC Server
        self.enable_ipc = enable_ipc
        self.ipc_port = ipc_port
        self.ipc_server: Optional[LocalSocketIPCServer] = None
        self._is_running = False

        if not self.policy._config_valid:
            self.audit_logger.health_tracker.update_policy_health(
                "UNHEALTHY", self.policy._config_error
            )

    def start(self) -> None:
        """Start the privileged service and its IPC server."""
        with self._lock:
            if self._is_running:
                return
            self._is_running = True

            if self.enable_ipc:
                self.ipc_server = LocalSocketIPCServer(
                    port=self.ipc_port,
                    logger_instance=self.logger,
                )
                self.ipc_server.start(handler_callback=self._handle_ipc_message)
                self.ipc_port = self.ipc_server.port
                self.audit_logger.health_tracker.update_ipc_health("HEALTHY", connected=True)

            self.logger.info("EndpointSecurityService started successfully.")

    def stop(self) -> None:
        """Gracefully stop the service and drain pending requests."""
        with self._lock:
            if not self._is_running:
                return
            self._is_running = False

            # Drain and cancel pending approval requests
            self.approval_manager.shutdown()

            # Clean up enforcement subsystems
            self.process_manager.close()
            self.wfp_manager.close()

            if self.ipc_server:
                self.ipc_server.stop()
                self.ipc_server = None
                self.audit_logger.health_tracker.update_ipc_health("STOPPED", connected=False)

            self.logger.info("EndpointSecurityService stopped.")

    def is_running(self) -> bool:
        return self._is_running

    def get_client(self) -> Optional[LocalSocketIPCClient]:
        """Return an authenticated client connected to this service's IPC listener."""
        with self._lock:
            if not self.ipc_server or not self.ipc_server.is_running():
                return None
            return LocalSocketIPCClient(
                port=self.ipc_server.port,
                auth_token=self.ipc_server.auth_token,
            )

    # -------------------------------------------------------------------------
    # Core Evaluation and Approval Workflow
    # -------------------------------------------------------------------------

    def submit_request(self, request: ExecutionRequest) -> ExecutionDecision:
        """
        Evaluate an execution or network request, determine policy decision,
        enqueue into approval manager if REQUIRE_APPROVAL, and log structured audit.
        """
        if request.operation_type == OperationType.NETWORK:
            approval_id = request.metadata.get("approval_id") if isinstance(request.metadata, dict) else None
            approval_token = request.metadata.get("approval_token") if isinstance(request.metadata, dict) else None
            decision = self.wfp_manager.evaluate_and_enforce_connection(
                remote_ip=request.remote_ip or "",
                remote_port=request.remote_port or 0,
                protocol=request.protocol or "TCP",
                direction=request.direction or "outbound",
                process_id=request.process_id,
                process_create_time=request.process_create_time,
                executable=request.executable,
                approval_id=approval_id,
                approval_token=approval_token,
            )
            # Record into recent decisions history
            with self._lock:
                rec = {
                    "request_id": request.request_id,
                    "operation_type": request.operation_type,
                    "target": f"{request.remote_ip}:{request.remote_port}",
                    "decision": decision.decision,
                    "enforcement_status": decision.enforcement_status,
                    "risk_score": decision.risk_score,
                    "risk_level": decision.risk_level,
                    "reasons": decision.reasons,
                    "provenance": decision.provenance,
                    "approval_id": decision.approval_id,
                    "timestamp": decision.timestamp,
                }
                self._decision_history.append(rec)
                if len(self._decision_history) > self._max_history:
                    self._decision_history.pop(0)

            # Update health tracker
            pending_list = self.approval_manager.get_pending_requests()
            self.audit_logger.health_tracker.update_approval_queue(
                size=len(pending_list),
                capacity=self.approval_manager.max_pending,
            )
            return decision

        # Step 1: Policy evaluation
        decision = self.policy.evaluate(request)

        # Step 2: Handle REQUIRE_APPROVAL workflow
        approval_details = None
        if decision.decision == DecisionStatus.REQUIRE_APPROVAL:
            try:
                appr_req = self.approval_manager.create_request(
                    request=request,
                    risk_score=decision.risk_score,
                    risk_level=decision.risk_level,
                    reasons=decision.reasons,
                )
                decision.approval_id = appr_req.approval_id
                decision.expires_at = appr_req.expires_at
                decision.enforcement_status = EnforcementStatus.PENDING_APPROVAL
                approval_details = {
                    "approval_id": appr_req.approval_id,
                    "status": appr_req.status,
                    "expires_at": appr_req.expires_at,
                }
            except ApprovalCapacityExceededError as e:
                # Fail closed when approval queue is full
                decision.decision = DecisionStatus.BLOCK
                decision.provenance = DecisionProvenance.FAIL_CLOSED
                decision.enforcement_status = EnforcementStatus.BLOCKED
                decision.error = f"Approval queue capacity exceeded: {e}"
                decision.reasons = [f"Fail-closed: {decision.error}"] + decision.reasons
        elif decision.decision == DecisionStatus.BLOCK:
            decision.enforcement_status = EnforcementStatus.BLOCKED
        elif decision.decision == DecisionStatus.ALLOW:
            decision.enforcement_status = EnforcementStatus.SIMULATED

        # Step 3: Record audit log
        self.audit_logger.record_decision(
            request=request,
            decision=decision,
            approval_details=approval_details,
        )

        # Step 4: Record into recent decisions history
        with self._lock:
            rec = {
                "request_id": request.request_id,
                "operation_type": request.operation_type,
                "target": request.executable if request.operation_type == OperationType.PROCESS else f"{request.remote_ip}:{request.remote_port}",
                "decision": decision.decision,
                "enforcement_status": decision.enforcement_status,
                "risk_score": decision.risk_score,
                "risk_level": decision.risk_level,
                "reasons": decision.reasons,
                "provenance": decision.provenance,
                "approval_id": decision.approval_id,
                "timestamp": decision.timestamp,
            }
            self._decision_history.append(rec)
            if len(self._decision_history) > self._max_history:
                self._decision_history.pop(0)

        # Update health tracker
        pending_list = self.approval_manager.get_pending_requests()
        self.audit_logger.health_tracker.update_approval_queue(
            size=len(pending_list),
            capacity=self.approval_manager.max_pending,
        )

        return decision

    def approve_request(
        self,
        approval_id: str,
        approver: str = "user",
        reason: str = "Approved by operator",
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Approve a pending approval request."""
        success, req, err = self.approval_manager.approve(approval_id, approver=approver, reason=reason)
        if success and req:
            # Update decision history record status
            with self._lock:
                for d in self._decision_history:
                    if d.get("approval_id") == approval_id:
                        d["decision"] = DecisionStatus.ALLOW
                        d["enforcement_status"] = EnforcementStatus.APPROVED
                        d["provenance"] = DecisionProvenance.APPROVAL_MANAGER
                        break

            public_record = req.to_dict()
            public_record.pop("single_use_token", None)
            return True, public_record, None
        return False, None, err

    def deny_request(
        self,
        approval_id: str,
        approver: str = "user",
        reason: str = "Denied by operator",
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Deny a pending approval request."""
        success, req, err = self.approval_manager.deny(approval_id, approver=approver, reason=reason)
        if success and req:
            with self._lock:
                for d in self._decision_history:
                    if d.get("approval_id") == approval_id:
                        d["decision"] = DecisionStatus.BLOCK
                        d["enforcement_status"] = EnforcementStatus.DENIED
                        d["provenance"] = DecisionProvenance.APPROVAL_MANAGER
                        break
            return True, req.to_dict(), None
        return False, None, err

    def get_health(self) -> Dict[str, Any]:
        """Fetch current service health telemetry."""
        proc_diag = self.process_manager.get_diagnostics()
        wfp_diag = self.wfp_manager.get_diagnostics()
        self.audit_logger.health_tracker.update_driver_health(
            available=proc_diag.driver_available,
            communicating=proc_diag.driver_service_connected,
            error=proc_diag.status_message if not proc_diag.driver_available else None,
        )
        self.audit_logger.health_tracker.update_wfp_health(
            available=wfp_diag.wfp_engine_available,
            session_open=wfp_diag.wfp_session_open,
            write_permitted=wfp_diag.wfp_write_permitted,
            active_filters=wfp_diag.active_dynamic_filters,
        )
        health = self.audit_logger.health_tracker.get_health_snapshot()
        health["service_running"] = self._is_running
        return health

    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Return list of active pending approval requests."""
        return self.approval_manager.get_pending_requests()

    def get_decision_history(self) -> List[Dict[str, Any]]:
        """Return recent decision records."""
        with self._lock:
            return list(self._decision_history)

    # -------------------------------------------------------------------------
    # IPC Message Dispatcher
    # -------------------------------------------------------------------------

    def _handle_ipc_message(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """Process validated IPC message and return response payload."""
        action = msg.get("action", "")
        payload = msg.get("payload", {})

        if action == "PING":
            return {"status": "PONG", "timestamp": time.time()}

        elif action == "GET_HEALTH":
            return self.get_health()

        elif action == "SUBMIT_REQUEST":
            req_data = payload.get("request", {})
            req = ExecutionRequest.from_dict(req_data)
            dec = self.submit_request(req)
            return {"decision": dec.to_dict()}

        elif action == "GET_PENDING_APPROVALS":
            return {"pending_approvals": self.get_pending_approvals()}

        elif action == "APPROVE_REQUEST":
            approval_id = str(payload.get("approval_id", ""))
            approver = str(payload.get("approver", "gui_user"))
            reason = str(payload.get("reason", "Approved from GUI"))
            success, record, err = self.approve_request(approval_id, approver=approver, reason=reason)
            return {"approved": success, "record": record, "error": err}

        elif action == "DENY_REQUEST":
            approval_id = str(payload.get("approval_id", ""))
            approver = str(payload.get("approver", "gui_user"))
            reason = str(payload.get("reason", "Denied from GUI"))
            success, record, err = self.deny_request(approval_id, approver=approver, reason=reason)
            return {"denied": success, "record": record, "error": err}

        elif action == "GET_DECISION_HISTORY":
            return {"decision_history": self.get_decision_history()}

        raise ValueError(f"Unhandled action: {action}")
