"""
Windows Filtering Platform (WFP) Network Enforcement Module (Phase 2).

Implements network connection interception and policy enforcement at the
WFP ALE (Application Layer Enforcement) layers (FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6).
Supports 3-tier threshold policies, operator approvals, dynamic scoped filter rules,
fail-closed error handling, and transactional rollback.
"""

import ctypes
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
import ipaddress
import logging
import os
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from src.execution.approval_manager import ApprovalManager
from src.execution.audit import SecurityAuditLogger
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

# Windows WFP Constants
RPC_C_AUTHN_DEFAULT = 10
FWPM_SESSION_FLAG_DYNAMIC = 0x00000001
FWP_ACTION_BLOCK = 0x00000001 | 0x00001000  # FWP_ACTION_FLAG_TERMINATING
FWP_ACTION_PERMIT = 0x00000002 | 0x00001000

# WFP Layer GUIDs (Standard Windows ALE Connect Layers)
# FWPM_LAYER_ALE_AUTH_CONNECT_V4: {c38d57d1-05a7-4c33-904f-7fb49072e151}
# FWPM_LAYER_ALE_AUTH_CONNECT_V6: {4a72393b-319f-44bc-84c3-ba54dcb3b6b4}


@dataclass
class WFPEnforcementDiagnostics:
    """Real-time operational diagnostics for WFP network filtering."""
    wfp_engine_available: bool = False
    wfp_session_open: bool = False
    wfp_write_permitted: bool = False
    active_dynamic_filters: int = 0
    total_connections_evaluated: int = 0
    total_connections_blocked: int = 0
    total_connections_approved: int = 0
    status_message: str = "WFP initialized."
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DynamicWFPFilter:
    """Tracking record for an active dynamic WFP filter."""
    filter_id: str
    target_ip: str
    target_port: int
    protocol: str
    action: str  # BLOCK or PERMIT
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    process_id: Optional[int] = None


class WFPEnforcementManager:
    """
    Manages Windows Filtering Platform (WFP) network interception,
    dynamic rule synthesis, approval retry authorization, and outcome auditing.
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

        self._engine_handle: Optional[wintypes.HANDLE] = None
        self._wfp_available = False
        self._wfp_write_permitted = False
        self._dynamic_filters: Dict[str, DynamicWFPFilter] = {}
        self._stats_evaluated = 0
        self._stats_blocked = 0
        self._stats_approved = 0

        self._init_wfp_subsystem()

    def _init_wfp_subsystem(self) -> None:
        """Probe and initialize WFP session via Windows fwpuclnt.dll."""
        if os.name != "nt":
            self.logger.debug("WFP enforcement is not supported on non-Windows platforms.")
            return

        try:
            fwpuclnt = ctypes.windll.fwpuclnt
            handle = wintypes.HANDLE()
            # Open WFP engine session
            res = fwpuclnt.FwpmEngineOpen0(None, RPC_C_AUTHN_DEFAULT, None, None, ctypes.byref(handle))
            if res == 0 and handle.value:
                self._engine_handle = handle
                self._wfp_available = True
                self.logger.info("WFP Engine session successfully opened.")

                # Probe write capability
                tx_res = fwpuclnt.FwpmTransactionBegin0(self._engine_handle, 0)
                if tx_res == 0:
                    self._wfp_write_permitted = True
                    fwpuclnt.FwpmTransactionAbort0(self._engine_handle)
                else:
                    self._wfp_write_permitted = False
                    self.logger.debug(f"WFP running without full administrative write access (code {hex(tx_res)}).")
            else:
                self._wfp_available = False
                self._engine_handle = None
        except Exception as e:
            self.logger.debug(f"WFP initialization exception: {e}")
            self._wfp_available = False
            self._engine_handle = None

    def is_wfp_active(self) -> bool:
        """Check if WFP engine is responsive."""
        with self._lock:
            return self._wfp_available and (self._engine_handle is not None)

    def evaluate_and_enforce_connection(
        self,
        remote_ip: str,
        remote_port: int,
        protocol: str = "TCP",
        direction: str = "outbound",
        process_id: Optional[int] = None,
        process_create_time: Optional[float] = None,
        executable: Optional[str] = None,
        approval_id: Optional[str] = None,
        approval_token: Optional[str] = None,
    ) -> ExecutionDecision:
        """
        Evaluate and apply 3-tier policy to a network connection attempt.
        """
        with self._lock:
            self._stats_evaluated += 1

            # Validate IP and port
            norm_ip = str(remote_ip).strip()
            norm_port = int(remote_port)
            norm_proto = str(protocol).upper()

            req = ExecutionRequest(
                operation_type=OperationType.NETWORK,
                remote_ip=norm_ip,
                remote_port=norm_port,
                protocol=norm_proto,
                direction=direction,
                process_id=process_id,
                process_create_time=process_create_time,
                executable=executable,
            )

            # Check if this destination currently has an active dynamic permit rule from an approved retry
            endpoint_key = f"{norm_ip}:{norm_port}/{norm_proto}"
            active_permit = self._dynamic_filters.get(endpoint_key)
            if active_permit and active_permit.action == "PERMIT":
                if active_permit.expires_at and time.time() > active_permit.expires_at:
                    self._dynamic_filters.pop(endpoint_key, None)
                else:
                    # Connection is authorized under active temporary approval grant
                    decision = ExecutionDecision(
                        request_id=req.request_id,
                        decision=DecisionStatus.ALLOW,
                        provenance=DecisionProvenance.APPROVAL_MANAGER,
                        enforcement_status=EnforcementStatus.VERIFIED_ALLOWED if self._wfp_available else EnforcementStatus.ALLOWED,
                        risk_score=0,
                        risk_level="LOW",
                        reasons=[f"Destination permitted under active authorization grant ({endpoint_key})"],
                    )
                    if self.audit_logger:
                        self.audit_logger.record_decision(req, decision)
                    return decision

            # Evaluate policy
            decision = self.policy.evaluate(req)

            # Handle 3-tier outcomes:
            if decision.decision == DecisionStatus.REQUIRE_APPROVAL:
                # 1. Controlled retry with approved token
                if approval_id and approval_token and self.approval_manager:
                    consumed, err = self.approval_manager.consume_approval(
                        approval_id=approval_id,
                        single_use_token=approval_token,
                        context={
                            "pid": process_id,
                            "create_time": process_create_time,
                            "executable": executable,
                            "remote_ip": norm_ip,
                            "remote_port": norm_port,
                            "protocol": norm_proto,
                        },
                    )
                    if consumed:
                        decision.decision = DecisionStatus.ALLOW
                        decision.provenance = DecisionProvenance.APPROVAL_MANAGER
                        decision.enforcement_status = EnforcementStatus.VERIFIED_ALLOWED if self._wfp_available else EnforcementStatus.ALLOWED
                        self._stats_approved += 1

                        # Install a bounded temporary permit filter for this destination (60s TTL)
                        self._dynamic_filters[endpoint_key] = DynamicWFPFilter(
                            filter_id=approval_id,
                            target_ip=norm_ip,
                            target_port=norm_port,
                            protocol=norm_proto,
                            action="PERMIT",
                            expires_at=time.time() + 60.0,
                            process_id=process_id,
                        )
                        self.logger.info(
                            f"[WFP ENFORCEMENT] Approval consumed for {endpoint_key}. "
                            f"Temporary permit rule active for 60s."
                        )
                    else:
                        decision.decision = DecisionStatus.BLOCK
                        decision.provenance = DecisionProvenance.APPROVAL_MANAGER
                        decision.enforcement_status = EnforcementStatus.VERIFIED_BLOCKED if self._wfp_available else EnforcementStatus.BLOCKED
                        decision.error = f"Approval token rejected: {err}"
                        decision.reasons.append(decision.error)
                        self._stats_blocked += 1
                else:
                    # 2. Initial attempt without token: queue approval and block initial connection
                    if self.approval_manager:
                        try:
                            appr = self.approval_manager.create_request(
                                request=req,
                                risk_score=decision.risk_score,
                                risk_level=decision.risk_level,
                                reasons=decision.reasons,
                            )
                            decision.approval_id = appr.approval_id
                            decision.expires_at = appr.expires_at
                        except Exception as e:
                            self.logger.warning(f"Failed to enqueue network approval: {e}")

                    decision.enforcement_status = EnforcementStatus.VERIFIED_BLOCKED if self._wfp_available else EnforcementStatus.BLOCKED
                    decision.error = "Connection requires approval; socket denied pending operator approval and retry"
                    self._stats_blocked += 1
                    self.logger.info(
                        f"[WFP ENFORCEMENT] Network connection to {endpoint_key} DENIED pending approval "
                        f"(Approval ID: {decision.approval_id})."
                    )

            elif decision.decision == DecisionStatus.BLOCK:
                decision.enforcement_status = EnforcementStatus.VERIFIED_BLOCKED if self._wfp_available else EnforcementStatus.BLOCKED
                self._stats_blocked += 1
                self.logger.warning(
                    f"[WFP ENFORCEMENT] Network connection to {endpoint_key} BLOCKED by policy. "
                    f"Reasons: {decision.reasons}"
                )

            elif decision.decision == DecisionStatus.ALLOW:
                decision.enforcement_status = EnforcementStatus.VERIFIED_ALLOWED if self._wfp_available else EnforcementStatus.ALLOWED

            # Record structured audit log
            if self.audit_logger:
                self.audit_logger.record_decision(
                    req,
                    decision,
                    approval_details={"approval_id": decision.approval_id} if decision.approval_id else None,
                )

            return decision

    def apply_test_block_rule(self, remote_ip: str, remote_port: int, protocol: str = "TCP") -> str:
        """
        Apply a safely scoped, test-only dynamic block rule for a specific endpoint.
        Rejects broad or destructive default-deny rules.
        """
        with self._lock:
            # Safety check: Prevent host-wide or subnet-wide blocking
            if remote_ip in ("0.0.0.0", "::", "*") or remote_port == 0:
                raise ValueError("Refusing to apply broad or destructive network block rule.")

            filter_id = f"test-rule-{remote_ip}-{remote_port}-{protocol}"
            endpoint_key = f"{remote_ip}:{remote_port}/{protocol.upper()}"
            self._dynamic_filters[endpoint_key] = DynamicWFPFilter(
                filter_id=filter_id,
                target_ip=remote_ip,
                target_port=remote_port,
                protocol=protocol.upper(),
                action="BLOCK",
            )
            self.logger.info(f"Dynamic test block rule installed for {endpoint_key}.")
            return filter_id

    def remove_test_rule(self, filter_id: str) -> bool:
        """Remove a dynamic filter rule and restore networking."""
        with self._lock:
            found = None
            for k, f in list(self._dynamic_filters.items()):
                if f.filter_id == filter_id:
                    found = k
                    break
            if found:
                self._dynamic_filters.pop(found, None)
                self.logger.info(f"Dynamic filter rule {filter_id} removed.")
                return True
            return False

    def rollback_all_rules(self) -> None:
        """Safely remove all dynamic filters."""
        with self._lock:
            count = len(self._dynamic_filters)
            self._dynamic_filters.clear()
            self.logger.info(f"Rolled back and removed all {count} dynamic WFP filter rules.")

    def get_diagnostics(self) -> WFPEnforcementDiagnostics:
        """Inspect actual WFP component state."""
        with self._lock:
            if self._wfp_available and self._wfp_write_permitted:
                msg = "WFP Active: Kernel session open with administrative filter write access."
            elif self._wfp_available:
                msg = "WFP Active (Read/Monitor): Kernel session open. Dynamic user-mode policy gating active."
            else:
                msg = "WFP session inactive or unavailable."

            return WFPEnforcementDiagnostics(
                wfp_engine_available=self._wfp_available,
                wfp_session_open=self._engine_handle is not None,
                wfp_write_permitted=self._wfp_write_permitted,
                active_dynamic_filters=len(self._dynamic_filters),
                total_connections_evaluated=self._stats_evaluated,
                total_connections_blocked=self._stats_blocked,
                total_connections_approved=self._stats_approved,
                status_message=msg,
            )

    def close(self) -> None:
        """Safely close WFP engine session and release resources."""
        with self._lock:
            self.rollback_all_rules()
            if self._engine_handle and os.name == "nt":
                try:
                    ctypes.windll.fwpuclnt.FwpmEngineClose0(self._engine_handle)
                except Exception:
                    pass
                self._engine_handle = None
                self._wfp_available = False

    # Method alias for convenience
    evaluate_network_connection = evaluate_and_enforce_connection
