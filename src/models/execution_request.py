"""
Execution Request and Decision Data Models.

Defines the data contract for proposed execution requests that have not been
launched by the operating system yet, and structured policy decisions.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple
import os
import time
import uuid


class DecisionStatus:
    """Explicit policy decisions."""
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


class OperationType:
    """Supported enforcement operation types."""
    PROCESS = "process"
    NETWORK = "network"


class EnforcementStatus:
    """
    Standardized OS enforcement outcome states.
    Represents actual OS enforcement separately from the requested policy decision.
    """
    NOT_ENFORCED = "NOT_ENFORCED"       # Phase 1 dry-run / passive monitoring
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"
    ALLOWED = "ALLOWED"
    CONSUMED = "CONSUMED"
    FAILED = "FAILED"
    SIMULATED = "SIMULATED"             # Dry-run execution or simulated block

    # Semantic aliases for explicit verification status
    VERIFIED_ALLOWED = "ALLOWED"
    VERIFIED_BLOCKED = "BLOCKED"
    FAILED_UNENFORCED = "FAILED"
    POLICY_DECIDED_ONLY = "NOT_ENFORCED"
    MONITORING_ONLY = "NOT_ENFORCED"


class DecisionProvenance:
    """Provenance tracking for policy and enforcement decisions."""
    POLICY_ENGINE = "policy_engine"
    MANDATORY_RULE = "mandatory_rule"
    APPROVAL_MANAGER = "approval_manager"
    FAIL_CLOSED = "fail_closed"
    CACHE = "cache"
    SERVICE_SHUTDOWN = "service_shutdown"


@dataclass
class ExecutionRequest:
    """
    Represents an operation request (process execution or network connection)
    before it is enacted by the operating system.
    """
    operation_type: str = OperationType.PROCESS
    executable: str = ""
    command_line: List[str] = field(default_factory=list)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    parent_pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    username: Optional[str] = None
    working_directory: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Process identity & PID reuse protection
    process_id: Optional[int] = None
    process_create_time: Optional[float] = None

    # Network destination metadata (when operation_type == OperationType.NETWORK)
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    protocol: Optional[str] = None       # "TCP" or "UDP"
    direction: Optional[str] = None      # "OUTBOUND" or "INBOUND"

    def validate(self) -> Tuple[bool, Optional[str]]:
        """
        Validate request field types and required values based on operation_type.
        Returns (is_valid, error_message).
        """
        if not isinstance(self.operation_type, str) or self.operation_type not in (
            OperationType.PROCESS,
            OperationType.NETWORK,
        ):
            return False, f"Invalid operation_type: must be '{OperationType.PROCESS}' or '{OperationType.NETWORK}', got {self.operation_type!r}"

        # 1. Process operation validation
        if self.operation_type == OperationType.PROCESS:
            if not isinstance(self.executable, str) or not self.executable.strip():
                return False, "Executable must be a non-empty string"
            if "\0" in self.executable:
                return False, "Executable must not contain null characters"

            if not isinstance(self.command_line, list) or len(self.command_line) == 0:
                return False, "Command line must be a non-empty list of strings"

            for idx, arg in enumerate(self.command_line):
                if not isinstance(arg, str):
                    return False, f"Command line argument at index {idx} must be a string, got {type(arg).__name__}"
                if "\0" in arg:
                    return False, f"Command line argument at index {idx} must not contain null characters"

            if self.working_directory is not None:
                if not isinstance(self.working_directory, str):
                    return False, f"Working directory must be a string or None, got {type(self.working_directory).__name__}"
                if "\0" in self.working_directory:
                    return False, "Working directory must not contain null characters"

        # 2. Network operation validation
        elif self.operation_type == OperationType.NETWORK:
            if not isinstance(self.remote_ip, str) or not self.remote_ip.strip():
                return False, "Network remote_ip must be a non-empty string"
            if "\0" in self.remote_ip:
                return False, "Network remote_ip must not contain null characters"

            if self.remote_port is None or not isinstance(self.remote_port, int) or isinstance(self.remote_port, bool):
                return False, f"Network remote_port must be an integer between 1 and 65535, got {self.remote_port!r}"
            if not (1 <= self.remote_port <= 65535):
                return False, f"Network remote_port out of range (1-65535): {self.remote_port}"

            if self.local_port is not None:
                if not isinstance(self.local_port, int) or isinstance(self.local_port, bool) or not (0 <= self.local_port <= 65535):
                    return False, f"Network local_port must be an integer between 0 and 65535, got {self.local_port!r}"

            if self.protocol is not None:
                if not isinstance(self.protocol, str) or self.protocol.upper() not in ("TCP", "UDP"):
                    return False, f"Network protocol must be 'TCP', 'UDP', or None, got {self.protocol!r}"

            if self.direction is not None:
                if not isinstance(self.direction, str) or self.direction.upper() not in ("OUTBOUND", "INBOUND"):
                    return False, f"Network direction must be 'OUTBOUND', 'INBOUND', or None, got {self.direction!r}"

        # 3. Contextual and PID fields
        if self.parent_pid is not None:
            if not isinstance(self.parent_pid, int) or isinstance(self.parent_pid, bool) or self.parent_pid < 0:
                return False, f"Parent PID must be a non-negative integer, got {self.parent_pid!r}"

        if self.process_id is not None:
            if not isinstance(self.process_id, int) or isinstance(self.process_id, bool) or self.process_id < 0:
                return False, f"Process ID must be a non-negative integer, got {self.process_id!r}"

        if self.process_create_time is not None:
            if not isinstance(self.process_create_time, (int, float)) or isinstance(self.process_create_time, bool) or self.process_create_time <= 0:
                return False, f"process_create_time must be a positive number, got {self.process_create_time!r}"

        if self.parent_process_name is not None:
            if not isinstance(self.parent_process_name, str):
                return False, f"Parent process name must be a string or None, got {type(self.parent_process_name).__name__}"
            if "\0" in self.parent_process_name:
                return False, "Parent process name must not contain null characters"

        if self.username is not None:
            if not isinstance(self.username, str):
                return False, f"Username must be a string or None, got {type(self.username).__name__}"
            if "\0" in self.username:
                return False, "Username must not contain null characters"

        if not isinstance(self.metadata, dict):
            return False, f"Metadata must be a dictionary, got {type(self.metadata).__name__}"

        return True, None

    def to_process_info(self) -> Dict[str, Any]:
        """
        Convert request to process_info dictionary compatible with existing
        detectors (detect_command_indicators, calculate_risk, ProcessTreeAnalyzer).
        """
        name = os.path.basename(self.executable) if self.executable else ""
        return {
            "pid": self.process_id,
            "ppid": self.parent_pid,
            "name": name,
            "parent_name": self.parent_process_name,
            "username": self.username,
            "cmdline": list(self.command_line) if self.command_line else [],
            "create_time": self.process_create_time,
        }

    def to_network_info(self) -> Dict[str, Any]:
        """Convert request to network_info dictionary compatible with network detectors."""
        return {
            "pid": self.process_id,
            "process_name": os.path.basename(self.executable) if self.executable else (self.metadata.get("process_name") or ""),
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "protocol": self.protocol.upper() if self.protocol else "TCP",
            "direction": self.direction.upper() if self.direction else "OUTBOUND",
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert execution request to JSON-serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionRequest":
        """Construct an ExecutionRequest from a dictionary."""
        return cls(
            operation_type=data.get("operation_type", OperationType.PROCESS),
            executable=data.get("executable", ""),
            command_line=data.get("command_line", []),
            request_id=data.get("request_id") or str(uuid.uuid4()),
            timestamp=data.get("timestamp") or time.time(),
            parent_pid=data.get("parent_pid"),
            parent_process_name=data.get("parent_process_name"),
            username=data.get("username"),
            working_directory=data.get("working_directory"),
            metadata=data.get("metadata", {}),
            process_id=data.get("process_id"),
            process_create_time=data.get("process_create_time"),
            remote_ip=data.get("remote_ip"),
            remote_port=data.get("remote_port"),
            local_ip=data.get("local_ip"),
            local_port=data.get("local_port"),
            protocol=data.get("protocol"),
            direction=data.get("direction"),
        )


# Alias for enforcement naming consistency
EnforcementRequest = ExecutionRequest


@dataclass
class ExecutionDecision:
    """
    Represents the evaluation decision and risk telemetry for an ExecutionRequest / EnforcementRequest.
    Distinguishes the policy decision from actual operating-system enforcement status.
    """
    request_id: str
    decision: str                            # DecisionStatus.ALLOW, DecisionStatus.REQUIRE_APPROVAL, DecisionStatus.BLOCK
    risk_score: int = 0
    risk_level: str = "LOW"                  # "LOW", "MEDIUM", "HIGH", or "UNKNOWN"
    reasons: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    dry_run: bool = True
    executed: bool = False                   # Never True in dry-run or when decision is BLOCK/REQUIRE_APPROVAL
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    # Phase 1 shared enforcement extensions
    policy_version: str = "1.0.0"
    expires_at: Optional[float] = None
    provenance: str = DecisionProvenance.POLICY_ENGINE
    enforcement_status: str = EnforcementStatus.NOT_ENFORCED
    approval_id: Optional[str] = None
    operation_type: str = OperationType.PROCESS
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert execution decision to JSON-serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionDecision":
        """Construct an ExecutionDecision from a dictionary."""
        return cls(
            request_id=data.get("request_id", ""),
            decision=data.get("decision", DecisionStatus.BLOCK),
            risk_score=data.get("risk_score", 0),
            risk_level=data.get("risk_level", "LOW"),
            reasons=data.get("reasons", []),
            indicators=data.get("indicators", []),
            dry_run=data.get("dry_run", True),
            executed=data.get("executed", False),
            error=data.get("error"),
            timestamp=data.get("timestamp", time.time()),
            policy_version=data.get("policy_version", "1.0.0"),
            expires_at=data.get("expires_at"),
            provenance=data.get("provenance", DecisionProvenance.POLICY_ENGINE),
            enforcement_status=data.get("enforcement_status", EnforcementStatus.NOT_ENFORCED),
            approval_id=data.get("approval_id"),
            operation_type=data.get("operation_type", OperationType.PROCESS),
            metadata=data.get("metadata", {}),
        )


# Alias for enforcement naming consistency
EnforcementDecision = ExecutionDecision
