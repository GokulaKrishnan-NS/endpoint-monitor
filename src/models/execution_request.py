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
    """Explicit execution decisions."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass
class ExecutionRequest:
    """
    Represents an execution request for a target process before it is launched.
    Contains proposed execution parameters and caller context.
    """
    executable: str = ""
    command_line: List[str] = field(default_factory=list)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    parent_pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    username: Optional[str] = None
    working_directory: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> Tuple[bool, Optional[str]]:
        """
        Validate request field types and required values.
        Returns (is_valid, error_message).
        """
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

        if self.parent_pid is not None:
            if not isinstance(self.parent_pid, int) or isinstance(self.parent_pid, bool) or self.parent_pid < 0:
                return False, f"Parent PID must be a non-negative integer, got {self.parent_pid!r}"

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

        if self.working_directory is not None:
            if not isinstance(self.working_directory, str):
                return False, f"Working directory must be a string or None, got {type(self.working_directory).__name__}"
            if "\0" in self.working_directory:
                return False, "Working directory must not contain null characters"

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
            "pid": None,
            "ppid": self.parent_pid,
            "name": name,
            "parent_name": self.parent_process_name,
            "username": self.username,
            "cmdline": list(self.command_line),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert execution request to JSON-serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionRequest":
        """Construct an ExecutionRequest from a dictionary."""
        return cls(
            executable=data.get("executable", ""),
            command_line=data.get("command_line", []),
            request_id=data.get("request_id") or str(uuid.uuid4()),
            timestamp=data.get("timestamp") or time.time(),
            parent_pid=data.get("parent_pid"),
            parent_process_name=data.get("parent_process_name"),
            username=data.get("username"),
            working_directory=data.get("working_directory"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ExecutionDecision:
    """
    Represents the evaluation decision and risk telemetry for an ExecutionRequest.
    """
    request_id: str
    decision: str                            # DecisionStatus.ALLOW or DecisionStatus.BLOCK
    risk_score: int = 0
    risk_level: str = "LOW"                  # "LOW", "MEDIUM", "HIGH", or "UNKNOWN"
    reasons: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    dry_run: bool = True
    executed: bool = False                   # Never True in dry-run or when decision is BLOCK
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

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
        )
