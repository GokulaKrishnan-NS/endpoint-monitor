"""
Native Windows Firewall Enforcement Module.

Provides safe, scoped, argument-validated Windows Defender Firewall rule management
via native Windows interfaces (netsh.exe advfirewall firewall).
Integrates with the detection and risk-scoring pipeline to enforce policy-authorized
remediation actions without weakening security controls, without shell injection
risks, and preserving safe defaults.
"""

from dataclasses import asdict, dataclass, field
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


logger = logging.getLogger("endpoint_monitor")

DEFAULT_RULE_PREFIX = "EndpointMonitor_Block_"
DEFAULT_RULE_GROUP = "Endpoint Monitor Enforcement"
DEFAULT_TIMEOUT_SECONDS = 10.0


def is_windows_os() -> bool:
    """Check if host platform is Windows."""
    return os.name == "nt" or sys.platform == "win32"


def is_administrator() -> bool:
    """Check if current process has elevated administrative privileges on Windows."""
    if not is_windows_os():
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


@dataclass
class FirewallRuleScope:
    """Specification of target scope for a firewall enforcement rule."""
    executable: str
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: Optional[str] = None
    direction: str = "outbound"
    process_id: Optional[int] = None
    process_create_time: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FirewallRuleRecord:
    """Structured record of a firewall rule state and OS outcome."""
    rule_name: str
    action: str = "BLOCK"
    direction: str = "OUT"
    scope: Dict[str, Any] = field(default_factory=dict)
    status: str = "PENDING"  # "APPLIED", "DRY_RUN", "FAILED", "DISABLED", "REMOVED"
    success: bool = False
    dry_run: bool = False
    error: Optional[str] = None
    command_executed: Optional[List[str]] = None
    created_at: float = field(default_factory=time.time)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FirewallEnforcementResult:
    """Result of an evaluation and enforcement cycle for a network event."""
    request_id: str
    policy_decision: str  # "ALLOW", "BLOCK", "REQUIRE_APPROVAL", "NO_ACTION"
    enforcement_status: str  # "VERIFIED_BLOCKED", "SIMULATED", "NOT_ENFORCED", "FAILED", "SKIPPED"
    rule_applied: bool = False
    rule_record: Optional[FirewallRuleRecord] = None
    reasons: List[str] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.rule_record:
            data["rule_record"] = self.rule_record.to_dict()
        return data


class WindowsFirewallAdapter:
    """
    Low-level adapter for managing Windows Defender Firewall rules via netsh.exe.

    Enforces argument safety, strict parameter validation, ownership prefixes,
    idempotent cleanup, and non-blocking failure recovery.
    """

    def __init__(
        self,
        executor: Optional[Callable[..., Any]] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        rule_prefix: str = DEFAULT_RULE_PREFIX,
        rule_group: str = DEFAULT_RULE_GROUP,
    ) -> None:
        self._executor = executor if executor is not None else subprocess.run
        self.timeout = max(1.0, float(timeout))
        self.rule_prefix = str(rule_prefix) or DEFAULT_RULE_PREFIX
        self.rule_group = str(rule_group) or DEFAULT_RULE_GROUP

        self._lock = threading.RLock()
        self._active_rules: Dict[str, FirewallRuleRecord] = {}

    def is_supported(self) -> bool:
        """Check if Windows Firewall management is supported on this platform."""
        return is_windows_os()

    def has_admin_privileges(self) -> bool:
        """Check if process has administrative permissions required to modify rules."""
        return is_administrator()

    # -------------------------------------------------------------------------
    # Parameter Validation
    # -------------------------------------------------------------------------

    def validate_scope(
        self,
        executable: str,
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
        protocol: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate rule parameters strictly.
        Rejects invalid IP formats, broad wildcards, invalid ports, and relative paths.
        """
        if not executable or not isinstance(executable, str):
            return False, "Executable path must be a non-empty string."

        cleaned_exe = executable.strip().strip('"')
        if not cleaned_exe:
            return False, "Executable path cannot be blank."

        # Reject path characters that could indicate malformed input
        if "\0" in cleaned_exe or "\n" in cleaned_exe or "\r" in cleaned_exe:
            return False, "Executable path contains invalid control characters."

        # Require absolute path (drive letter e.g. C:\ or UNC e.g. \\server\share)
        drive_match = re.match(r"^[a-zA-Z]:[\\/]", cleaned_exe)
        unc_match = cleaned_exe.startswith("\\\\")
        if not (drive_match or unc_match):
            return (
                False,
                f"Executable must be an explicit absolute path (got: '{cleaned_exe}'). "
                f"Relative paths are not permitted for firewall rule scoping.",
            )

        # Validate remote_ip if provided
        if remote_ip is not None:
            if not isinstance(remote_ip, str):
                return False, f"remote_ip must be a string, got {type(remote_ip).__name__}."
            cleaned_ip = remote_ip.strip()
            if not cleaned_ip:
                return False, "remote_ip cannot be an empty string if specified."

            # Reject broad wildcards or broadcast
            if cleaned_ip in ("*", "0.0.0.0", "::", "255.255.255.255"):
                return False, f"Refusing broad wildcard or broadcast IP destination ('{cleaned_ip}')."

            try:
                addr = ipaddress.ip_address(cleaned_ip)
            except ValueError:
                return False, f"Invalid IP address format: '{cleaned_ip}'."

            if addr.is_unspecified or addr.is_multicast:
                return False, f"Refusing unspecified or multicast destination address ('{cleaned_ip}')."

        # Validate remote_port if provided
        if remote_port is not None:
            if isinstance(remote_port, bool) or not isinstance(remote_port, int):
                return False, f"remote_port must be an integer, got {type(remote_port).__name__}."
            if not (1 <= remote_port <= 65535):
                return False, f"remote_port must be between 1 and 65535 (got: {remote_port})."

        # Validate protocol if provided
        if protocol is not None:
            if not isinstance(protocol, str):
                return False, f"protocol must be a string, got {type(protocol).__name__}."
            norm_proto = protocol.strip().upper()
            if norm_proto not in ("TCP", "UDP"):
                return False, f"protocol must be 'TCP' or 'UDP', got '{protocol}'."

        return True, None

    # -------------------------------------------------------------------------
    # Command Construction
    # -------------------------------------------------------------------------

    def build_add_rule_command(
        self,
        rule_name: str,
        executable: str,
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
        protocol: Optional[str] = None,
    ) -> List[str]:
        """
        Construct argument-safe netsh command list for adding an outbound block rule.
        Uses explicit argument separation with no shell expansion.
        """
        norm_exe = os.path.normpath(executable.strip().strip('"'))

        cmd = [
            "netsh.exe",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=out",
            "action=block",
            f"program={norm_exe}",
            "enable=yes",
        ]

        if remote_ip:
            cmd.append(f"remoteip={remote_ip.strip()}")

        if remote_port is not None:
            proto = (protocol or "TCP").strip().lower()
            cmd.append(f"protocol={proto}")
            cmd.append(f"remoteport={remote_port}")
        elif protocol:
            cmd.append(f"protocol={protocol.strip().lower()}")

        return cmd

    def build_delete_rule_command(self, rule_name: str) -> List[str]:
        """Construct argument-safe netsh command list for deleting a rule by name."""
        return [
            "netsh.exe",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]

    # -------------------------------------------------------------------------
    # Rule Creation
    # -------------------------------------------------------------------------

    def create_block_rule(
        self,
        executable: str,
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
        protocol: Optional[str] = None,
        process_id: Optional[int] = None,
        process_create_time: Optional[float] = None,
        reasons: Optional[List[str]] = None,
        dry_run: bool = False,
        rule_name: Optional[str] = None,
    ) -> FirewallRuleRecord:
        """
        Create an outbound block rule scoped to the specified executable and optional endpoint.
        """
        scope_dict = {
            "executable": executable,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "protocol": protocol,
            "direction": "outbound",
            "process_id": process_id,
            "process_create_time": process_create_time,
        }

        # 1. Validate parameters
        is_valid, validation_err = self.validate_scope(
            executable=executable,
            remote_ip=remote_ip,
            remote_port=remote_port,
            protocol=protocol,
        )

        # Generate a predictable, unique rule name if not specified
        if not rule_name:
            exe_base = os.path.basename(executable.strip().strip('"')).replace(" ", "_")
            port_part = f"_{remote_port}" if remote_port else ""
            rule_name = f"{self.rule_prefix}{exe_base}{port_part}_{int(time.time() * 1000) % 1000000}"

        if not is_valid:
            return FirewallRuleRecord(
                rule_name=rule_name,
                scope=scope_dict,
                status="FAILED",
                success=False,
                dry_run=dry_run,
                error=validation_err,
                reasons=reasons or [validation_err or "Validation failure"],
            )

        # Check for duplicate active rule
        with self._lock:
            for active_name, active_rec in self._active_rules.items():
                if (
                    active_rec.scope.get("executable") == executable
                    and active_rec.scope.get("remote_ip") == remote_ip
                    and active_rec.scope.get("remote_port") == remote_port
                    and active_rec.scope.get("protocol") == protocol
                    and active_rec.success
                ):
                    return active_rec

        # 2. Dry-Run simulation
        command = self.build_add_rule_command(
            rule_name=rule_name,
            executable=executable,
            remote_ip=remote_ip,
            remote_port=remote_port,
            protocol=protocol,
        )

        if dry_run:
            simulated_reasons = (reasons or []) + [
                f"[DRY-RUN] Simulated outbound firewall block rule '{rule_name}' for {executable}"
            ]
            record = FirewallRuleRecord(
                rule_name=rule_name,
                scope=scope_dict,
                status="DRY_RUN",
                success=True,
                dry_run=True,
                error=None,
                command_executed=command,
                reasons=simulated_reasons,
            )
            with self._lock:
                self._active_rules[rule_name] = record
            logger.info(f"[FIREWALL ENFORCEMENT] {simulated_reasons[-1]}")
            return record

        # 3. Check Windows OS platform
        if not self.is_supported():
            err_msg = "Windows Firewall enforcement is only supported on Windows operating systems."
            return FirewallRuleRecord(
                rule_name=rule_name,
                scope=scope_dict,
                status="FAILED",
                success=False,
                dry_run=False,
                error=err_msg,
                reasons=(reasons or []) + [err_msg],
            )

        # 4. Check Administrator Privileges
        if not self.has_admin_privileges():
            err_msg = "Administrator privileges required to modify Windows Firewall rules."
            logger.warning(f"[FIREWALL ENFORCEMENT] {err_msg}")
            return FirewallRuleRecord(
                rule_name=rule_name,
                scope=scope_dict,
                status="FAILED",
                success=False,
                dry_run=False,
                error=err_msg,
                reasons=(reasons or []) + [err_msg],
            )

        # 5. Execute command via executor
        try:
            result = self._executor(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError:
            err_msg = "netsh.exe is not available on this system."
            logger.error(f"[FIREWALL ENFORCEMENT] {err_msg}")
            return FirewallRuleRecord(
                rule_name=rule_name,
                scope=scope_dict,
                status="FAILED",
                success=False,
                dry_run=False,
                error=err_msg,
                reasons=(reasons or []) + [err_msg],
            )
        except subprocess.TimeoutExpired:
            err_msg = f"netsh.exe timed out after {self.timeout}s."
            logger.warning(f"[FIREWALL ENFORCEMENT] {err_msg}")
            return FirewallRuleRecord(
                rule_name=rule_name,
                scope=scope_dict,
                status="FAILED",
                success=False,
                dry_run=False,
                error=err_msg,
                reasons=(reasons or []) + [err_msg],
            )
        except Exception as ex:
            err_msg = f"Firewall command execution error: {ex}"
            logger.error(f"[FIREWALL ENFORCEMENT] {err_msg}")
            return FirewallRuleRecord(
                rule_name=rule_name,
                scope=scope_dict,
                status="FAILED",
                success=False,
                dry_run=False,
                error=err_msg,
                reasons=(reasons or []) + [err_msg],
            )

        returncode = getattr(result, "returncode", 0)
        stdout = getattr(result, "stdout", "") or ""
        stderr = getattr(result, "stderr", "") or ""

        if returncode != 0:
            lowered = (stderr + " " + stdout).lower()
            if "elevation" in lowered or "administrator" in lowered or "access is denied" in lowered:
                err_msg = "Administrator privileges required to modify Windows Firewall rules."
            else:
                err_msg = f"netsh returned exit code {returncode}: {stderr.strip() or stdout.strip()}"

            logger.warning(f"[FIREWALL ENFORCEMENT] Failed to apply rule '{rule_name}': {err_msg}")
            return FirewallRuleRecord(
                rule_name=rule_name,
                scope=scope_dict,
                status="FAILED",
                success=False,
                dry_run=False,
                error=err_msg,
                command_executed=command,
                reasons=(reasons or []) + [err_msg],
            )

        # Success
        record = FirewallRuleRecord(
            rule_name=rule_name,
            scope=scope_dict,
            status="APPLIED",
            success=True,
            dry_run=False,
            error=None,
            command_executed=command,
            reasons=(reasons or []) + [f"Outbound block rule '{rule_name}' applied successfully via netsh"],
        )
        with self._lock:
            self._active_rules[rule_name] = record

        logger.info(
            f"[FIREWALL ENFORCEMENT] Successfully applied outbound block rule: {rule_name} "
            f"(exe={executable}, remote={remote_ip}:{remote_port})"
        )
        return record

    # -------------------------------------------------------------------------
    # Rule Removal and Idempotent Cleanup
    # -------------------------------------------------------------------------

    def delete_rule(self, rule_name: str) -> bool:
        """
        Remove a specific rule owned by Endpoint Monitor.
        Strictly refuses to delete rules not matching rule_prefix.
        """
        if not rule_name or not isinstance(rule_name, str):
            return False

        # Strictly enforce ownership: never touch unrelated rules
        if not rule_name.startswith(self.rule_prefix):
            raise ValueError(
                f"Refusing to delete rule '{rule_name}': rule does not have application prefix '{self.rule_prefix}'."
            )

        with self._lock:
            self._active_rules.pop(rule_name, None)

        if not self.is_supported():
            return True

        cmd = self.build_delete_rule_command(rule_name)
        try:
            result = self._executor(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            stdout = getattr(result, "stdout", "") or ""
            stderr = getattr(result, "stderr", "") or ""
            combined = (stdout + " " + stderr).lower()

            # "No rules match the specified criteria" is considered idempotent success
            if result.returncode == 0 or "no rules match" in combined:
                logger.info(f"[FIREWALL ENFORCEMENT] Rule '{rule_name}' removed or absent.")
                return True
            else:
                logger.warning(f"[FIREWALL ENFORCEMENT] Could not delete rule '{rule_name}': {stderr.strip()}")
                return False
        except Exception as ex:
            logger.warning(f"[FIREWALL ENFORCEMENT] Error deleting rule '{rule_name}': {ex}")
            return False

    def delete_all_owned_rules(self) -> int:
        """
        Remove all active rules created by this application.
        Strictly deletes by specific owned rule names; never passes broad 'name=all'.
        """
        with self._lock:
            targets = list(self._active_rules.keys())

        deleted_count = 0
        for name in targets:
            if name.startswith(self.rule_prefix):
                if self.delete_rule(name):
                    deleted_count += 1

        logger.info(f"[FIREWALL ENFORCEMENT] Cleaned up {deleted_count} application-owned firewall rules.")
        return deleted_count

    def list_owned_rules(self) -> List[Dict[str, Any]]:
        """List active rules tracked by this adapter."""
        with self._lock:
            return [rec.to_dict() for rec in self._active_rules.values()]

    def is_rule_active(self, rule_name: str) -> bool:
        """Check if a rule is recorded as active."""
        with self._lock:
            rec = self._active_rules.get(rule_name)
            return rec is not None and rec.status in ("APPLIED", "DRY_RUN")


class WindowsFirewallEnforcer:
    """
    High-level policy coordinator for Windows Firewall enforcement.

    Coordinates risk thresholds, dry-run safety gates, event-to-scope mapping,
    diagnostic reporting, and startup messaging.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: str = "config/config.json",
        adapter: Optional[WindowsFirewallAdapter] = None,
        logger_instance: Optional[logging.Logger] = None,
    ) -> None:
        self.logger = logger_instance if logger_instance is not None else logger
        self.config_path = config_path
        self.config = self._load_firewall_config(config, config_path)

        self.enabled: bool = bool(self.config.get("enabled", False))
        self.dry_run: bool = bool(self.config.get("dry_run", True))
        self.auto_block_suspicious: bool = bool(self.config.get("auto_block_suspicious", False))
        self.block_threshold: int = int(self.config.get("block_threshold", 7))
        self.blocked_severities: Set[str] = set(self.config.get("blocked_severities", ["HIGH"]))
        self.blocked_indicators: Set[str] = set(self.config.get("blocked_indicators", []))
        self.allowed_executables: Set[str] = {
            os.path.basename(str(exe)).lower() for exe in self.config.get("allowed_executables", [])
        }

        self.adapter = adapter if adapter is not None else WindowsFirewallAdapter(
            timeout=float(self.config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)),
            rule_prefix=str(self.config.get("rule_prefix", DEFAULT_RULE_PREFIX)),
            rule_group=str(self.config.get("rule_group", DEFAULT_RULE_GROUP)),
        )

        self._lock = threading.RLock()
        self._stats_evaluated = 0
        self._stats_applied = 0
        self._stats_simulated = 0
        self._stats_failed = 0
        self._last_error: Optional[str] = None

    def _load_firewall_config(
        self,
        explicit_config: Optional[Dict[str, Any]],
        config_path: str,
    ) -> Dict[str, Any]:
        """Load firewall enforcement config from dict or config.json."""
        default_cfg: Dict[str, Any] = {
            "enabled": False,
            "dry_run": True,
            "auto_block_suspicious": False,
            "block_threshold": 7,
            "blocked_severities": ["HIGH"],
            "blocked_indicators": [],
            "allowed_executables": [],
            "rule_prefix": DEFAULT_RULE_PREFIX,
            "rule_group": DEFAULT_RULE_GROUP,
            "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        }

        if explicit_config is not None:
            if "firewall_enforcement" in explicit_config:
                default_cfg.update(explicit_config["firewall_enforcement"])
            else:
                default_cfg.update(explicit_config)
            return default_cfg

        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    ce = data.get("controlled_execution", {})
                    fe = ce.get("firewall_enforcement", data.get("firewall_enforcement", {}))
                    if isinstance(fe, dict):
                        default_cfg.update(fe)
            except Exception as e:
                logger.debug(f"Could not load firewall config from {config_path}: {e}")

        return default_cfg

    def get_startup_status_message(self) -> str:
        """Provide a clear human-readable startup message describing enforcement mode."""
        if not self.enabled:
            return (
                "[FIREWALL ENFORCEMENT] Windows Firewall enforcement is DISABLED (dry_run=True). "
                "Passive monitoring and alerting active."
            )
        elif self.dry_run:
            return (
                "[FIREWALL ENFORCEMENT] Windows Firewall enforcement is in DRY-RUN mode. "
                "Policy decisions will be simulated; no OS firewall rules will be modified."
            )
        else:
            admin_str = "Admin permissions verified" if self.adapter.has_admin_privileges() else "CAUTION: Non-admin process"
            return (
                f"[FIREWALL ENFORCEMENT] Windows Firewall enforcement is LIVE ENABLED ({admin_str}). "
                f"Outbound block rules will be applied for authorized policy violations."
            )

    # -------------------------------------------------------------------------
    # Policy Decision Interface
    # -------------------------------------------------------------------------

    def evaluate_event_for_enforcement(
        self,
        event: Any,
    ) -> Tuple[bool, str, List[str]]:
        """
        Determine whether a network event is authorized for enforcement by policy.
        Separates detection/risk scoring from enforcement.
        Returns: (should_block, decision_status, reasons)
        """
        reasons: List[str] = []

        # 1. Enforcement disabled check
        if not self.enabled:
            return False, "NO_ACTION", ["Firewall enforcement is disabled by configuration"]

        # 2. Check if binary is in allowlist
        proc_name = getattr(event, "process_name", "") or ""
        if proc_name and os.path.basename(proc_name).lower() in self.allowed_executables:
            return False, "ALLOW", [f"Executable '{proc_name}' is in allowed_executables list"]

        # 3. Policy criteria checks
        risk_score = getattr(event, "risk_score", 0) or 0
        severity = getattr(event, "severity", "LOW") or "LOW"
        indicators = getattr(event, "indicators", []) or []

        threshold_met = risk_score >= self.block_threshold
        severity_met = severity in self.blocked_severities
        indicator_met = any(ind in self.blocked_indicators for ind in indicators)
        auto_block = self.auto_block_suspicious and (risk_score >= 4 or len(indicators) > 0)

        should_enforce = threshold_met or severity_met or indicator_met or auto_block

        if threshold_met:
            reasons.append(f"Risk score {risk_score} meets block threshold {self.block_threshold}")
        if severity_met:
            reasons.append(f"Risk severity '{severity}' is in blocked_severities")
        if indicator_met:
            reasons.append(f"Contains blocked indicator: {[i for i in indicators if i in self.blocked_indicators]}")
        if auto_block and not (threshold_met or severity_met or indicator_met):
            reasons.append(f"auto_block_suspicious triggered on suspicious indicators: {indicators}")

        if should_enforce:
            return True, "BLOCK", reasons

        return False, "ALLOW", ["Event does not meet firewall enforcement policy criteria"]

    # -------------------------------------------------------------------------
    # Event Processing and Enforcement Execution
    # -------------------------------------------------------------------------

    def process_network_event(
        self,
        event: Any,
        running_processes: Optional[Dict[int, Dict[str, Any]]] = None,
    ) -> FirewallEnforcementResult:
        """
        Evaluate and optionally enforce a network event.
        Guarantees that telemetry collection and alerting keep operating if enforcement fails.
        """
        with self._lock:
            self._stats_evaluated += 1

        request_id = getattr(event, "event_id", "") or "unknown"
        risk_score = getattr(event, "risk_score", 0) or 0
        risk_level = getattr(event, "risk_level", getattr(event, "severity", "LOW")) or "LOW"

        # Separate detection from enforcement
        should_block, decision_status, policy_reasons = self.evaluate_event_for_enforcement(event)

        if not should_block:
            return FirewallEnforcementResult(
                request_id=request_id,
                policy_decision=decision_status,
                enforcement_status="NOT_ENFORCED",
                rule_applied=False,
                rule_record=None,
                reasons=policy_reasons,
                risk_score=risk_score,
                risk_level=risk_level,
            )

        # Extract connection details without inventing unknown endpoints
        net_info = getattr(event, "network_info", {}) or {}
        remote_ip = net_info.get("remote_ip")
        remote_port = net_info.get("remote_port")
        protocol = net_info.get("protocol")
        pid = getattr(event, "pid", None) or net_info.get("pid")

        # Resolve explicit executable path
        executable = net_info.get("exe") or getattr(event, "executable_path", None)
        if not executable and running_processes and pid in running_processes:
            executable = running_processes[pid].get("exe")

        # If executable still unavailable, try to locate well-known system binary or fail scope
        proc_name = getattr(event, "process_name", "") or net_info.get("process_name")
        if not executable and proc_name:
            # Check system directories safely
            sys_root = os.environ.get("SystemRoot", "C:\\Windows")
            candidates = [
                os.path.join(sys_root, "System32", proc_name),
                os.path.join(sys_root, proc_name),
            ]
            for cand in candidates:
                if os.path.exists(cand):
                    executable = cand
                    break

        # If executable path is unavailable, do not create an un-scoped broad rule!
        if not executable:
            skip_msg = f"Cannot apply scoped firewall rule: executable path is unavailable for process '{proc_name}' (PID: {pid})."
            self.logger.warning(f"[FIREWALL ENFORCEMENT] {skip_msg}")
            return FirewallEnforcementResult(
                request_id=request_id,
                policy_decision="BLOCK",
                enforcement_status="SKIPPED",
                rule_applied=False,
                rule_record=None,
                reasons=policy_reasons + [skip_msg],
                risk_score=risk_score,
                risk_level=risk_level,
                error=skip_msg,
            )

        # Distinguish Sysmon Event ID 3 telemetry
        source = getattr(event, "source", "") or ""
        is_sysmon = "sysmon" in source.lower() or (
            isinstance(getattr(event, "metadata", None), dict)
            and event.metadata.get("telemetry_source") == "sysmon"
        )
        if is_sysmon:
            policy_reasons.append(
                "Sysmon Event ID 3 telemetry observed: prospective firewall rule applied to prevent subsequent outbound traffic."
            )

        # Execute rule creation via adapter
        try:
            record = self.adapter.create_block_rule(
                executable=executable,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=protocol,
                process_id=pid,
                reasons=policy_reasons,
                dry_run=self.dry_run,
            )
        except Exception as ex:
            err_msg = f"Unexpected exception in firewall adapter: {ex}"
            self.logger.error(f"[FIREWALL ENFORCEMENT] {err_msg}")
            with self._lock:
                self._stats_failed += 1
                self._last_error = err_msg
            return FirewallEnforcementResult(
                request_id=request_id,
                policy_decision="BLOCK",
                enforcement_status="FAILED",
                rule_applied=False,
                reasons=policy_reasons + [err_msg],
                risk_score=risk_score,
                risk_level=risk_level,
                error=err_msg,
            )

        # Update stats
        with self._lock:
            if record.status == "APPLIED" and record.success:
                self._stats_applied += 1
                enforcement_status = "VERIFIED_BLOCKED"
                rule_applied = True
            elif record.status == "DRY_RUN":
                self._stats_simulated += 1
                enforcement_status = "SIMULATED"
                rule_applied = False
            else:
                self._stats_failed += 1
                self._last_error = record.error
                enforcement_status = "FAILED"
                rule_applied = False

        res = FirewallEnforcementResult(
            request_id=request_id,
            policy_decision="BLOCK",
            enforcement_status=enforcement_status,
            rule_applied=rule_applied,
            rule_record=record,
            reasons=record.reasons,
            risk_score=risk_score,
            risk_level=risk_level,
            error=record.error,
        )

        # Record enforcement result in event metadata
        if hasattr(event, "metadata") and isinstance(event.metadata, dict):
            event.metadata["firewall_enforcement"] = res.to_dict()

        return res

    def cleanup(self) -> int:
        """Safely remove all application-owned rules."""
        return self.adapter.delete_all_owned_rules()

    def get_diagnostics(self) -> Dict[str, Any]:
        """Return diagnostic metrics snapshot."""
        with self._lock:
            return {
                "is_windows": self.adapter.is_supported(),
                "is_admin": self.adapter.has_admin_privileges(),
                "enabled": self.enabled,
                "dry_run": self.dry_run,
                "auto_block_suspicious": self.auto_block_suspicious,
                "block_threshold": self.block_threshold,
                "active_rules_count": len(self.adapter._active_rules),
                "total_evaluations": self._stats_evaluated,
                "total_applied": self._stats_applied,
                "total_simulated": self._stats_simulated,
                "total_failures": self._stats_failed,
                "last_error": self._last_error,
                "status_message": self.get_startup_status_message(),
                "active_rules": self.adapter.list_owned_rules(),
            }

    get_status_snapshot = get_diagnostics

    def close(self) -> None:
        """Alias for cleanup when shut down."""
        self.cleanup()
