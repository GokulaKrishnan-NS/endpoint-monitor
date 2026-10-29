"""
Execution Policy Evaluation Module.

Evaluates an ExecutionRequest (or EnforcementRequest) before process launch or network
connection by integrating with:
- Command indicator detection (detect_command_indicators)
- Process tree lineage analysis (ProcessTreeAnalyzer.evaluate_parent_child)
- Network anomaly detection and port risk rules
- Risk scoring engine (calculate_risk)

Enforces fail-closed semantics: any validation or analyzer failure results in BLOCK.
Mandatory policy blocks strictly override risk scores.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from src.analysis.process_tree import ProcessTreeAnalyzer
from src.detectors.command_detector import detect_command_indicators
from src.detectors.risk_detector import calculate_risk
from src.execution.config import load_execution_config
from src.models.execution_request import (
    DecisionProvenance,
    DecisionStatus,
    EnforcementStatus,
    ExecutionDecision,
    ExecutionRequest,
    OperationType,
)
from src.monitors.network_monitor import DEFAULT_NETWORK_CONFIG, is_loopback_or_local, is_private_ip


def validate_policy_thresholds(cfg: Any) -> Tuple[bool, Optional[str], Optional[int], int]:
    """
    Validate threshold semantics:
    - approval_threshold and block_threshold must be non-negative numbers.
    - approval_threshold must not exceed block_threshold.
    Returns (is_valid, error_message, approval_threshold, block_threshold).
    """
    if not isinstance(cfg, dict):
        return False, f"Policy configuration must be a dictionary, got {type(cfg).__name__}", None, 7

    block_val = cfg.get("block_threshold", cfg.get("score_threshold", 7))
    if isinstance(block_val, bool) or not isinstance(block_val, (int, float)):
        try:
            block_val = int(block_val)
        except (ValueError, TypeError):
            return False, f"Invalid block_threshold: must be numeric, got {block_val!r}", None, 7

    block_threshold = int(block_val)
    if block_threshold < 0:
        return False, f"Invalid block_threshold: cannot be negative ({block_threshold})", None, block_threshold

    approval_val = cfg.get("approval_threshold")
    approval_threshold = None
    if approval_val is not None:
        if isinstance(approval_val, bool) or not isinstance(approval_val, (int, float)):
            try:
                approval_val = int(approval_val)
            except (ValueError, TypeError):
                return False, f"Invalid approval_threshold: must be numeric, got {approval_val!r}", None, block_threshold

        approval_threshold = int(approval_val)
        if approval_threshold < 0:
            return False, f"Invalid approval_threshold: cannot be negative ({approval_threshold})", None, block_threshold
        if approval_threshold > block_threshold:
            return (
                False,
                f"Contradictory thresholds: approval_threshold ({approval_threshold}) cannot exceed block_threshold ({block_threshold})",
                approval_threshold,
                block_threshold,
            )

    return True, None, approval_threshold, block_threshold


class ExecutionPolicy:
    """
    Configurable security policy that inspects proposed process execution and
    network requests and issues explicit ALLOW, REQUIRE_APPROVAL, or BLOCK decisions.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: str = "config/config.json",
        tree_analyzer: Optional[ProcessTreeAnalyzer] = None,
    ):
        self.logger = logging.getLogger("endpoint_monitor")
        self._config_valid = True
        self._config_error: Optional[str] = None

        if config is not None:
            if not isinstance(config, dict):
                self._config_valid = False
                self._config_error = f"Policy configuration must be a dictionary, got {type(config).__name__}"
                self.config = {}
            else:
                self.config = config
        else:
            try:
                self.config = load_execution_config(config_path)
            except Exception as e:
                self.config = {}
                self._config_valid = False
                self._config_error = f"Failed to load policy configuration: {e}"

        # Validate threshold configuration
        is_valid, err, approval_th, block_th = validate_policy_thresholds(self.config)
        if not is_valid:
            self._config_valid = False
            self._config_error = err
            self.block_threshold = block_th
            self.score_threshold = block_th
            self.approval_threshold = approval_th
        else:
            self.block_threshold = block_th
            self.score_threshold = block_th  # Backward compatibility
            self.approval_threshold = approval_th

        self.policy_version: str = str(self.config.get("policy_version", "1.0.0"))
        self.enabled: bool = bool(self.config.get("enabled", True))
        self.blocked_severities: Set[str] = set(
            self.config.get("blocked_severities", ["HIGH"])
        )
        self.blocked_indicators: Set[str] = set(
            self.config.get("blocked_indicators", [])
        )
        self.fail_closed: bool = bool(self.config.get("fail_closed", True))

        # Mandatory explicit block lists (always override scores)
        raw_blocked_exes = self.config.get("blocked_executables", [])
        self.blocked_executables: Set[str] = {
            os.path.basename(str(exe)).lower() for exe in raw_blocked_exes if isinstance(exe, str)
        }
        self.blocked_ports: Set[int] = {
            int(p) for p in self.config.get("blocked_ports", []) if isinstance(p, (int, float)) and not isinstance(p, bool)
        }
        self.blocked_ips: Set[str] = {
            str(ip).strip().lower() for ip in self.config.get("blocked_ips", []) if isinstance(ip, str)
        }

        # Network risk assessment rules
        self.suspicious_ports: Set[int] = set(
            self.config.get("suspicious_ports", DEFAULT_NETWORK_CONFIG.get("suspicious_ports", []))
        )
        self.unexpected_network_processes: Set[str] = {
            p.lower() for p in self.config.get("unexpected_network_processes", DEFAULT_NETWORK_CONFIG.get("unexpected_processes", []))
        }
        self.script_interpreters: Set[str] = {
            s.lower() for s in self.config.get("script_interpreters", DEFAULT_NETWORK_CONFIG.get("script_interpreters", []))
        }

        if tree_analyzer is not None:
            self.tree_analyzer = tree_analyzer
        else:
            self.tree_analyzer = ProcessTreeAnalyzer(config_path=config_path)

    def evaluate(self, request: ExecutionRequest) -> ExecutionDecision:
        """
        Evaluate an ExecutionRequest / EnforcementRequest against configured security policies.
        Returns an ExecutionDecision with decision status, score, reasons, provenance, and indicators.
        Guarantees fail-closed BLOCK behavior if validation, configuration, or analysis fails.
        """
        if not isinstance(request, ExecutionRequest):
            err_msg = f"Invalid request type: expected ExecutionRequest, got {type(request).__name__}"
            self.logger.warning(err_msg)
            return ExecutionDecision(
                request_id="",
                decision=DecisionStatus.BLOCK,
                risk_score=999,
                risk_level="UNKNOWN",
                reasons=[f"Validation failure: {err_msg}"],
                indicators=[],
                dry_run=True,
                executed=False,
                error=err_msg,
                policy_version=self.policy_version,
                provenance=DecisionProvenance.FAIL_CLOSED,
                enforcement_status=EnforcementStatus.NOT_ENFORCED,
            )

        # 1. Reject if policy configuration is invalid or contradictory
        if not self._config_valid:
            err_msg = f"Invalid policy configuration: {self._config_error}"
            self.logger.error(f"Policy evaluation rejected for {request.request_id}: {err_msg}")
            return ExecutionDecision(
                request_id=request.request_id,
                decision=DecisionStatus.BLOCK,
                risk_score=999,
                risk_level="UNKNOWN",
                reasons=[err_msg],
                indicators=[],
                dry_run=True,
                executed=False,
                error=err_msg,
                policy_version=self.policy_version,
                provenance=DecisionProvenance.FAIL_CLOSED,
                enforcement_status=EnforcementStatus.NOT_ENFORCED,
                operation_type=request.operation_type,
            )

        # 2. Validate request structure and field types
        is_valid, validation_error = request.validate()
        if not is_valid:
            err_msg = f"Validation failure: {validation_error}"
            self.logger.warning(f"Request {request.request_id} failed validation: {validation_error}")
            return ExecutionDecision(
                request_id=request.request_id,
                decision=DecisionStatus.BLOCK,
                risk_score=999,
                risk_level="UNKNOWN",
                reasons=[err_msg],
                indicators=[],
                dry_run=True,
                executed=False,
                error=err_msg,
                policy_version=self.policy_version,
                provenance=DecisionProvenance.FAIL_CLOSED,
                enforcement_status=EnforcementStatus.NOT_ENFORCED,
                operation_type=request.operation_type,
            )

        # 3. If policy engine is disabled, return ALLOW
        if not self.enabled:
            return ExecutionDecision(
                request_id=request.request_id,
                decision=DecisionStatus.ALLOW,
                risk_score=0,
                risk_level="LOW",
                reasons=["Controlled execution policy is disabled"],
                indicators=[],
                dry_run=True,
                executed=False,
                error=None,
                policy_version=self.policy_version,
                provenance=DecisionProvenance.POLICY_ENGINE,
                enforcement_status=EnforcementStatus.NOT_ENFORCED,
                operation_type=request.operation_type,
            )

        # 4. Route evaluation by operation type
        try:
            if request.operation_type == OperationType.NETWORK:
                return self._evaluate_network_request(request)
            else:
                return self._evaluate_process_request(request)
        except Exception as exc:
            err_msg = f"Analyzer error during evaluation: {exc}"
            self.logger.error(f"Request {request.request_id} evaluation failed: {exc}", exc_info=True)
            return ExecutionDecision(
                request_id=request.request_id,
                decision=DecisionStatus.BLOCK,
                risk_score=999,
                risk_level="UNKNOWN",
                reasons=[f"Fail-closed policy enforced: {err_msg}"],
                indicators=[],
                dry_run=True,
                executed=False,
                error=err_msg,
                policy_version=self.policy_version,
                provenance=DecisionProvenance.FAIL_CLOSED,
                enforcement_status=EnforcementStatus.NOT_ENFORCED,
                operation_type=request.operation_type,
            )

    def _evaluate_process_request(self, request: ExecutionRequest) -> ExecutionDecision:
        """Evaluate a process creation request."""
        proc_name = os.path.basename(request.executable).lower() if request.executable else ""

        # Check mandatory executable blocks first (overrides scores completely)
        mandatory_block_reasons: List[str] = []
        if proc_name and proc_name in self.blocked_executables:
            mandatory_block_reasons.append(
                f"Executable '{proc_name}' is explicitly blocked by mandatory policy rule"
            )

        cmdline = request.command_line
        indicators: List[str] = detect_command_indicators(cmdline)

        # Process tree lineage analysis
        tree_findings: List[Dict[str, Any]] = []
        if request.parent_process_name:
            tree_findings = self.tree_analyzer.evaluate_parent_child(
                request.parent_process_name, proc_name
            )
            for finding in tree_findings:
                ind = finding.get("indicator")
                if ind and ind not in indicators:
                    indicators.append(ind)

        # Calculate risk score
        process_info = request.to_process_info()
        risk_result = calculate_risk(
            indicators=indicators,
            process_info=process_info,
            tree_findings=tree_findings,
        )

        score: int = risk_result.get("score", 0)
        level: str = risk_result.get("level", "LOW")
        reasons: List[str] = list(risk_result.get("reasons", []))

        # Check mandatory indicator blocks
        for ind in indicators:
            if ind in self.blocked_indicators:
                mandatory_block_reasons.append(
                    f"Detected indicator '{ind}' is explicitly blocked by mandatory policy rule"
                )

        # Mandatory blocks always override scores
        if mandatory_block_reasons:
            return ExecutionDecision(
                request_id=request.request_id,
                decision=DecisionStatus.BLOCK,
                risk_score=score,
                risk_level=level,
                reasons=mandatory_block_reasons + reasons,
                indicators=indicators,
                dry_run=True,
                executed=False,
                error=None,
                policy_version=self.policy_version,
                provenance=DecisionProvenance.MANDATORY_RULE,
                enforcement_status=EnforcementStatus.NOT_ENFORCED,
                operation_type=OperationType.PROCESS,
            )

        # Standard policy threshold evaluation:
        # High risk: score >= block_threshold or level in blocked_severities -> BLOCK
        # Intermediate risk: approval_threshold <= score < block_threshold -> REQUIRE_APPROVAL
        # Low risk: score < approval_threshold -> ALLOW
        block_reasons: List[str] = []
        if score >= self.block_threshold:
            block_reasons.append(
                f"Risk score {score} meets or exceeds threshold {self.block_threshold}"
            )
        if level in self.blocked_severities:
            block_reasons.append(
                f"Risk severity level '{level}' is blocked by policy ({sorted(self.blocked_severities)})"
            )

        if block_reasons:
            decision = DecisionStatus.BLOCK
            final_reasons = block_reasons + reasons
        elif self.approval_threshold is not None and score >= self.approval_threshold:
            decision = DecisionStatus.REQUIRE_APPROVAL
            approval_note = f"Risk score {score} meets or exceeds approval threshold {self.approval_threshold} — user approval required"
            final_reasons = [approval_note] + reasons
        else:
            decision = DecisionStatus.ALLOW
            final_reasons = reasons if reasons else ["Risk score below threshold and severity within acceptable limits"]

        return ExecutionDecision(
            request_id=request.request_id,
            decision=decision,
            risk_score=score,
            risk_level=level,
            reasons=final_reasons,
            indicators=indicators,
            dry_run=True,
            executed=False,
            error=None,
            policy_version=self.policy_version,
            provenance=DecisionProvenance.POLICY_ENGINE,
            enforcement_status=EnforcementStatus.NOT_ENFORCED,
            operation_type=OperationType.PROCESS,
        )

    def _evaluate_network_request(self, request: ExecutionRequest) -> ExecutionDecision:
        """Evaluate a network connection request."""
        remote_ip = (request.remote_ip or "").strip().lower()
        remote_port = request.remote_port
        proc_name = os.path.basename(request.executable).lower() if request.executable else ""

        # Mandatory blocks check first
        mandatory_block_reasons: List[str] = []
        if remote_port in self.blocked_ports:
            mandatory_block_reasons.append(
                f"Destination port {remote_port} is explicitly blocked by mandatory policy rule"
            )
        if remote_ip in self.blocked_ips:
            mandatory_block_reasons.append(
                f"Destination IP '{remote_ip}' is explicitly blocked by mandatory policy rule"
            )
        if proc_name and proc_name in self.blocked_executables:
            mandatory_block_reasons.append(
                f"Process '{proc_name}' initiating network connection is explicitly blocked by mandatory policy rule"
            )

        # Detect network risk indicators
        indicators: List[str] = []
        reasons: List[str] = []
        score = 0

        if remote_port in self.suspicious_ports:
            indicators.append("suspicious_network_port")
            reasons.append(f"Connection destination port {remote_port} is classified as suspicious/sensitive")
            score += 4

        if proc_name in self.unexpected_network_processes:
            indicators.append("unexpected_network_binary")
            reasons.append(f"Process '{proc_name}' is not expected to initiate network connections")
            score += 4

        if proc_name in self.script_interpreters and not is_loopback_or_local(remote_ip):
            indicators.append("script_interpreter_outbound")
            reasons.append(f"Script interpreter '{proc_name}' initiating outbound network connection to {remote_ip}:{remote_port}")
            score += 3

        level = "HIGH" if score >= 7 else ("MEDIUM" if score >= 4 else "LOW")

        # Mandatory block overrides
        if mandatory_block_reasons:
            return ExecutionDecision(
                request_id=request.request_id,
                decision=DecisionStatus.BLOCK,
                risk_score=score,
                risk_level=level,
                reasons=mandatory_block_reasons + reasons,
                indicators=indicators,
                dry_run=True,
                executed=False,
                error=None,
                policy_version=self.policy_version,
                provenance=DecisionProvenance.MANDATORY_RULE,
                enforcement_status=EnforcementStatus.NOT_ENFORCED,
                operation_type=OperationType.NETWORK,
            )

        # Threshold checks
        block_reasons: List[str] = []
        if score >= self.block_threshold:
            block_reasons.append(f"Network risk score {score} meets or exceeds block threshold {self.block_threshold}")
        if level in self.blocked_severities:
            block_reasons.append(f"Network risk severity '{level}' is blocked by policy")

        if block_reasons:
            decision = DecisionStatus.BLOCK
            final_reasons = block_reasons + reasons
        elif self.approval_threshold is not None and score >= self.approval_threshold:
            decision = DecisionStatus.REQUIRE_APPROVAL
            final_reasons = [f"Network risk score {score} requires user approval (threshold {self.approval_threshold})"] + reasons
        else:
            decision = DecisionStatus.ALLOW
            final_reasons = reasons if reasons else ["Network connection within acceptable risk boundaries"]

        return ExecutionDecision(
            request_id=request.request_id,
            decision=decision,
            risk_score=score,
            risk_level=level,
            reasons=final_reasons,
            indicators=indicators,
            dry_run=True,
            executed=False,
            error=None,
            policy_version=self.policy_version,
            provenance=DecisionProvenance.POLICY_ENGINE,
            enforcement_status=EnforcementStatus.NOT_ENFORCED,
            operation_type=OperationType.NETWORK,
        )

