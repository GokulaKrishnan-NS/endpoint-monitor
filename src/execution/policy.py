"""
Execution Policy Evaluation Module.

Evaluates an ExecutionRequest before process launch by integrating with:
- Command indicator detection (detect_command_indicators)
- Process tree lineage analysis (ProcessTreeAnalyzer.evaluate_parent_child)
- Risk scoring engine (calculate_risk)

Enforces fail-closed semantics: any validation or analyzer failure results in BLOCK.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Set

from src.analysis.process_tree import ProcessTreeAnalyzer
from src.detectors.command_detector import detect_command_indicators
from src.detectors.risk_detector import calculate_risk
from src.execution.config import load_execution_config
from src.models.execution_request import DecisionStatus, ExecutionDecision, ExecutionRequest


class ExecutionPolicy:
    """
    Configurable security policy that inspects proposed process execution requests
    and issues explicit ALLOW or BLOCK decisions.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: str = "config/config.json",
        tree_analyzer: Optional[ProcessTreeAnalyzer] = None,
    ):
        self.config: Dict[str, Any] = (
            config if config is not None else load_execution_config(config_path)
        )
        self.logger = logging.getLogger("endpoint_monitor")

        self.enabled: bool = bool(self.config.get("enabled", True))
        self.score_threshold: int = int(self.config.get("score_threshold", 7))
        self.blocked_severities: Set[str] = set(
            self.config.get("blocked_severities", ["HIGH"])
        )
        self.blocked_indicators: Set[str] = set(
            self.config.get("blocked_indicators", [])
        )
        self.fail_closed: bool = bool(self.config.get("fail_closed", True))

        if tree_analyzer is not None:
            self.tree_analyzer = tree_analyzer
        else:
            self.tree_analyzer = ProcessTreeAnalyzer(config_path=config_path)

    def evaluate(self, request: ExecutionRequest) -> ExecutionDecision:
        """
        Evaluate an ExecutionRequest against configured security policies.
        Returns an ExecutionDecision with decision status, score, reasons, and indicators.
        Guarantees fail-closed BLOCK behavior if validation or analysis fails.
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
            )

        # 1. Validate request structure and field types
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
            )

        # 2. If policy engine is disabled, return ALLOW
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
            )

        # 3. Analyze request using existing detectors with fail-closed exception handling
        try:
            # 3a. Command indicator detection
            cmdline = request.command_line
            indicators: List[str] = detect_command_indicators(cmdline)

            # 3b. Process tree lineage analysis (parent-child relationship)
            tree_findings: List[Dict[str, Any]] = []
            if request.parent_process_name:
                proc_name = os.path.basename(request.executable)
                tree_findings = self.tree_analyzer.evaluate_parent_child(
                    request.parent_process_name, proc_name
                )
                for finding in tree_findings:
                    ind = finding.get("indicator")
                    if ind and ind not in indicators:
                        indicators.append(ind)

            # 3c. Calculate overall risk using the existing risk scoring engine
            process_info = request.to_process_info()
            risk_result = calculate_risk(
                indicators=indicators,
                process_info=process_info,
                tree_findings=tree_findings,
            )

            score: int = risk_result.get("score", 0)
            level: str = risk_result.get("level", "LOW")
            reasons: List[str] = list(risk_result.get("reasons", []))

            # 4. Determine policy decision based on score, severity, and indicator rules
            block_reasons: List[str] = []

            if score >= self.score_threshold:
                block_reasons.append(
                    f"Risk score {score} meets or exceeds threshold {self.score_threshold}"
                )

            if level in self.blocked_severities:
                block_reasons.append(
                    f"Risk severity level '{level}' is blocked by policy ({sorted(self.blocked_severities)})"
                )

            for ind in indicators:
                if ind in self.blocked_indicators:
                    block_reasons.append(
                        f"Detected indicator '{ind}' is explicitly blocked by policy"
                    )

            if block_reasons:
                decision = DecisionStatus.BLOCK
                final_reasons = block_reasons + reasons
            else:
                decision = DecisionStatus.ALLOW
                final_reasons = (
                    reasons
                    if reasons
                    else ["Risk score below threshold and severity within acceptable limits"]
                )

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
            )

        except Exception as exc:
            err_msg = f"Analyzer error during evaluation: {exc}"
            self.logger.error(f"Request {request.request_id} evaluation failed: {exc}", exc_info=True)
            # Fail closed: never default to allowing execution when analysis fails
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
            )
