"""
Controlled Execution Controller Module.

Orchestrates execution request intake, policy evaluation, dry-run safety gating,
and audit logging.
"""

import logging
from typing import Optional

from src.execution.policy import ExecutionPolicy
from src.models.execution_request import DecisionStatus, ExecutionDecision, ExecutionRequest


class ControlledExecutor:
    """
    Manages process execution requests and strictly enforces pre-launch policy gating.
    Guarantees that target processes are never launched in dry-run mode or during Phase 1.
    """

    def __init__(
        self,
        policy: Optional[ExecutionPolicy] = None,
        dry_run: bool = True,
        logger: Optional[logging.Logger] = None,
    ):
        self.policy: ExecutionPolicy = policy if policy is not None else ExecutionPolicy()
        self.dry_run: bool = dry_run
        self.logger: logging.Logger = (
            logger if logger is not None else logging.getLogger("endpoint_monitor")
        )

    def evaluate_request(self, request: ExecutionRequest) -> ExecutionDecision:
        """
        Evaluate an ExecutionRequest using the configured ExecutionPolicy.
        Does not attempt to launch any process.
        """
        decision = self.policy.evaluate(request)
        decision.dry_run = self.dry_run
        decision.executed = False
        return decision

    def request_execution(self, request: ExecutionRequest) -> ExecutionDecision:
        """
        Process an execution request:
        1. Evaluates request against policy.
        2. Logs decision.
        3. If BLOCK -> returns decision immediately with executed=False.
        4. If ALLOW -> in dry-run mode (or Phase 1 foundation), target process is never launched.
        """
        decision = self.evaluate_request(request)

        if decision.decision == DecisionStatus.BLOCK:
            self.logger.warning(
                f"[CONTROLLED EXECUTION] BLOCKED execution request {request.request_id} "
                f"for target '{request.executable}'. Score: {decision.risk_score}, "
                f"Level: {decision.risk_level}. Reasons: {decision.reasons}"
            )
            decision.executed = False
            return decision

        # Decision is ALLOW
        if self.dry_run:
            self.logger.info(
                f"[CONTROLLED EXECUTION] ALLOWED (DRY-RUN) execution request {request.request_id} "
                f"for target '{request.executable}'. Process launch suppressed by dry-run mode."
            )
            decision.executed = False
            return decision

        # Active process launch is prohibited in Phase 1 foundation
        self.logger.warning(
            f"[CONTROLLED EXECUTION] Active execution requested for {request.request_id}, "
            f"but active process launching is disabled in Phase 1 foundation."
        )
        decision.executed = False
        decision.error = "Active process launching is disabled in Phase 1 foundation"
        return decision
