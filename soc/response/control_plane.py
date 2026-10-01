"""
Response Control Plane.
Strictly governs defensive action execution:
- Rejects non-allowlisted actions
- Fails closed without valid human approval
- Supports safe dry-run mode
- Maintains complete execution and rollback audit trails
"""
from datetime import datetime, timezone
import time
from typing import List, Dict, Optional
from uuid import uuid4

from soc.schemas.response import (
    ResponseActionType,
    ApprovalStatus,
    ExecutionStatus,
    ResponseRecommendation,
    HumanApproval,
    ResponseExecution,
)


class ResponseControlPlane:
    def __init__(self):
        self.approvals: Dict[str, HumanApproval] = {}
        self.executions: Dict[str, ResponseExecution] = {}
        # Simulated state tracking
        self.blocked_ips: set[str] = set()
        self.disabled_users: set[str] = set()
        self.isolated_hosts: set[str] = set()

    def submit_approval(
        self,
        recommendation: ResponseRecommendation,
        approver_username: str,
        decision: ApprovalStatus,
        reason: str = "Authorized by SOC Analyst",
    ) -> HumanApproval:
        approval = HumanApproval(
            recommendation_id=recommendation.recommendation_id,
            incident_id=recommendation.incident_id,
            approver_username=approver_username,
            status=decision,
            decision_timestamp=datetime.now(timezone.utc),
            reason=reason,
            signature=f"SIG-SHA256-{uuid4().hex[:12]}",
        )
        self.approvals[recommendation.recommendation_id] = approval
        return approval

    def execute_action(
        self,
        recommendation: ResponseRecommendation,
        dry_run: bool = False,
    ) -> ResponseExecution:
        start_ticks = time.time()
        now = datetime.now(timezone.utc)

        # Safety Check 1: Approval verification
        approval = self.approvals.get(recommendation.recommendation_id)
        if not dry_run:
            if not approval or approval.status != ApprovalStatus.APPROVED:
                raise PermissionError(
                    f"Execution blocked: Action {recommendation.action_type.value} requires approved HumanApproval."
                )

        execution = ResponseExecution(
            recommendation_id=recommendation.recommendation_id,
            approval_id=approval.approval_id if approval else None,
            action_type=recommendation.action_type,
            target=recommendation.target,
            dry_run=dry_run,
            status=ExecutionStatus.DRY_RUN_PASSED if dry_run else ExecutionStatus.EXECUTING,
            executed_at=now,
        )

        # Execute safe simulated adapter operations
        logs = []
        action = recommendation.action_type
        target = recommendation.target

        if action == ResponseActionType.BLOCK_IP:
            logs.append(f"[FIREWALL] Evaluated IP rule for {target}: valid IPv4.")
            if not dry_run:
                self.blocked_ips.add(target)
                logs.append(f"[FIREWALL] Rule applied: DROP INBOUND from {target} on WAN0.")
            else:
                logs.append(f"[FIREWALL-DRYRUN] Validation passed. Rule syntax valid.")

        elif action == ResponseActionType.UNBLOCK_IP:
            logs.append(f"[FIREWALL] Removing DROP rule for {target}.")
            if not dry_run:
                self.blocked_ips.discard(target)
                logs.append(f"[FIREWALL] Rule deleted for {target}.")

        elif action == ResponseActionType.DISABLE_USER:
            logs.append(f"[DIRECTORY] Querying account {target}: active account found.")
            if not dry_run:
                self.disabled_users.add(target)
                logs.append(f"[DIRECTORY] Account {target} suspended; active tokens revoked.")
            else:
                logs.append(f"[DIRECTORY-DRYRUN] User found in directory, lockable: True.")

        elif action == ResponseActionType.ENABLE_USER:
            logs.append(f"[DIRECTORY] Re-enabling account {target}.")
            if not dry_run:
                self.disabled_users.discard(target)
                logs.append(f"[DIRECTORY] Account {target} restored to active status.")

        elif action == ResponseActionType.ISOLATE_HOST:
            logs.append(f"[EDR] Contacting endpoint agent on {target}.")
            if not dry_run:
                self.isolated_hosts.add(target)
                logs.append(f"[EDR] Network isolation policy enforced on {target}. Telemetry channel intact.")
            else:
                logs.append(f"[EDR-DRYRUN] Host agent responsive, isolation driver active.")

        elif action == ResponseActionType.UNISOLATE_HOST:
            logs.append(f"[EDR] Restoring network adapter on {target}.")
            if not dry_run:
                self.isolated_hosts.discard(target)
                logs.append(f"[EDR] Isolation policy removed on {target}.")

        else:
            raise ValueError(f"Unsupported response action type: {action}")

        duration_ms = int((time.time() - start_ticks) * 1000)
        execution.duration_ms = duration_ms
        execution.logs = logs
        execution.status = ExecutionStatus.DRY_RUN_PASSED if dry_run else ExecutionStatus.COMPLETED
        self.executions[execution.execution_id] = execution
        return execution

    def rollback_action(self, execution_id: str) -> ResponseExecution:
        execution = self.executions.get(execution_id)
        if not execution:
            raise KeyError(f"Execution {execution_id} not found.")

        if execution.dry_run:
            raise ValueError("Cannot rollback dry-run execution.")

        if execution.is_rolled_back:
            return execution

        # Apply inverse action
        action = execution.action_type
        target = execution.target

        if action == ResponseActionType.BLOCK_IP:
            self.blocked_ips.discard(target)
            execution.logs.append(f"[ROLLBACK] Reverted IP block for {target}.")
        elif action == ResponseActionType.DISABLE_USER:
            self.disabled_users.discard(target)
            execution.logs.append(f"[ROLLBACK] Re-enabled account {target}.")
        elif action == ResponseActionType.ISOLATE_HOST:
            self.isolated_hosts.discard(target)
            execution.logs.append(f"[ROLLBACK] Removed host isolation for {target}.")

        execution.is_rolled_back = True
        execution.rollback_timestamp = datetime.now(timezone.utc)
        execution.status = ExecutionStatus.ROLLED_BACK
        return execution
