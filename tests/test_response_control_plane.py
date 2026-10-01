"""
Tests for Response Control Plane: Authorization Gates, Dry-Run, and Rollback.
"""
import pytest
from soc.response.control_plane import ResponseControlPlane
from soc.schemas.response import (
    ResponseRecommendation,
    ResponseActionType,
    ApprovalStatus,
    ExecutionStatus,
)


def test_unapproved_action_fails_closed(control_plane):
    rec = ResponseRecommendation(
        incident_id="INC-TEST01",
        action_type=ResponseActionType.BLOCK_IP,
        target="198.51.100.99",
        justification="Perimeter block",
        operational_impact="Drop inbound traffic",
        rollback_procedure="Remove iptables rule",
    )
    # Must fail closed if not approved
    with pytest.raises(PermissionError):
        control_plane.execute_action(rec, dry_run=False)


def test_dry_run_allowed_without_approval(control_plane):
    rec = ResponseRecommendation(
        incident_id="INC-TEST02",
        action_type=ResponseActionType.BLOCK_IP,
        target="198.51.100.99",
        justification="Perimeter block",
        operational_impact="Drop inbound traffic",
        rollback_procedure="Remove iptables rule",
    )
    execution = control_plane.execute_action(rec, dry_run=True)
    assert execution.status == ExecutionStatus.DRY_RUN_PASSED
    assert "198.51.100.99" not in control_plane.blocked_ips


def test_approved_action_and_rollback(control_plane):
    rec = ResponseRecommendation(
        incident_id="INC-TEST03",
        action_type=ResponseActionType.BLOCK_IP,
        target="203.0.113.55",
        justification="Perimeter block",
        operational_impact="Drop inbound traffic",
        rollback_procedure="Remove iptables rule",
    )
    # Approve
    control_plane.submit_approval(
        recommendation=rec,
        approver_username="lead_analyst",
        decision=ApprovalStatus.APPROVED,
    )
    execution = control_plane.execute_action(rec, dry_run=False)
    assert execution.status == ExecutionStatus.COMPLETED
    assert "203.0.113.55" in control_plane.blocked_ips

    # Rollback
    rolled = control_plane.rollback_action(execution.execution_id)
    assert rolled.status == ExecutionStatus.ROLLED_BACK
    assert "203.0.113.55" not in control_plane.blocked_ips
