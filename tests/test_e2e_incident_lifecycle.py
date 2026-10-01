"""
End-to-End Test for Complete Incident Lifecycle.
Verifies telemetry ingestion -> deterministic detection -> multi-agent orchestration ->
risk calculation -> response recommendation -> human approval -> execution -> resolution.
"""
from soc.detection import create_default_detection_engine
from soc.agents.orchestrator import CentralOrchestrator
from soc.response.control_plane import ResponseControlPlane
from soc.schemas.incidents import IncidentLifecycleState
from soc.schemas.response import ApprovalStatus, ExecutionStatus
from soc.ingestion.synthetic_replay import generate_ssh_bruteforce_scenario


def test_full_incident_lifecycle_e2e(mock_groq_client):
    # 1. Telemetry Ingestion
    events = generate_ssh_bruteforce_scenario(attacker_ip="198.51.100.45", fail_count=6)
    assert len(events) == 6

    # 2. Deterministic Rule Detection
    engine = create_default_detection_engine()
    alerts = engine.analyze(events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-DET-001"

    # 3. Multi-Agent Orchestration
    orchestrator = CentralOrchestrator(mock_groq_client)
    incident = orchestrator.orchestrate_incident(alert)

    assert incident.state == IncidentLifecycleState.CONTAINMENT_RECOMMENDED
    assert len(incident.timeline) >= 5
    assert len(incident.findings) >= 4
    assert len(incident.mitre_mappings) >= 1
    assert incident.mitre_mappings[0].technique_id == "T1110.001"
    assert incident.risk_assessment is not None
    assert incident.risk_assessment.score > 0
    assert len(incident.response_recommendations) >= 1

    # 4. Human Approval Gate
    rec = incident.response_recommendations[0]
    control_plane = ResponseControlPlane()
    approval = control_plane.submit_approval(
        recommendation=rec,
        approver_username="analyst_alice",
        decision=ApprovalStatus.APPROVED,
        reason="Verified active attack against production server",
    )
    assert approval.status == ApprovalStatus.APPROVED

    # 5. Defensive Execution
    execution = control_plane.execute_action(rec, dry_run=False)
    assert execution.status == ExecutionStatus.COMPLETED
    assert "198.51.100.45" in control_plane.blocked_ips
