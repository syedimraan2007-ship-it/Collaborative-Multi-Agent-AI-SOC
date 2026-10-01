"""
FastAPI REST API Service for SOC Platform.
Provides authenticated endpoints, telemetry ingestion, alert triage,
multi-agent investigation triggering, response control plane, and system metrics.
"""
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from soc.schemas.events import CanonicalSecurityEvent
from soc.schemas.incidents import Incident, IncidentLifecycleState
from soc.schemas.response import (
    ApprovalStatus,
    HumanApproval,
    ResponseExecution,
    ResponseRecommendation,
)
from soc.detection import create_default_detection_engine, DetectionAlert
from soc.agents.orchestrator import CentralOrchestrator
from soc.response.control_plane import ResponseControlPlane
from soc.llm.groq_client import GroqClient, SUPPORTED_GROQ_MODELS
from soc.ingestion.synthetic_replay import (
    generate_ssh_bruteforce_scenario,
    generate_password_spray_scenario,
    generate_auth_fail_then_success_scenario,
    generate_port_scan_scenario,
    generate_suspicious_dns_scenario,
    generate_lolbin_execution_scenario,
    generate_unusual_c2_beacon_scenario,
    generate_benign_traffic_scenario,
)
from soc.evaluation.benchmarks import run_soc_benchmarks

app = FastAPI(
    title="Collaborative Multi-Agent AI SOC API",
    description="Multi-Agent Threat Detection, Investigation, Risk Assessment, and Controlled Incident Response",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory single-node state store (persisted in SQLite/Postgres in production)
detection_engine = create_default_detection_engine()
groq_client = GroqClient()
orchestrator = CentralOrchestrator(groq_client)
control_plane = ResponseControlPlane()

events_store: List[CanonicalSecurityEvent] = []
alerts_store: Dict[str, DetectionAlert] = {}
incidents_store: Dict[str, Incident] = {}


class ReplayRequest(BaseModel):
    scenario: str = Field(..., description="ssh_bruteforce, password_spray, auth_fail_success, port_scan, dns_dga, lolbin, c2_beacon, benign")
    auto_investigate: bool = True


class ApprovalRequest(BaseModel):
    recommendation_id: str
    incident_id: str
    approver: str = "soc_analyst"
    decision: ApprovalStatus = ApprovalStatus.APPROVED
    reason: str = "Authorized after analyst review"


class ExecutionRequest(BaseModel):
    recommendation_id: str
    dry_run: bool = False


class RollbackRequest(BaseModel):
    execution_id: str


class ConfigUpdateRequest(BaseModel):
    groq_api_key: Optional[str] = None
    default_model: Optional[str] = None


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "collaborative-multi-agent-soc",
        "version": "1.0.0",
        "groq_live": groq_client.is_live,
        "default_model": groq_client.default_model,
        "supported_models": SUPPORTED_GROQ_MODELS,
        "events_count": len(events_store),
        "alerts_count": len(alerts_store),
        "incidents_count": len(incidents_store),
    }


@app.post("/api/ingestion/stream")
def ingest_events(events: List[CanonicalSecurityEvent]):
    events_store.extend(events)
    # Run deterministic detection engine
    new_alerts = detection_engine.analyze(events)
    for alert in new_alerts:
        alerts_store[alert.alert_id] = alert
    return {"ingested_events": len(events), "new_alerts": len(new_alerts), "alerts": [a.model_dump(mode="json") for a in new_alerts]}


@app.post("/api/ingestion/replay")
def replay_scenario(req: ReplayRequest):
    generators = {
        "ssh_bruteforce": generate_ssh_bruteforce_scenario,
        "password_spray": generate_password_spray_scenario,
        "auth_fail_success": generate_auth_fail_then_success_scenario,
        "port_scan": generate_port_scan_scenario,
        "dns_dga": generate_suspicious_dns_scenario,
        "lolbin": generate_lolbin_execution_scenario,
        "c2_beacon": generate_unusual_c2_beacon_scenario,
        "benign": generate_benign_traffic_scenario,
    }

    gen = generators.get(req.scenario)
    if not gen:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{req.scenario}'. Available: {list(generators.keys())}")

    events = gen()
    events_store.extend(events)
    new_alerts = detection_engine.analyze(events)

    created_incidents = []
    for alert in new_alerts:
        alerts_store[alert.alert_id] = alert
        if req.auto_investigate:
            incident = orchestrator.orchestrate_incident(alert)
            incidents_store[incident.incident_id] = incident
            created_incidents.append(incident.model_dump(mode="json"))

    return {
        "scenario": req.scenario,
        "events_generated": len(events),
        "alerts_triggered": len(new_alerts),
        "incidents_created": len(created_incidents),
        "incidents": created_incidents,
    }


@app.get("/api/alerts")
def list_alerts():
    return list(alerts_store.values())


@app.get("/api/incidents")
def list_incidents():
    return list(incidents_store.values())


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    inc = incidents_store.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.post("/api/incidents/{alert_id}/investigate")
def investigate_alert(alert_id: str):
    alert = alerts_store.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    incident = orchestrator.orchestrate_incident(alert)
    incidents_store[incident.incident_id] = incident
    return incident


@app.post("/api/response/approve")
def approve_recommendation(req: ApprovalRequest):
    # Locate recommendation
    target_rec: Optional[ResponseRecommendation] = None
    target_inc: Optional[Incident] = None

    for inc in incidents_store.values():
        for r in inc.response_recommendations:
            if r.recommendation_id == req.recommendation_id:
                target_rec = r
                target_inc = inc
                break

    if not target_rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")

    approval = control_plane.submit_approval(
        recommendation=target_rec,
        approver_username=req.approver,
        decision=req.decision,
        reason=req.reason,
    )

    if req.decision == ApprovalStatus.APPROVED and target_inc:
        target_inc.state = IncidentLifecycleState.AWAITING_APPROVAL

    return approval


@app.post("/api/response/execute")
def execute_response(req: ExecutionRequest):
    target_rec: Optional[ResponseRecommendation] = None
    target_inc: Optional[Incident] = None

    for inc in incidents_store.values():
        for r in inc.response_recommendations:
            if r.recommendation_id == req.recommendation_id:
                target_rec = r
                target_inc = inc
                break

    if not target_rec:
        raise HTTPException(status_code=404, detail="Recommendation not found")

    try:
        execution = control_plane.execute_action(
            recommendation=target_rec,
            dry_run=req.dry_run,
        )
        if not req.dry_run and target_inc:
            target_inc.state = IncidentLifecycleState.CONTAINED
        return execution
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/response/rollback")
def rollback_response(req: RollbackRequest):
    try:
        execution = control_plane.rollback_action(req.execution_id)
        return execution
    except KeyError as ke:
        raise HTTPException(status_code=404, detail=str(ke))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/traces")
def get_agent_traces():
    return orchestrator.traces[-50:]


@app.get("/api/metrics")
def get_metrics():
    benchmarks = run_soc_benchmarks()
    token_metrics = groq_client.token_tracker.metrics
    return {
        "benchmarks": benchmarks,
        "tokens": token_metrics,
        "control_plane": {
            "blocked_ips": list(control_plane.blocked_ips),
            "disabled_users": list(control_plane.disabled_users),
            "isolated_hosts": list(control_plane.isolated_hosts),
            "total_executions": len(control_plane.executions),
        },
        "counts": {
            "events": len(events_store),
            "alerts": len(alerts_store),
            "incidents": len(incidents_store),
        }
    }


@app.post("/api/config")
def update_config(req: ConfigUpdateRequest):
    global groq_client, orchestrator
    if req.groq_api_key is not None:
        groq_client = GroqClient(api_key=req.groq_api_key, default_model=req.default_model or groq_client.default_model)
        orchestrator = CentralOrchestrator(groq_client)
    elif req.default_model is not None:
        groq_client.default_model = req.default_model
    return {
        "status": "updated",
        "groq_live": groq_client.is_live,
        "default_model": groq_client.default_model,
    }
