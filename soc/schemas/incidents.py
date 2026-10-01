"""
Incident Management and Case Lifecycle Schema (v1.0.0).
Defines lifecycle states, incident records, timeline entries, and case management models.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from uuid import uuid4
from pydantic import BaseModel, Field

from soc.schemas.agent_contracts import AgentFinding
from soc.schemas.risk import RiskAssessment
from soc.schemas.response import ResponseRecommendation


class IncidentLifecycleState(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINMENT_RECOMMENDED = "CONTAINMENT_RECOMMENDED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    CONTAINED = "CONTAINED"
    MITIGATED = "MITIGATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class IncidentTimelineEntry(BaseModel):
    entry_id: str = Field(default_factory=lambda: f"TL-{uuid4().hex[:8].upper()}")
    incident_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    phase: str = Field(..., description="e.g. Ingestion, Detection, Correlation, Investigation, Risk, Response")
    title: str
    description: str
    source_event_id: Optional[str] = None
    agent_id: Optional[str] = None
    evidence_id: Optional[str] = None


class MitreTechniqueMapping(BaseModel):
    technique_id: str = Field(..., description="e.g. T1110.001")
    technique_name: str
    tactic: str = Field(..., description="e.g. Credential Access, Initial Access, Execution")
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_event_ids: List[str] = Field(default_factory=list)
    rationale: str


class Incident(BaseModel):
    """Core Case Record tracking an ongoing or resolved security incident."""
    incident_id: str = Field(default_factory=lambda: f"INC-{uuid4().hex[:8].upper()}")
    title: str
    description: str
    state: IncidentLifecycleState = IncidentLifecycleState.NEW
    severity: str = "medium"
    priority: int = Field(default=3, ge=1, le=5, description="1 (P1-Critical) to 5 (P5-Low)")
    
    source_alert_ids: List[str] = Field(default_factory=list)
    correlated_event_ids: List[str] = Field(default_factory=list)
    
    # Entities
    affected_hosts: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    affected_ips: List[str] = Field(default_factory=list)
    
    # Analytical Artifacts
    timeline: List[IncidentTimelineEntry] = Field(default_factory=list)
    findings: List[AgentFinding] = Field(default_factory=list)
    mitre_mappings: List[MitreTechniqueMapping] = Field(default_factory=list)
    risk_assessment: Optional[RiskAssessment] = None
    response_recommendations: List[ResponseRecommendation] = Field(default_factory=list)
    
    # Audit & Analyst
    assigned_analyst: Optional[str] = "unassigned"
    analyst_notes: List[str] = Field(default_factory=list)
    closure_reason: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
