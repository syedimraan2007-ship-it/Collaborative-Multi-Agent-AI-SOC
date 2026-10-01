"""
Agent Communication and Evidence Contracts (v1.0.0).
Defines strictly validated Pydantic v2 schemas for tasks, findings, results, and traces.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from uuid import uuid4
from pydantic import BaseModel, Field


class AgentTaskType(str, Enum):
    DETECTION_ANALYSIS = "detection_analysis"
    THREAT_INTEL_ENRICHMENT = "threat_intel_enrichment"
    INCIDENT_INVESTIGATION = "incident_investigation"
    RISK_ASSESSMENT = "risk_assessment"
    RESPONSE_PLANNING = "response_planning"
    ORCHESTRATION_SYNTHESIS = "orchestration_synthesis"


class AgentTaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class EvidenceReference(BaseModel):
    """Immutable reference linking an analytical conclusion to ground-truth telemetry."""
    evidence_id: str = Field(default_factory=lambda: f"EVD-{uuid4().hex[:8].upper()}")
    source_event_id: str
    artifact_type: str = Field(..., description="e.g. ip_indicator, auth_log, process_exec, network_flow")
    summary: str
    observed_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_hash: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)


class AgentFinding(BaseModel):
    """Atomic finding discovered by an AI agent."""
    finding_id: str = Field(default_factory=lambda: f"FND-{uuid4().hex[:8].upper()}")
    title: str
    summary: str
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score strictly bounded [0.0, 1.0]")
    confidence_rationale: str = Field(..., description="Explainable justification for why this confidence was assigned")
    evidence_references: List[str] = Field(default_factory=list, description="IDs of EvidenceReference supporting this finding")
    uncertainty: str = Field(default="None identified", description="Missing evidence, telemetry gaps, or alternative interpretations")
    false_positive_likelihood: float = Field(default=0.1, ge=0.0, le=1.0)
    mitre_technique_id: Optional[str] = Field(default=None, description="e.g. T1110.001, T1078, T1046")
    mitre_technique_name: Optional[str] = None
    recommended_next_step: Optional[str] = None


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


class AgentTask(BaseModel):
    """Work package dispatched by Central Orchestrator to a specialized agent."""
    task_id: str = Field(default_factory=lambda: f"TSK-{uuid4().hex[:8].upper()}")
    incident_id: str
    agent_id: str
    task_type: AgentTaskType
    schema_version: str = "1.0.0"
    correlation_id: str = Field(default_factory=lambda: str(uuid4()))
    scoped_instructions: str
    relevant_evidence_ids: List[str] = Field(default_factory=list)
    context_data: Dict[str, Any] = Field(default_factory=dict)
    deadline_seconds: int = 30
    token_budget: int = 4096
    permitted_capabilities: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AgentResult(BaseModel):
    """Validated structured response from an agent back to Orchestrator."""
    task_id: str
    incident_id: str
    agent_id: str
    status: AgentTaskStatus
    structured_findings: List[AgentFinding] = Field(default_factory=list)
    evidence_references: List[EvidenceReference] = Field(default_factory=list)
    confidence_rationale: str = ""
    uncertainty_and_limitations: str = ""
    recommended_next_step: Optional[str] = None
    execution_time_ms: int = 0
    model_name: Optional[str] = None
    token_usage: TokenUsage = Field(default_factory=TokenUsage)
    error_message: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AgentExecutionTrace(BaseModel):
    """Audit log entry capturing prompt, latency, tokens, and decisions for security review."""
    trace_id: str = Field(default_factory=lambda: f"TRC-{uuid4().hex[:8].upper()}")
    task_id: str
    incident_id: str
    agent_id: str
    model_name: str
    start_time: datetime
    end_time: datetime
    duration_ms: int
    prompt_tokens: int
    completion_tokens: int
    status: str
    sanitized_prompt_summary: str
    sanitized_response_summary: str
    error_details: Optional[str] = None
