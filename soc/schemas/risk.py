"""
Explainable Risk Assessment Schema (v1.0.0).
Enforces deterministic scoring rules and transparent mathematical formulas.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Any
from uuid import uuid4
from pydantic import BaseModel, Field


class RiskSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskFactors(BaseModel):
    asset_criticality: float = Field(..., ge=1.0, le=5.0, description="Asset importance factor: 1.0 (Lab) to 5.0 (Domain Controller/Prod DB)")
    threat_severity: float = Field(..., ge=1.0, le=5.0, description="Observed threat behavior severity")
    exposure_level: float = Field(..., ge=1.0, le=5.0, description="Network boundary exposure: internal (1) to internet-facing (5)")
    evidence_quality: float = Field(..., ge=0.2, le=1.0, description="Verification certainty factor based on correlated evidence")
    confirmatory_intel: float = Field(default=1.0, ge=1.0, le=2.0, description="Multiplication factor if threat intel confirmed malicious")


class RiskAssessment(BaseModel):
    """Deterministic, auditable calculation of incident risk."""
    assessment_id: str = Field(default_factory=lambda: f"RSK-{uuid4().hex[:8].upper()}")
    incident_id: str
    score: float = Field(..., ge=0.0, le=100.0, description="Overall incident risk score from 0.0 to 100.0")
    severity: RiskSeverity
    factors: RiskFactors
    scoring_rule_version: str = "v1.2-deterministic-weighted"
    formula_explanation: str = "BaseScore = (Asset * 0.35 + Threat * 0.40 + Exposure * 0.25) * 20 * EvidenceQuality * IntelFactor"
    rationale: str
    uncertainty: str
    escalation_recommended: bool = False
    evidence_references: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
