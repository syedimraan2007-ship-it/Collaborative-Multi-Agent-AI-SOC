"""
Agent D: Risk Assessment Analyst.
Role: Applies a deterministic, explainable mathematical scoring formula to compute incident risk,
combining asset criticality, threat severity, exposure, and evidence verification.
"""
from typing import Tuple
from soc.agents.base_agent import BaseAgent
from soc.schemas.agent_contracts import AgentTask
from soc.schemas.risk import RiskAssessment, RiskFactors, RiskSeverity


def calculate_deterministic_risk(
    asset_criticality: float,
    threat_severity: float,
    exposure_level: float,
    evidence_quality: float,
    confirmatory_intel: float = 1.0,
) -> Tuple[float, RiskSeverity]:
    """
    Deterministic scoring formula:
    Base = (Asset * 0.35 + Threat * 0.40 + Exposure * 0.25) / 5.0 * 100
    Adjusted = Base * EvidenceQuality * (1.1 if confirmatory_intel > 1.2 else 1.0)
    Bounded strictly in [0.0, 100.0]
    """
    raw_base = (
        (asset_criticality * 0.35)
        + (threat_severity * 0.40)
        + (exposure_level * 0.25)
    ) / 5.0 * 100.0

    intel_multiplier = 1.15 if confirmatory_intel > 1.2 else 1.0
    final_score = min(100.0, max(0.0, raw_base * evidence_quality * intel_multiplier))

    if final_score >= 80.0:
        severity = RiskSeverity.CRITICAL
    elif final_score >= 60.0:
        severity = RiskSeverity.HIGH
    elif final_score >= 40.0:
        severity = RiskSeverity.MEDIUM
    elif final_score >= 20.0:
        severity = RiskSeverity.LOW
    else:
        severity = RiskSeverity.INFORMATIONAL

    return round(final_score, 1), severity


class RiskAnalystAgent(BaseAgent):
    agent_id = "agent_risk_analyst"
    agent_role = "Risk Assessment Analyst"
    default_model = "llama-3.3-70b-versatile"

    def compute_assessment(self, incident_id: str, context: dict) -> RiskAssessment:
        asset_crit = float(context.get("asset_criticality", 3.5))
        threat_sev = float(context.get("threat_severity", 4.0))
        exposure = float(context.get("exposure_level", 4.0))
        ev_quality = float(context.get("evidence_quality", 0.9))
        intel_fact = float(context.get("confirmatory_intel", 1.3))

        score, severity = calculate_deterministic_risk(
            asset_crit, threat_sev, exposure, ev_quality, intel_fact
        )

        factors = RiskFactors(
            asset_criticality=asset_crit,
            threat_severity=threat_sev,
            exposure_level=exposure,
            evidence_quality=ev_quality,
            confirmatory_intel=intel_fact,
        )

        return RiskAssessment(
            incident_id=incident_id,
            score=score,
            severity=severity,
            factors=factors,
            rationale=(
                f"Incident scored {score}/100 ({severity.value.upper()}) using deterministic rule v1.2. "
                f"Weights: Asset ({asset_crit}/5, 35%), Threat ({threat_sev}/5, 40%), Exposure ({exposure}/5, 25%). "
                f"Evidence quality modifier: {ev_quality}. CTI confirmation boost applied: {intel_fact > 1.2}."
            ),
            uncertainty="Score dependent on reported host classification in CMDB.",
            escalation_recommended=(score >= 60.0),
        )

    def build_prompts(self, task: AgentTask) -> Tuple[str, str]:
        system_prompt = (
            "You are a Senior Cyber Risk Architect. Explain the business impact, operational threat, "
            "and regulatory implications of the calculated risk assessment. Never override deterministic math scores."
            "Return valid JSON only matching the schema: "
            "{\"findings\": [{\"finding_id\": string, \"title\": string, \"summary\": string, \"confidence\": float, "
            "\"confidence_rationale\": string, \"evidence_references\": [string], \"uncertainty\": string, \"false_positive_likelihood\": float, "
            "\"recommended_next_step\": string}], "
            "\"confidence_rationale\": string, \"uncertainty_and_limitations\": string, \"recommended_next_step\": string}"
        )

        user_prompt = (
            f"Incident ID: {task.incident_id}\n"
            f"Risk Assessment Request: {task.scoped_instructions}\n"
            f"Parameters: {task.context_data}\n\n"
            "Provide the executive risk impact explanation and recommend escalation actions."
        )
        return system_prompt, user_prompt
