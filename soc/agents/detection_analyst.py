"""
Agent A: Detection Analyst.
Role: Interprets deterministic alerts, reviews normalized events, screens false positives,
and suggests follow-up enrichment without inventing unobserved facts.
"""
from typing import Tuple
from soc.agents.base_agent import BaseAgent
from soc.schemas.agent_contracts import AgentTask


class DetectionAnalystAgent(BaseAgent):
    agent_id = "agent_detection_analyst"
    agent_role = "Detection Analyst (Tier 1 Triage)"
    default_model = "llama-3.3-70b-versatile"

    def build_prompts(self, task: AgentTask) -> Tuple[str, str]:
        system_prompt = (
            "You are a Senior SOC Detection Analyst. Your mission is to analyze deterministic security alerts "
            "and normalized telemetry events. You must evaluate whether the alert represents genuine malicious activity "
            "or a benign false positive, cite exact event IDs and timestamps, and explain your reasoning in precise SOC terminology. "
            "CRITICAL: Never fabricate event IDs, IPs, users, or unobserved attack steps. "
            "Return valid JSON only matching the schema: "
            "{\"findings\": [{\"finding_id\": string, \"title\": string, \"summary\": string, \"confidence\": float (0.0-1.0), "
            "\"confidence_rationale\": string, \"evidence_references\": [string], \"uncertainty\": string, \"false_positive_likelihood\": float, "
            "\"mitre_technique_id\": string, \"mitre_technique_name\": string, \"recommended_next_step\": string}], "
            "\"confidence_rationale\": string, \"uncertainty_and_limitations\": string, \"recommended_next_step\": string}"
        )

        context_str = str(task.context_data)
        evidence_str = ", ".join(task.relevant_evidence_ids)

        user_prompt = (
            f"Incident ID: {task.incident_id}\n"
            f"Task Instructions: {task.scoped_instructions}\n"
            f"Relevant Evidence IDs: {evidence_str}\n"
            f"Telemetry Context: {context_str}\n\n"
            "Analyze these alerts. Produce structured findings assessing the alert fidelity, "
            "highlighting observed indicators, identifying any benign explanations, and recommending the next SOC step."
        )
        return system_prompt, user_prompt
