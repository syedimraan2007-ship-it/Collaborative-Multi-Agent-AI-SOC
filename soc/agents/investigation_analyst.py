"""
Agent C: Investigation Analyst.
Role: Correlates events across hosts, users, indicators, and time windows.
Constructs chronological timelines and maps observed adversary behavior to MITRE ATT&CK techniques.
"""
from typing import Tuple
from soc.agents.base_agent import BaseAgent
from soc.schemas.agent_contracts import AgentTask


class InvestigationAnalystAgent(BaseAgent):
    agent_id = "agent_investigation_analyst"
    agent_role = "Senior Incident Investigator (Tier 2/3)"
    default_model = "llama-3.3-70b-versatile"

    def build_prompts(self, task: AgentTask) -> Tuple[str, str]:
        system_prompt = (
            "You are a Senior Incident Investigator in a Security Operations Center. Your mission is to correlate "
            "security events across network, identity, host, and cloud telemetry. Reconstruct the adversary attack sequence "
            "in chronological order. Map behaviors strictly to MITRE ATT&CK techniques where explicit evidence exists. "
            "Explicitly separate verified facts from working hypotheses. "
            "Return valid JSON only matching the schema: "
            "{\"findings\": [{\"finding_id\": string, \"title\": string, \"summary\": string, \"confidence\": float (0.0-1.0), "
            "\"confidence_rationale\": string, \"evidence_references\": [string], \"uncertainty\": string, \"false_positive_likelihood\": float, "
            "\"mitre_technique_id\": string, \"mitre_technique_name\": string, \"recommended_next_step\": string}], "
            "\"confidence_rationale\": string, \"uncertainty_and_limitations\": string, \"recommended_next_step\": string}"
        )

        user_prompt = (
            f"Incident ID: {task.incident_id}\n"
            f"Investigation Instructions: {task.scoped_instructions}\n"
            f"Correlated Event IDs: {', '.join(task.relevant_evidence_ids)}\n"
            f"Context Data: {task.context_data}\n\n"
            "Build the attack sequence, evaluate lateral movement or privilege escalation indications, "
            "map verified steps to MITRE ATT&CK, and identify telemetry gaps."
        )
        return system_prompt, user_prompt
