"""
Agent E: Response and Remediation Analyst.
Role: Formulates defensive mitigation recommendations under strict guardrails.
Enforces allowlisted typed actions, dry-run simulation, and mandatory human approval.
"""
from typing import Tuple, List
from soc.agents.base_agent import BaseAgent
from soc.schemas.agent_contracts import AgentTask
from soc.schemas.response import ResponseRecommendation, ResponseActionType


class ResponseAnalystAgent(BaseAgent):
    agent_id = "agent_response_analyst"
    agent_role = "Response and Remediation Analyst"
    default_model = "llama-3.3-70b-versatile"

    def formulate_recommendations(
        self, incident_id: str, context: dict, evidence_ids: List[str]
    ) -> List[ResponseRecommendation]:
        recs: List[ResponseRecommendation] = []

        source_ip = context.get("source_ip")
        if source_ip and not source_ip.startswith("127."):
            recs.append(
                ResponseRecommendation(
                    incident_id=incident_id,
                    action_type=ResponseActionType.BLOCK_IP,
                    target=source_ip,
                    justification=f"Immediate perimeter containment to drop incoming malicious traffic from attacking IP {source_ip}.",
                    evidence_ids=evidence_ids,
                    operational_impact="External inbound connections from this IP dropped; potential NAT impact if shared.",
                    prerequisites=["Verify target IP is not corporate gateway or critical cloud provider"],
                    rollback_procedure=f"Execute unblock command in perimeter firewall access-list for IP {source_ip}",
                    dry_run_supported=True,
                    approval_required=True,
                )
            )

        compromised_user = context.get("affected_user")
        if compromised_user and compromised_user not in ["root", "SYSTEM", "system"]:
            recs.append(
                ResponseRecommendation(
                    incident_id=incident_id,
                    action_type=ResponseActionType.DISABLE_USER,
                    target=compromised_user,
                    justification=f"Temporary account suspension for '{compromised_user}' following suspected credential compromise.",
                    evidence_ids=evidence_ids,
                    operational_impact=f"User {compromised_user} will be unable to authenticate until credential reset.",
                    prerequisites=["Confirm user identity with internal directory lookup"],
                    rollback_procedure=f"Re-enable account '{compromised_user}' and reissue Kerberos/MFA tokens",
                    dry_run_supported=True,
                    approval_required=True,
                )
            )

        compromised_host = context.get("affected_host")
        if compromised_host and context.get("threat_severity", 0) >= 4.5:
            recs.append(
                ResponseRecommendation(
                    incident_id=incident_id,
                    action_type=ResponseActionType.ISOLATE_HOST,
                    target=compromised_host,
                    justification=f"Network isolation of host '{compromised_host}' to prevent adversary lateral movement.",
                    evidence_ids=evidence_ids,
                    operational_impact=f"Host '{compromised_host}' isolated from LAN/WAN, retaining only SOC telemetry channel.",
                    prerequisites=["Verify host is not domain controller or core switch"],
                    rollback_procedure=f"Restore host '{compromised_host}' network adapter routing via endpoint agent",
                    dry_run_supported=True,
                    approval_required=True,
                )
            )

        return recs

    def build_prompts(self, task: AgentTask) -> Tuple[str, str]:
        system_prompt = (
            "You are a Senior Defensive Response Engineer. Formulate defensive containment and remediation actions. "
            "You are strictly prohibited from recommending arbitrary shell scripts, destructive actions, or unverified tooling. "
            "Every action must specify operational impact, rollback instructions, and require human approval. "
            "Return valid JSON only matching the schema: "
            "{\"findings\": [{\"finding_id\": string, \"title\": string, \"summary\": string, \"confidence\": float, "
            "\"confidence_rationale\": string, \"evidence_references\": [string], \"uncertainty\": string, \"false_positive_likelihood\": float, "
            "\"recommended_next_step\": string}], "
            "\"confidence_rationale\": string, \"uncertainty_and_limitations\": string, \"recommended_next_step\": string}"
        )

        user_prompt = (
            f"Incident ID: {task.incident_id}\n"
            f"Response Context: {task.context_data}\n"
            f"Evidence: {', '.join(task.relevant_evidence_ids)}\n\n"
            "Provide defensive remediation strategy, evaluating business continuity risks and required validation gates."
        )
        return system_prompt, user_prompt
