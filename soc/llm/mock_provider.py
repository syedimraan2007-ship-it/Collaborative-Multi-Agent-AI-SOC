"""
Mock LLM Provider for Offline Testing and CI.
Returns schema-compliant, realistic structured findings without requiring network access or API keys.
"""
import json
from typing import Dict, Any, Optional

from soc.schemas.agent_contracts import AgentTask, AgentTaskType


class MockLLMProvider:
    """Simulates Groq API responses deterministically based on input task context."""

    def generate(self, task: AgentTask) -> Dict[str, Any]:
        task_type = task.task_type
        incident_id = task.incident_id
        ev_ids = task.relevant_evidence_ids or ["EVD-DEFAULT01"]

        if task_type == AgentTaskType.DETECTION_ANALYSIS:
            return {
                "findings": [
                    {
                        "finding_id": f"FND-DET-{incident_id[:6]}",
                        "title": "Confirmed Brute-Force Authentication Spike",
                        "summary": "Observed multiple consecutive failed logins from single IP address targeting critical infrastructure.",
                        "confidence": 0.94,
                        "confidence_rationale": "High frequency of failures (exceeding 5 attempts within 2 minutes) followed by no valid MFA token.",
                        "evidence_references": ev_ids,
                        "uncertainty": "External NAT/proxy could mask multiple real clients.",
                        "false_positive_likelihood": 0.05,
                        "mitre_technique_id": "T1110.001",
                        "mitre_technique_name": "Password Guessing",
                        "recommended_next_step": "Enrich source IP reputation and query authentication logs for affected user."
                    }
                ],
                "confidence_rationale": "Strict threshold matching corroborated by authentication failure logs.",
                "uncertainty_and_limitations": "Limited to telemetry received within the evaluated 5-minute ingestion buffer.",
                "recommended_next_step": "Execute threat intelligence lookup on external origin IP."
            }

        elif task_type == AgentTaskType.THREAT_INTEL_ENRICHMENT:
            target_indicator = task.context_data.get("indicator", "198.51.100.45")
            return {
                "findings": [
                    {
                        "finding_id": f"FND-INTEL-{incident_id[:6]}",
                        "title": f"Threat Intel Hit: Suspicious IP {target_indicator}",
                        "summary": f"Indicator {target_indicator} flagged with abuse confidence 87% across threat feeds.",
                        "confidence": 0.88,
                        "confidence_rationale": "Cross-referenced with historical botnet and scanner activity within last 48 hours.",
                        "evidence_references": ev_ids,
                        "uncertainty": "IP address belongs to a VPS hosting provider; possible dynamic reallocation.",
                        "false_positive_likelihood": 0.12,
                        "mitre_technique_id": "T1583.001",
                        "mitre_technique_name": "Acquire Infrastructure: Domains/IPs",
                        "recommended_next_step": "Cross-check all firewall egress logs for outbound beacons to this IP."
                    }
                ],
                "confidence_rationale": "High multi-source reputation match across community blocklists.",
                "uncertainty_and_limitations": "Historical data freshness is within 24 hours.",
                "recommended_next_step": "Proceed to correlated incident timeline reconstruction."
            }

        elif task_type == AgentTaskType.INCIDENT_INVESTIGATION:
            return {
                "findings": [
                    {
                        "finding_id": f"FND-INV-{incident_id[:6]}",
                        "title": "Adversary Progression: Reconnaissance to Credential Access",
                        "summary": "Correlated events demonstrate systematic reconnaissance followed by targeted credential guessing on host.",
                        "confidence": 0.91,
                        "confidence_rationale": "Direct temporal linkage: port scan precedes brute force by exactly 90 seconds from identical source IP.",
                        "evidence_references": ev_ids,
                        "uncertainty": "No process creation logs available for internal workstation during the event window.",
                        "false_positive_likelihood": 0.08,
                        "mitre_technique_id": "T1110",
                        "mitre_technique_name": "Brute Force",
                        "recommended_next_step": "Calculate multi-factor risk score and propose defensive firewall containment."
                    }
                ],
                "confidence_rationale": "Chronological timeline links network probes with authentication failures.",
                "uncertainty_and_limitations": "Endpoint EDR coverage is 90% on targeted subnet.",
                "recommended_next_step": "Dispatch risk assessment task to evaluate business impact."
            }

        elif task_type == AgentTaskType.RISK_ASSESSMENT:
            return {
                "findings": [
                    {
                        "finding_id": f"FND-RSK-{incident_id[:6]}",
                        "title": "High Business Exposure on Production Bastion",
                        "summary": "Assessed incident risk score at 82.5 (HIGH). High-value asset targeted with confirmed malicious intent.",
                        "confidence": 0.95,
                        "confidence_rationale": "Asset Criticality: 4.5/5 (Prod Bastion). Threat Severity: 4.0/5. Quality of evidence: 0.95.",
                        "evidence_references": ev_ids,
                        "uncertainty": "Exact secondary credentials compromised cannot be verified without AD audit.",
                        "false_positive_likelihood": 0.02,
                        "mitre_technique_id": "T1078",
                        "mitre_technique_name": "Valid Accounts",
                        "recommended_next_step": "Recommend urgent perimeter IP block and credential reset."
                    }
                ],
                "confidence_rationale": "Calculated via deterministic weighted risk formula v1.2.",
                "uncertainty_and_limitations": "Asset criticality registry last updated 7 days ago.",
                "recommended_next_step": "Forward to Response Analyst for remediation plan generation."
            }

        elif task_type == AgentTaskType.RESPONSE_PLANNING:
            return {
                "findings": [
                    {
                        "finding_id": f"FND-RSP-{incident_id[:6]}",
                        "title": "Remediation Plan: Perimeter IP Block & Session Revocation",
                        "summary": "Drafted 2 allowlisted containment actions: Block IP at border firewall (DRY-RUN validated) and revoke active SSH sessions.",
                        "confidence": 0.96,
                        "confidence_rationale": "Actions are minimally disruptive to business operations with immediate rollback procedure verified.",
                        "evidence_references": ev_ids,
                        "uncertainty": "Temporary IP block might affect other users behind shared carrier-grade NAT.",
                        "false_positive_likelihood": 0.01,
                        "mitre_technique_id": "M1037",
                        "mitre_technique_name": "Filter Network Traffic",
                        "recommended_next_step": "Await SOC Lead human approval in response control plane."
                    }
                ],
                "confidence_rationale": "Defense-in-depth containment plan adhering to least-disruption principle.",
                "uncertainty_and_limitations": "Simulated adapter mode active until live firewall credentials supplied.",
                "recommended_next_step": "Submit approval request to SOC analyst dashboard."
            }

        else:
            return {
                "findings": [
                    {
                        "finding_id": f"FND-GEN-{incident_id[:6]}",
                        "title": "General Multi-Agent Assessment",
                        "summary": "Multi-agent synthesis completed with validated telemetry.",
                        "confidence": 0.85,
                        "confidence_rationale": "Synthesized findings across all contributing agents.",
                        "evidence_references": ev_ids,
                        "uncertainty": "None",
                        "false_positive_likelihood": 0.1,
                    }
                ],
                "confidence_rationale": "Orchestrator synthesis.",
                "uncertainty_and_limitations": "None",
                "recommended_next_step": "Complete case file."
            }
