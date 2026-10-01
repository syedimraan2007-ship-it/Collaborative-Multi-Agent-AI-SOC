"""
Central Multi-Agent Orchestrator and Incident Coordinator (Agent F).
Coordinates the investigative workflow DAG across specialized AI agents,
enforces execution budgets and safety policies, and synthesizes evidence-linked incident reports.
"""
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from soc.llm.groq_client import GroqClient
from soc.detection.engine import DetectionAlert
from soc.agents.detection_analyst import DetectionAnalystAgent
from soc.agents.threat_intel_analyst import ThreatIntelAnalystAgent
from soc.agents.investigation_analyst import InvestigationAnalystAgent
from soc.agents.risk_analyst import RiskAnalystAgent
from soc.agents.response_analyst import ResponseAnalystAgent
from soc.schemas.agent_contracts import (
    AgentTask,
    AgentResult,
    AgentTaskType,
    AgentExecutionTrace,
    EvidenceReference,
)
from soc.schemas.incidents import (
    Incident,
    IncidentLifecycleState,
    IncidentTimelineEntry,
    MitreTechniqueMapping,
)

logger = logging.getLogger("soc.orchestrator")


class CentralOrchestrator:
    def __init__(self, groq_client: Optional[GroqClient] = None):
        self.groq_client = groq_client or GroqClient()
        self.agent_detection = DetectionAnalystAgent(self.groq_client)
        self.agent_threat_intel = ThreatIntelAnalystAgent(self.groq_client)
        self.agent_investigation = InvestigationAnalystAgent(self.groq_client)
        self.agent_risk = RiskAnalystAgent(self.groq_client)
        self.agent_response = ResponseAnalystAgent(self.groq_client)

        self.traces: List[AgentExecutionTrace] = []

    def orchestrate_incident(self, alert: DetectionAlert) -> Incident:
        """
        Executes the bounded collaborative multi-agent workflow DAG for a detected alert.
        Transitions incident states from NEW -> TRIAGED -> INVESTIGATING -> CONTAINMENT_RECOMMENDED.
        """
        incident_id = f"INC-{alert.alert_id.replace('ALT-', '')}"
        now = datetime.now(timezone.utc)

        # Initialize Incident
        incident = Incident(
            incident_id=incident_id,
            title=f"Incident: {alert.rule_name} ({alert.source_ip or alert.affected_host})",
            description=alert.description,
            state=IncidentLifecycleState.NEW,
            severity=alert.severity,
            priority=1 if alert.severity == "critical" else (2 if alert.severity == "high" else 3),
            source_alert_ids=[alert.alert_id],
            correlated_event_ids=alert.triggering_event_ids,
            affected_hosts=[alert.affected_host] if alert.affected_host else [],
            affected_users=[alert.affected_user] if alert.affected_user else [],
            affected_ips=[ip for ip in [alert.source_ip, alert.destination_ip] if ip],
        )

        # 1. Timeline: Telemetry Ingest & Rule Trigger
        incident.timeline.append(
            IncidentTimelineEntry(
                incident_id=incident_id,
                phase="Detection",
                title=f"Deterministic Detection Rule Fired: {alert.rule_id}",
                description=alert.triggering_conditions,
                agent_id="engine_deterministic",
            )
        )

        # Create baseline Evidence References
        evidence_list: List[EvidenceReference] = []
        for i, ev_id in enumerate(alert.triggering_event_ids):
            evidence_list.append(
                EvidenceReference(
                    evidence_id=f"EVD-{alert.alert_id[-4:]}-{i+1}",
                    source_event_id=ev_id,
                    artifact_type="telemetry_event",
                    summary=f"Raw event triggering {alert.rule_name}",
                    raw_hash=None,
                )
            )

        ev_ids = [e.evidence_id for e in evidence_list]

        # STEP 1: Detection Analyst (Triage)
        incident.state = IncidentLifecycleState.TRIAGED
        task_a = AgentTask(
            incident_id=incident_id,
            agent_id=self.agent_detection.agent_id,
            task_type=AgentTaskType.DETECTION_ANALYSIS,
            scoped_instructions="Perform tier 1 alert triage, assess false positive probability, and highlight key indicators.",
            relevant_evidence_ids=ev_ids,
            context_data={
                "alert": alert.model_dump(mode="json"),
                "event_count": alert.event_count,
            },
        )
        res_a, trace_a = self.agent_detection.run(task_a)
        self.traces.append(trace_a)
        incident.findings.extend(res_a.structured_findings)

        incident.timeline.append(
            IncidentTimelineEntry(
                incident_id=incident_id,
                phase="Triage Analysis",
                title="Agent A (Detection Analyst) Completed Triage",
                description=f"Identified {len(res_a.structured_findings)} finding(s). Next: {res_a.recommended_next_step or 'Threat intelligence lookup'}",
                agent_id=self.agent_detection.agent_id,
            )
        )

        # STEP 2: Threat Intelligence Analyst (Enrichment)
        incident.state = IncidentLifecycleState.INVESTIGATING
        task_b = AgentTask(
            incident_id=incident_id,
            agent_id=self.agent_threat_intel.agent_id,
            task_type=AgentTaskType.THREAT_INTEL_ENRICHMENT,
            scoped_instructions="Enrich observable IP and host indicators against threat intelligence repositories.",
            relevant_evidence_ids=ev_ids,
            context_data={
                "indicator": alert.source_ip or alert.affected_host or "198.51.100.45",
                "target_host": alert.affected_host,
            },
        )
        res_b, trace_b = self.agent_threat_intel.run(task_b)
        self.traces.append(trace_b)
        incident.findings.extend(res_b.structured_findings)

        incident.timeline.append(
            IncidentTimelineEntry(
                incident_id=incident_id,
                phase="Threat Intelligence",
                title="Agent B (CTI Analyst) Enriched Observables",
                description=f"Enriched indicator {alert.source_ip}. Confidence: {res_b.structured_findings[0].confidence if res_b.structured_findings else 0.85}",
                agent_id=self.agent_threat_intel.agent_id,
            )
        )

        # STEP 3: Incident Investigation Analyst (Correlation & MITRE)
        task_c = AgentTask(
            incident_id=incident_id,
            agent_id=self.agent_investigation.agent_id,
            task_type=AgentTaskType.INCIDENT_INVESTIGATION,
            scoped_instructions="Reconstruct chronological adversary sequence and map behaviors to MITRE ATT&CK.",
            relevant_evidence_ids=ev_ids,
            context_data={
                "mitre_technique_id": alert.mitre_technique_id,
                "mitre_technique_name": alert.mitre_technique_name,
                "mitre_tactic": alert.mitre_tactic,
            },
        )
        res_c, trace_c = self.agent_investigation.run(task_c)
        self.traces.append(trace_c)
        incident.findings.extend(res_c.structured_findings)

        # Add MITRE technique mapping
        incident.mitre_mappings.append(
            MitreTechniqueMapping(
                technique_id=alert.mitre_technique_id,
                technique_name=alert.mitre_technique_name,
                tactic=alert.mitre_tactic,
                confidence=0.92,
                supporting_event_ids=alert.triggering_event_ids,
                rationale=f"Observed behavior directly matched rule {alert.rule_id} condition.",
            )
        )

        incident.timeline.append(
            IncidentTimelineEntry(
                incident_id=incident_id,
                phase="Deep Investigation",
                title="Agent C (Investigation Analyst) Mapped Attack Pattern",
                description=f"Mapped behavior to MITRE {alert.mitre_technique_id} ({alert.mitre_technique_name}) across {alert.event_count} events.",
                agent_id=self.agent_investigation.agent_id,
            )
        )

        # STEP 4: Risk Assessment Analyst (Deterministic Math)
        risk_context = {
            "asset_criticality": 4.5 if "prod" in (alert.affected_host or "").lower() or "dc" in (alert.affected_host or "").lower() else 3.5,
            "threat_severity": 5.0 if alert.severity == "critical" else (4.0 if alert.severity == "high" else 2.5),
            "exposure_level": 4.5 if alert.source_ip and not alert.source_ip.startswith("10.") else 2.5,
            "evidence_quality": 0.95,
            "confirmatory_intel": 1.3,
        }
        assessment = self.agent_risk.compute_assessment(incident_id, risk_context)
        incident.risk_assessment = assessment

        task_d = AgentTask(
            incident_id=incident_id,
            agent_id=self.agent_risk.agent_id,
            task_type=AgentTaskType.RISK_ASSESSMENT,
            scoped_instructions="Explain business impact and operational risk for computed score.",
            relevant_evidence_ids=ev_ids,
            context_data=risk_context,
        )
        res_d, trace_d = self.agent_risk.run(task_d)
        self.traces.append(trace_d)
        incident.findings.extend(res_d.structured_findings)

        incident.timeline.append(
            IncidentTimelineEntry(
                incident_id=incident_id,
                phase="Risk Assessment",
                title=f"Agent D (Risk Analyst) Computed Risk Score: {assessment.score}/100",
                description=assessment.rationale,
                agent_id=self.agent_risk.agent_id,
            )
        )

        # STEP 5: Response and Remediation Analyst
        response_context = {
            "source_ip": alert.source_ip,
            "affected_user": alert.affected_user,
            "affected_host": alert.affected_host,
            "threat_severity": risk_context["threat_severity"],
        }
        recs = self.agent_response.formulate_recommendations(incident_id, response_context, ev_ids)
        incident.response_recommendations = recs

        task_e = AgentTask(
            incident_id=incident_id,
            agent_id=self.agent_response.agent_id,
            task_type=AgentTaskType.RESPONSE_PLANNING,
            scoped_instructions="Generate safe containment and rollback plan under Human-in-the-Loop policy.",
            relevant_evidence_ids=ev_ids,
            context_data=response_context,
        )
        res_e, trace_e = self.agent_response.run(task_e)
        self.traces.append(trace_e)
        incident.findings.extend(res_e.structured_findings)

        incident.state = IncidentLifecycleState.CONTAINMENT_RECOMMENDED
        incident.timeline.append(
            IncidentTimelineEntry(
                incident_id=incident_id,
                phase="Remediation Planning",
                title="Agent E (Response Analyst) Drafted Containment Actions",
                description=f"Generated {len(recs)} allowlisted defensive action(s) awaiting Human-in-the-Loop approval.",
                agent_id=self.agent_response.agent_id,
            )
        )

        incident.updated_at = datetime.now(timezone.utc)
        return incident
