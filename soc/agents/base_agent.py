"""
Base Agent Interface.
Enforces Pydantic contracts, error boundaries, trace logging, and input/output sanitation.
"""
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from soc.llm.groq_client import GroqClient
from soc.schemas.agent_contracts import (
    AgentTask,
    AgentResult,
    AgentFinding,
    AgentTaskStatus,
    AgentExecutionTrace,
    EvidenceReference,
)


class BaseAgent(ABC):
    agent_id: str
    agent_role: str
    default_model: str

    def __init__(self, groq_client: GroqClient, model: Optional[str] = None):
        self.groq_client = groq_client
        self.model = model or self.default_model

    @abstractmethod
    def build_prompts(self, task: AgentTask) -> Tuple[str, str]:
        """Returns (system_prompt, user_prompt)."""
        pass

    def run(self, task: AgentTask) -> Tuple[AgentResult, AgentExecutionTrace]:
        """Executes the agent task safely, timing and parsing results strictly."""
        start_time = datetime.now(timezone.utc)
        start_ticks = time.time()
        system_prompt, user_prompt = self.build_prompts(task)

        try:
            raw_response = self.groq_client.execute_agent_task(
                task=task,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                model=self.model,
            )

            end_ticks = time.time()
            duration_ms = int((end_ticks - start_ticks) * 1000)
            end_time = datetime.now(timezone.utc)

            # Parse findings
            raw_findings = raw_response.get("findings", [])
            findings: List[AgentFinding] = []
            for f in raw_findings:
                findings.append(
                    AgentFinding(
                        finding_id=f.get("finding_id") or f"FND-{len(findings)+1}",
                        title=f.get("title", "Observed Security Indicator"),
                        summary=f.get("summary", ""),
                        confidence=min(1.0, max(0.0, float(f.get("confidence", 0.8)))),
                        confidence_rationale=f.get("confidence_rationale", "Derived from correlated telemetry."),
                        evidence_references=f.get("evidence_references", task.relevant_evidence_ids),
                        uncertainty=f.get("uncertainty", "None identified"),
                        false_positive_likelihood=float(f.get("false_positive_likelihood", 0.05)),
                        mitre_technique_id=f.get("mitre_technique_id"),
                        mitre_technique_name=f.get("mitre_technique_name"),
                        recommended_next_step=f.get("recommended_next_step"),
                    )
                )

            token_usage = raw_response.get("token_usage")

            result = AgentResult(
                task_id=task.task_id,
                incident_id=task.incident_id,
                agent_id=self.agent_id,
                status=AgentTaskStatus.COMPLETED,
                structured_findings=findings,
                confidence_rationale=raw_response.get("confidence_rationale", ""),
                uncertainty_and_limitations=raw_response.get("uncertainty_and_limitations", ""),
                recommended_next_step=raw_response.get("recommended_next_step"),
                execution_time_ms=duration_ms,
                model_name=raw_response.get("model_used", self.model),
                token_usage=token_usage or None,
            )

            trace = AgentExecutionTrace(
                task_id=task.task_id,
                incident_id=task.incident_id,
                agent_id=self.agent_id,
                model_name=raw_response.get("model_used", self.model),
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                prompt_tokens=token_usage.prompt_tokens if token_usage else 0,
                completion_tokens=token_usage.completion_tokens if token_usage else 0,
                status="SUCCESS",
                sanitized_prompt_summary=f"Task: {task.task_type.value}, evidence_count: {len(task.relevant_evidence_ids)}",
                sanitized_response_summary=f"Generated {len(findings)} findings in {duration_ms}ms",
            )
            return result, trace

        except Exception as e:
            end_ticks = time.time()
            duration_ms = int((end_ticks - start_ticks) * 1000)
            end_time = datetime.now(timezone.utc)

            result = AgentResult(
                task_id=task.task_id,
                incident_id=task.incident_id,
                agent_id=self.agent_id,
                status=AgentTaskStatus.FAILED,
                error_message=str(e),
                execution_time_ms=duration_ms,
                model_name=self.model,
            )

            trace = AgentExecutionTrace(
                task_id=task.task_id,
                incident_id=task.incident_id,
                agent_id=self.agent_id,
                model_name=self.model,
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                prompt_tokens=0,
                completion_tokens=0,
                status="FAILED",
                sanitized_prompt_summary=f"Failed task {task.task_type.value}",
                sanitized_response_summary=f"Execution failed: {str(e)[:100]}",
                error_details=str(e),
            )
            return result, trace
