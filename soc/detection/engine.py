"""
Deterministic Detection Engine.
Operates strictly on rule-based logic without LLM hallucinations.
Separates observed facts from hypotheses and provides configurable thresholds,
suppression windows, and alert correlation.
"""
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from soc.schemas.events import CanonicalSecurityEvent, EventCategory, EventOutcome


class DetectionAlert(BaseModel):
    alert_id: str = Field(default_factory=lambda: f"ALT-{uuid4().hex[:8].upper()}")
    rule_id: str
    rule_name: str
    rule_version: str = "1.0.0"
    severity: str = "high"
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    description: str
    triggering_conditions: str
    triggering_event_ids: List[str]
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    affected_user: Optional[str] = None
    affected_host: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    suppression_key: str
    status: str = "open"  # open, triaged, investigating, closed
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BaseDetectionRule:
    rule_id: str
    rule_name: str
    rule_version: str = "1.0.0"
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_tactic: str
    severity: str
    window_seconds: int = 120

    def evaluate(self, events: List[CanonicalSecurityEvent]) -> List[DetectionAlert]:
        raise NotImplementedError


class DeterministicDetectionEngine:
    def __init__(self):
        self.rules: List[BaseDetectionRule] = []
        self._suppressed_alerts: Dict[str, datetime] = {}
        self.suppression_window = timedelta(minutes=15)

    def register_rule(self, rule: BaseDetectionRule) -> None:
        self.rules.append(rule)

    def analyze(self, events: List[CanonicalSecurityEvent]) -> List[DetectionAlert]:
        """Runs all registered deterministic rules over the given events, applying deduplication."""
        alerts: List[DetectionAlert] = []
        now = datetime.now(timezone.utc)
        
        # Sort events by event_timestamp
        sorted_events = sorted(events, key=lambda e: e.event_timestamp)

        for rule in self.rules:
            rule_alerts = rule.evaluate(sorted_events)
            for alert in rule_alerts:
                # Check suppression
                last_alert_time = self._suppressed_alerts.get(alert.suppression_key)
                if last_alert_time and (now - last_alert_time) < self.suppression_window:
                    continue  # Deduplicated within window
                
                self._suppressed_alerts[alert.suppression_key] = now
                alerts.append(alert)

        return alerts
