"""
Rule: Authentication Failures Followed by Success
MITRE ATT&CK: T1078 - Valid Accounts
Detects multiple failed logins (>= 3) followed closely (< 300s) by a successful login for the same account.
"""
from collections import defaultdict
from datetime import timedelta
from typing import List

from soc.detection.engine import BaseDetectionRule, DetectionAlert
from soc.schemas.events import CanonicalSecurityEvent, EventCategory, EventOutcome


class AuthFailFollowedBySuccessRule(BaseDetectionRule):
    rule_id = "RULE-DET-003"
    rule_name = "Authentication Failure Followed by Successful Compromise"
    rule_version = "1.0.0"
    mitre_technique_id = "T1078"
    mitre_technique_name = "Valid Accounts"
    mitre_tactic = "Initial Access / Persistence"
    severity = "critical"
    window_seconds = 300
    failure_threshold = 3

    def evaluate(self, events: List[CanonicalSecurityEvent]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        user_events = defaultdict(list)

        for e in events:
            if e.event_category == EventCategory.AUTHENTICATION and e.username:
                user_events[e.username.lower()].append(e)

        window = timedelta(seconds=self.window_seconds)

        for user, evs in user_events.items():
            evs_sorted = sorted(evs, key=lambda x: x.event_timestamp)
            for i, ev in enumerate(evs_sorted):
                if ev.event_outcome == EventOutcome.SUCCESS:
                    # Look back within window for failures
                    prior_failures = [
                        p for p in evs_sorted[:i]
                        if p.event_outcome == EventOutcome.FAILURE
                        and ev.event_timestamp - p.event_timestamp <= window
                    ]
                    if len(prior_failures) >= self.failure_threshold:
                        earliest = prior_failures[0].event_timestamp
                        latest = ev.event_timestamp
                        trigger_ids = [p.event_id for p in prior_failures] + [ev.event_id]
                        src_ip = ev.source_ip or prior_failures[-1].source_ip

                        alert = DetectionAlert(
                            rule_id=self.rule_id,
                            rule_name=self.rule_name,
                            rule_version=self.rule_version,
                            severity=self.severity,
                            confidence=0.95,
                            mitre_technique_id=self.mitre_technique_id,
                            mitre_technique_name=self.mitre_technique_name,
                            mitre_tactic=self.mitre_tactic,
                            description=(
                                f"Account '{user}' suffered {len(prior_failures)} failed logins before a SUCCESSFUL login "
                                f"from IP {src_ip} within {int((latest - earliest).total_seconds())}s. High probability of credential compromise."
                            ),
                            triggering_conditions=f">= {self.failure_threshold} failed logins followed by login_success within {self.window_seconds}s",
                            triggering_event_ids=trigger_ids,
                            source_ip=src_ip,
                            destination_ip=ev.destination_ip,
                            affected_user=user,
                            affected_host=ev.hostname or ev.destination_ip,
                            first_seen=earliest,
                            last_seen=latest,
                            event_count=len(trigger_ids),
                            suppression_key=f"{self.rule_id}:{user}:{src_ip}",
                        )
                        alerts.append(alert)
                        break

        return alerts
