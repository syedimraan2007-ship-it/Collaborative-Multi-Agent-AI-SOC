"""
Rule: Horizontal Password Spraying Attempt
MITRE ATT&CK: T1110.003 - Password Spraying
Detects >= 4 failed authentication attempts from a single source IP targeting distinct usernames within 180 seconds.
"""
from collections import defaultdict
from datetime import timedelta
from typing import List

from soc.detection.engine import BaseDetectionRule, DetectionAlert
from soc.schemas.events import CanonicalSecurityEvent, EventCategory, EventOutcome


class PasswordSprayingRule(BaseDetectionRule):
    rule_id = "RULE-DET-002"
    rule_name = "Horizontal Password Spraying Attempt"
    rule_version = "1.0.0"
    mitre_technique_id = "T1110.003"
    mitre_technique_name = "Brute Force: Password Spraying"
    mitre_tactic = "Credential Access"
    severity = "high"
    window_seconds = 180
    distinct_user_threshold = 4

    def evaluate(self, events: List[CanonicalSecurityEvent]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        ip_events = defaultdict(list)

        for e in events:
            if (
                e.event_category == EventCategory.AUTHENTICATION
                and e.event_outcome == EventOutcome.FAILURE
                and e.source_ip
                and e.username
            ):
                ip_events[e.source_ip].append(e)

        window = timedelta(seconds=self.window_seconds)

        for src_ip, evs in ip_events.items():
            if len(evs) < self.distinct_user_threshold:
                continue

            for i in range(len(evs)):
                window_evs = [
                    ev for ev in evs[i:]
                    if ev.event_timestamp - evs[i].event_timestamp <= window
                ]
                distinct_users = {ev.username for ev in window_evs if ev.username}
                if len(distinct_users) >= self.distinct_user_threshold:
                    earliest = window_evs[0].event_timestamp
                    latest = window_evs[-1].event_timestamp
                    event_ids = [ev.event_id for ev in window_evs]

                    alert = DetectionAlert(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        rule_version=self.rule_version,
                        severity=self.severity,
                        confidence=0.88,
                        mitre_technique_id=self.mitre_technique_id,
                        mitre_technique_name=self.mitre_technique_name,
                        mitre_tactic=self.mitre_tactic,
                        description=(
                            f"Detected horizontal password spray attack from {src_ip} against "
                            f"{len(distinct_users)} distinct accounts ({', '.join(sorted(list(distinct_users))[:6])}) "
                            f"within {int((latest - earliest).total_seconds())}s."
                        ),
                        triggering_conditions=f">= {self.distinct_user_threshold} distinct user accounts targeted by failed auths in {self.window_seconds}s",
                        triggering_event_ids=event_ids,
                        source_ip=src_ip,
                        destination_ip=window_evs[0].destination_ip,
                        affected_user=", ".join(sorted(list(distinct_users))[:5]),
                        affected_host=window_evs[0].hostname or window_evs[0].destination_ip,
                        first_seen=earliest,
                        last_seen=latest,
                        event_count=len(window_evs),
                        suppression_key=f"{self.rule_id}:{src_ip}",
                    )
                    alerts.append(alert)
                    break

        return alerts
