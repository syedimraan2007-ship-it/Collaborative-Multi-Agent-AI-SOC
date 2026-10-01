"""
Rule: SSH Brute-Force Authentication Attempt
MITRE ATT&CK: T1110.001 - Password Guessing
Detects >= 5 failed SSH authentication attempts from the same source IP within a 120-second rolling window.
"""
from collections import defaultdict
from datetime import timedelta
from typing import List

from soc.detection.engine import BaseDetectionRule, DetectionAlert
from soc.schemas.events import CanonicalSecurityEvent, EventCategory, EventOutcome


class SSHBruteForceRule(BaseDetectionRule):
    rule_id = "RULE-DET-001"
    rule_name = "SSH Brute-Force Authentication Guessing"
    rule_version = "1.0.0"
    mitre_technique_id = "T1110.001"
    mitre_technique_name = "Brute Force: Password Guessing"
    mitre_tactic = "Credential Access"
    severity = "high"
    window_seconds = 120
    threshold = 5

    def evaluate(self, events: List[CanonicalSecurityEvent]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        ip_events = defaultdict(list)

        for e in events:
            # Check for SSH failed auth
            is_ssh = (
                e.destination_port == 22
                or "ssh" in (e.process_name or "").lower()
                or "sshd" in (e.source_product or "").lower()
                or "ssh" in [t.lower() for t in e.tags]
            )
            if is_ssh and e.event_outcome == EventOutcome.FAILURE and e.source_ip:
                ip_events[e.source_ip].append(e)

        window = timedelta(seconds=self.window_seconds)

        for src_ip, evs in ip_events.items():
            if len(evs) < self.threshold:
                continue

            # Sliding window check
            for i in range(len(evs)):
                window_evs = [
                    ev for ev in evs[i:]
                    if ev.event_timestamp - evs[i].event_timestamp <= window
                ]
                if len(window_evs) >= self.threshold:
                    earliest = window_evs[0].event_timestamp
                    latest = window_evs[-1].event_timestamp
                    event_ids = [ev.event_id for ev in window_evs]
                    users_targeted = list({ev.username for ev in window_evs if ev.username})
                    target_host = window_evs[0].hostname or window_evs[0].destination_ip

                    alert = DetectionAlert(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        rule_version=self.rule_version,
                        severity=self.severity,
                        confidence=0.92,
                        mitre_technique_id=self.mitre_technique_id,
                        mitre_technique_name=self.mitre_technique_name,
                        mitre_tactic=self.mitre_tactic,
                        description=(
                            f"Detected {len(window_evs)} failed SSH login attempts from {src_ip} "
                            f"targeting user(s) {users_targeted or ['unknown']} within "
                            f"{int((latest - earliest).total_seconds())}s."
                        ),
                        triggering_conditions=f"Threshold >= {self.threshold} failed SSH auths in {self.window_seconds}s from single source IP",
                        triggering_event_ids=event_ids,
                        source_ip=src_ip,
                        destination_ip=window_evs[0].destination_ip,
                        affected_user=", ".join(users_targeted) if users_targeted else None,
                        affected_host=target_host,
                        first_seen=earliest,
                        last_seen=latest,
                        event_count=len(window_evs),
                        suppression_key=f"{self.rule_id}:{src_ip}",
                    )
                    alerts.append(alert)
                    break

        return alerts
