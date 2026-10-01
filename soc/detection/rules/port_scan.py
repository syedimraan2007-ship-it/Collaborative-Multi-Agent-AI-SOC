"""
Rule: Network Port Reconnaissance Scan
MITRE ATT&CK: T1046 - Network Service Discovery
Detects >= 5 distinct destination ports probed by the same source IP within a 60-second window.
"""
from collections import defaultdict
from datetime import timedelta
from typing import List

from soc.detection.engine import BaseDetectionRule, DetectionAlert
from soc.schemas.events import CanonicalSecurityEvent, EventCategory


class PortScanRule(BaseDetectionRule):
    rule_id = "RULE-DET-004"
    rule_name = "Network Service Discovery / Port Reconnaissance"
    rule_version = "1.0.0"
    mitre_technique_id = "T1046"
    mitre_technique_name = "Network Service Discovery"
    mitre_tactic = "Discovery"
    severity = "medium"
    window_seconds = 60
    distinct_port_threshold = 5

    def evaluate(self, events: List[CanonicalSecurityEvent]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        ip_events = defaultdict(list)

        for e in events:
            if (
                e.event_category == EventCategory.NETWORK
                and e.source_ip
                and e.destination_port is not None
            ):
                ip_events[e.source_ip].append(e)

        window = timedelta(seconds=self.window_seconds)

        for src_ip, evs in ip_events.items():
            if len(evs) < self.distinct_port_threshold:
                continue

            for i in range(len(evs)):
                window_evs = [
                    ev for ev in evs[i:]
                    if ev.event_timestamp - evs[i].event_timestamp <= window
                ]
                ports = {ev.destination_port for ev in window_evs if ev.destination_port}
                if len(ports) >= self.distinct_port_threshold:
                    earliest = window_evs[0].event_timestamp
                    latest = window_evs[-1].event_timestamp
                    event_ids = [ev.event_id for ev in window_evs]

                    alert = DetectionAlert(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        rule_version=self.rule_version,
                        severity=self.severity,
                        confidence=0.85,
                        mitre_technique_id=self.mitre_technique_id,
                        mitre_technique_name=self.mitre_technique_name,
                        mitre_tactic=self.mitre_tactic,
                        description=(
                            f"Port scan reconnaissance detected from {src_ip} hitting {len(ports)} distinct ports "
                            f"({', '.join(map(str, sorted(list(ports))[:8]))}) within {int((latest - earliest).total_seconds())}s."
                        ),
                        triggering_conditions=f">= {self.distinct_port_threshold} distinct destination ports scanned in {self.window_seconds}s",
                        triggering_event_ids=event_ids,
                        source_ip=src_ip,
                        destination_ip=window_evs[0].destination_ip,
                        affected_host=window_evs[0].hostname or window_evs[0].destination_ip,
                        first_seen=earliest,
                        last_seen=latest,
                        event_count=len(window_evs),
                        suppression_key=f"{self.rule_id}:{src_ip}",
                    )
                    alerts.append(alert)
                    break

        return alerts
