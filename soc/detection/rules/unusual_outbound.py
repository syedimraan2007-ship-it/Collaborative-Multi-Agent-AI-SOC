"""
Rule: Unusual Outbound C2 Network Connection
MITRE ATT&CK: T1071 - Application Layer Protocol
Detects repeated outbound connections to high-risk non-standard ports or suspicious external destinations.
"""
from collections import defaultdict
from datetime import timedelta
from typing import List

from soc.detection.engine import BaseDetectionRule, DetectionAlert
from soc.schemas.events import CanonicalSecurityEvent, EventCategory


SUSPICIOUS_C2_PORTS = {1337, 4444, 5555, 6667, 8443, 8888, 9001, 31337}


class UnusualOutboundRule(BaseDetectionRule):
    rule_id = "RULE-DET-006"
    rule_name = "Unusual Outbound C2 Beaconing Activity"
    rule_version = "1.0.0"
    mitre_technique_id = "T1071"
    mitre_technique_name = "Application Layer Protocol"
    mitre_tactic = "Command and Control"
    severity = "high"
    window_seconds = 180
    beacon_count_threshold = 3

    def evaluate(self, events: List[CanonicalSecurityEvent]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        flow_groups = defaultdict(list)

        for e in events:
            if (
                e.event_category == EventCategory.NETWORK
                and e.source_ip
                and e.destination_ip
                and e.destination_port in SUSPICIOUS_C2_PORTS
            ):
                key = (e.source_ip, e.destination_ip, e.destination_port)
                flow_groups[key].append(e)

        window = timedelta(seconds=self.window_seconds)

        for (src_ip, dst_ip, dport), evs in flow_groups.items():
            if len(evs) >= self.beacon_count_threshold:
                evs_sorted = sorted(evs, key=lambda x: x.event_timestamp)
                earliest = evs_sorted[0].event_timestamp
                latest = evs_sorted[-1].event_timestamp

                if latest - earliest <= window:
                    alert = DetectionAlert(
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        rule_version=self.rule_version,
                        severity=self.severity,
                        confidence=0.87,
                        mitre_technique_id=self.mitre_technique_id,
                        mitre_technique_name=self.mitre_technique_name,
                        mitre_tactic=self.mitre_tactic,
                        description=(
                            f"Periodic outbound connections ({len(evs)} bursts) from internal host {src_ip} "
                            f"to external C2 server {dst_ip}:{dport} within {int((latest - earliest).total_seconds())}s."
                        ),
                        triggering_conditions=f">= {self.beacon_count_threshold} outbound connects to suspicious port {dport} within {self.window_seconds}s",
                        triggering_event_ids=[x.event_id for x in evs_sorted],
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        affected_host=evs_sorted[0].hostname or src_ip,
                        first_seen=earliest,
                        last_seen=latest,
                        event_count=len(evs_sorted),
                        suppression_key=f"{self.rule_id}:{src_ip}:{dst_ip}:{dport}",
                    )
                    alerts.append(alert)

        return alerts
