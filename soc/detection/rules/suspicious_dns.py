"""
Rule: Suspicious High-Entropy DNS Query (DGA / Tunneling)
MITRE ATT&CK: T1071.004 - Application Layer Protocol: DNS
Detects DNS queries with abnormally high Shannon entropy (> 3.7) or encoded subdomains indicative of C2 data exfiltration.
"""
import math
from collections import Counter
from typing import List

from soc.detection.engine import BaseDetectionRule, DetectionAlert
from soc.schemas.events import CanonicalSecurityEvent, EventCategory


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    p, lns = Counter(s), float(len(s))
    return -sum(count / lns * math.log2(count / lns) for count in p.values())


class SuspiciousDNSRule(BaseDetectionRule):
    rule_id = "RULE-DET-005"
    rule_name = "Suspicious High-Entropy / Tunneling DNS Query"
    rule_version = "1.0.0"
    mitre_technique_id = "T1071.004"
    mitre_technique_name = "Application Layer Protocol: DNS"
    mitre_tactic = "Command and Control / Exfiltration"
    severity = "high"
    entropy_threshold = 3.6
    subdomain_len_threshold = 24

    def evaluate(self, events: List[CanonicalSecurityEvent]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []

        for e in events:
            domain = e.domain or ""
            if not domain and e.event_category != EventCategory.DNS:
                continue

            subdomain = domain.split(".")[0] if "." in domain else domain
            entropy = shannon_entropy(subdomain)

            is_suspicious_entropy = (len(subdomain) >= self.subdomain_len_threshold and entropy >= self.entropy_threshold)
            is_suspicious_tld = any(domain.endswith(tld) for tld in [".top", ".xyz", ".cc", ".onion", ".bit", ".tk"])

            if is_suspicious_entropy or (is_suspicious_tld and entropy > 3.2):
                alert = DetectionAlert(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    rule_version=self.rule_version,
                    severity=self.severity,
                    confidence=0.89,
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    mitre_tactic=self.mitre_tactic,
                    description=(
                        f"Suspicious DNS query '{domain}' from host {e.hostname or e.source_ip} "
                        f"(entropy: {entropy:.2f}, label_len: {len(subdomain)}). Likely DGA or DNS tunneling C2 channel."
                    ),
                    triggering_conditions=f"Subdomain length >= {self.subdomain_len_threshold} and Shannon entropy >= {self.entropy_threshold}",
                    triggering_event_ids=[e.event_id],
                    source_ip=e.source_ip,
                    destination_ip=e.destination_ip,
                    affected_host=e.hostname or e.source_ip,
                    first_seen=e.event_timestamp,
                    last_seen=e.event_timestamp,
                    event_count=1,
                    suppression_key=f"{self.rule_id}:{domain}:{e.source_ip}",
                )
                alerts.append(alert)

        return alerts
