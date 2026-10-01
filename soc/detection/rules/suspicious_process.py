"""
Rule: Suspicious Living-Off-The-Land Binary (LOLBIN) Execution
MITRE ATT&CK: T1059.001 - Command and Scripting Interpreter: PowerShell
Detects execution of scripting or administrative utilities with encoded commands, download strings, or obfuscated payloads.
"""
import re
from typing import List

from soc.detection.engine import BaseDetectionRule, DetectionAlert
from soc.schemas.events import CanonicalSecurityEvent, EventCategory


SUSPICIOUS_CMD_PATTERNS = [
    re.compile(r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE),
    re.compile(r"downloadstring\s*\(", re.IGNORECASE),
    re.compile(r"invoke-expression|iex\b", re.IGNORECASE),
    re.compile(r"certutil(\.exe)?\s+(-urlcache|-decode|-split)", re.IGNORECASE),
    re.compile(r"mshta(\.exe)?\s+(javascript|vbscript|http)", re.IGNORECASE),
    re.compile(r"powershell(\.exe)?\s+.*bypass", re.IGNORECASE),
    re.compile(r"curl\s+.*\|\s*(bash|sh)", re.IGNORECASE),
    re.compile(r"/bin/bash\s+-i", re.IGNORECASE),
]


class SuspiciousProcessRule(BaseDetectionRule):
    rule_id = "RULE-DET-007"
    rule_name = "Suspicious Living-Off-The-Land Command Execution"
    rule_version = "1.0.0"
    mitre_technique_id = "T1059.001"
    mitre_technique_name = "Command and Scripting Interpreter: PowerShell"
    mitre_tactic = "Execution"
    severity = "critical"

    def evaluate(self, events: List[CanonicalSecurityEvent]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []

        for e in events:
            cmd = e.process_command_line or ""
            proc = (e.process_name or "").lower()

            if not cmd and not proc:
                continue

            matched_pattern = None
            for pattern in SUSPICIOUS_CMD_PATTERNS:
                if pattern.search(cmd):
                    matched_pattern = pattern.pattern
                    break

            if matched_pattern or ("powershell" in proc and "-enc" in cmd.lower()):
                alert = DetectionAlert(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    rule_version=self.rule_version,
                    severity=self.severity,
                    confidence=0.96,
                    mitre_technique_id=self.mitre_technique_id,
                    mitre_technique_name=self.mitre_technique_name,
                    mitre_tactic=self.mitre_tactic,
                    description=(
                        f"LOLBIN obfuscated execution on host {e.hostname or 'unknown'} by user '{e.username or 'SYSTEM'}'. "
                        f"Process '{e.process_name}' ran suspicious payload: {cmd[:120]}..."
                    ),
                    triggering_conditions=f"Matched regex pattern: {matched_pattern or 'encoded command'}",
                    triggering_event_ids=[e.event_id],
                    source_ip=e.source_ip,
                    destination_ip=e.destination_ip,
                    affected_user=e.username,
                    affected_host=e.hostname,
                    first_seen=e.event_timestamp,
                    last_seen=e.event_timestamp,
                    event_count=1,
                    suppression_key=f"{self.rule_id}:{e.hostname}:{e.process_id or cmd[:30]}",
                )
                alerts.append(alert)

        return alerts
