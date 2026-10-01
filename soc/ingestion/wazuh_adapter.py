"""
Wazuh Log / Alert Ingestion Adapter.
Parses Wazuh JSON alerts into CanonicalSecurityEvent schema.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Union
from soc.ingestion.base import BaseIngestionAdapter
from soc.schemas.events import CanonicalSecurityEvent, EventCategory, EventOutcome


class WazuhAdapter(BaseIngestionAdapter):
    source_type = "wazuh"

    def parse(self, raw_data: Union[str, Dict[str, Any], List[Dict[str, Any]]]) -> List[CanonicalSecurityEvent]:
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                return []

        items = raw_data if isinstance(raw_data, list) else [raw_data]
        events: List[CanonicalSecurityEvent] = []

        for item in items:
            rule = item.get("rule", {})
            agent = item.get("agent", {})
            data = item.get("data", {})
            
            # Map category
            groups = rule.get("groups", [])
            category = EventCategory.SYSTEM
            if "authentication_failed" in groups or "authentication_success" in groups or "sshd" in groups:
                category = EventCategory.AUTHENTICATION
            elif "syscheck" in groups:
                category = EventCategory.FILE
            elif "network" in groups:
                category = EventCategory.NETWORK

            # Map outcome
            outcome = EventOutcome.UNKNOWN
            if "authentication_failed" in groups:
                outcome = EventOutcome.FAILURE
            elif "authentication_success" in groups:
                outcome = EventOutcome.SUCCESS

            raw_str = json.dumps(item, sort_keys=True)
            raw_hash = hashlib.sha256(raw_str.encode()).hexdigest()

            # Timestamp parsing
            timestamp_str = item.get("timestamp")
            if timestamp_str:
                try:
                    ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            event = CanonicalSecurityEvent(
                source_type=self.source_type,
                source_product="wazuh-agent",
                event_timestamp=ts,
                host_id=agent.get("id"),
                hostname=agent.get("name"),
                source_ip=data.get("srcip") or data.get("src_ip"),
                destination_ip=data.get("dstip") or data.get("dst_ip"),
                source_port=int(data.get("srcport")) if data.get("srcport") else None,
                destination_port=int(data.get("dstport")) if data.get("dstport") else (22 if "sshd" in groups else None),
                protocol=data.get("protocol"),
                username=data.get("dstuser") or data.get("srcuser"),
                event_category=category,
                event_action=rule.get("description", "wazuh_alert"),
                event_outcome=outcome,
                severity=min(5, max(1, int(rule.get("level", 3) / 3))),
                raw_event_reference=raw_hash,
                tags=groups,
                metadata={"wazuh_rule_id": rule.get("id"), "full_log": item.get("full_log")},
            )
            events.append(event)

        return events
