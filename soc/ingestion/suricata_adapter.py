"""
Suricata EVE JSON Ingestion Adapter.
Parses network intrusion alerts, flow records, and DNS queries from Suricata into CanonicalSecurityEvent.
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Union
from soc.ingestion.base import BaseIngestionAdapter
from soc.schemas.events import CanonicalSecurityEvent, EventCategory, EventOutcome


class SuricataAdapter(BaseIngestionAdapter):
    source_type = "suricata"

    def parse(self, raw_data: Union[str, Dict[str, Any], List[Dict[str, Any]]]) -> List[CanonicalSecurityEvent]:
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                # Might be line-delimited JSON
                lines = [l.strip() for l in raw_data.strip().splitlines() if l.strip()]
                parsed_list = []
                for line in lines:
                    try:
                        parsed_list.append(json.loads(line))
                    except Exception:
                        pass
                raw_data = parsed_list

        items = raw_data if isinstance(raw_data, list) else [raw_data]
        events: List[CanonicalSecurityEvent] = []

        for item in items:
            event_type = item.get("event_type", "alert")
            alert_obj = item.get("alert", {})
            dns_obj = item.get("dns", {})

            category = EventCategory.NETWORK
            if event_type == "dns" or dns_obj:
                category = EventCategory.DNS

            raw_str = json.dumps(item, sort_keys=True)
            raw_hash = hashlib.sha256(raw_str.encode()).hexdigest()

            timestamp_str = item.get("timestamp")
            if timestamp_str:
                try:
                    ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            action = alert_obj.get("signature") or f"suricata_{event_type}"
            severity = alert_obj.get("severity", 3)
            # Suricata severity: 1 (highest) to 4 (lowest) -> map to 1-5 scale (5 is highest)
            mapped_severity = 5 if severity == 1 else (4 if severity == 2 else 2)

            domain = dns_obj.get("rrname") or dns_obj.get("query", [{}])[0].get("rrname") if isinstance(dns_obj.get("query"), list) and dns_obj.get("query") else None

            event = CanonicalSecurityEvent(
                source_type=self.source_type,
                source_product="suricata-ids",
                event_timestamp=ts,
                source_ip=item.get("src_ip"),
                destination_ip=item.get("dest_ip"),
                source_port=item.get("src_port"),
                destination_port=item.get("dest_port"),
                protocol=item.get("proto"),
                domain=domain,
                query_type=dns_obj.get("rrtype"),
                event_category=category,
                event_action=action,
                event_outcome=EventOutcome.BLOCKED if alert_obj.get("action") == "blocked" else EventOutcome.SUCCESS,
                severity=mapped_severity,
                raw_event_reference=raw_hash,
                tags=["nids", event_type],
                metadata={
                    "signature_id": alert_obj.get("signature_id"),
                    "category": alert_obj.get("category"),
                },
            )
            events.append(event)

        return events
