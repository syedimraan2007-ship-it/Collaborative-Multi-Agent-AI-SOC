"""
Windows Sysmon Ingestion Adapter.
Parses Event ID 1 (Process Create), Event ID 3 (Network Connect), and Event ID 22 (DNS Query).
"""
import hashlib
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Union
from soc.ingestion.base import BaseIngestionAdapter
from soc.schemas.events import CanonicalSecurityEvent, EventCategory, EventOutcome


class SysmonAdapter(BaseIngestionAdapter):
    source_type = "sysmon"

    def parse(self, raw_data: Union[str, Dict[str, Any], List[Dict[str, Any]]]) -> List[CanonicalSecurityEvent]:
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                return []

        items = raw_data if isinstance(raw_data, list) else [raw_data]
        events: List[CanonicalSecurityEvent] = []

        for item in items:
            event_data = item.get("EventData", item)
            event_id = int(item.get("EventID", event_data.get("EventID", 1)))

            raw_str = json.dumps(item, sort_keys=True)
            raw_hash = hashlib.sha256(raw_str.encode()).hexdigest()

            time_created = item.get("TimeCreated", {}).get("SystemTime") or item.get("UtcTime") or item.get("timestamp")
            if time_created:
                try:
                    ts = datetime.fromisoformat(time_created.replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.now(timezone.utc)
            else:
                ts = datetime.now(timezone.utc)

            host = item.get("Computer") or event_data.get("Computer")
            user = event_data.get("User")

            if event_id == 1:  # Process Create
                image = event_data.get("Image", "")
                cmd = event_data.get("CommandLine", "")
                hashes = event_data.get("Hashes", "")
                pid = int(event_data.get("ProcessId", 0)) if event_data.get("ProcessId") else None
                ppid = int(event_data.get("ParentProcessId", 0)) if event_data.get("ParentProcessId") else None

                event = CanonicalSecurityEvent(
                    source_type=self.source_type,
                    source_product="microsoft-sysmon",
                    event_timestamp=ts,
                    hostname=host,
                    username=user,
                    process_name=image.split("\\")[-1] if "\\" in image else image,
                    process_id=pid,
                    parent_process_id=ppid,
                    process_command_line=cmd,
                    process_hash=hashes,
                    event_category=EventCategory.PROCESS,
                    event_action="process_create",
                    event_outcome=EventOutcome.SUCCESS,
                    severity=3,
                    raw_event_reference=raw_hash,
                    tags=["sysmon", "eid1", "process_create"],
                )
                events.append(event)

            elif event_id == 3:  # Network Connect
                image = event_data.get("Image", "")
                event = CanonicalSecurityEvent(
                    source_type=self.source_type,
                    source_product="microsoft-sysmon",
                    event_timestamp=ts,
                    hostname=host,
                    username=user,
                    source_ip=event_data.get("SourceIp"),
                    destination_ip=event_data.get("DestinationIp"),
                    source_port=int(event_data.get("SourcePort")) if event_data.get("SourcePort") else None,
                    destination_port=int(event_data.get("DestinationPort")) if event_data.get("DestinationPort") else None,
                    protocol=event_data.get("Protocol"),
                    process_name=image.split("\\")[-1] if "\\" in image else image,
                    event_category=EventCategory.NETWORK,
                    event_action="network_connect",
                    event_outcome=EventOutcome.SUCCESS,
                    severity=2,
                    raw_event_reference=raw_hash,
                    tags=["sysmon", "eid3", "network_connect"],
                )
                events.append(event)

            elif event_id == 22:  # DNS Query
                event = CanonicalSecurityEvent(
                    source_type=self.source_type,
                    source_product="microsoft-sysmon",
                    event_timestamp=ts,
                    hostname=host,
                    username=user,
                    domain=event_data.get("QueryName"),
                    event_category=EventCategory.DNS,
                    event_action="dns_query",
                    event_outcome=EventOutcome.SUCCESS,
                    severity=2,
                    raw_event_reference=raw_hash,
                    tags=["sysmon", "eid22", "dns_query"],
                )
                events.append(event)

        return events
