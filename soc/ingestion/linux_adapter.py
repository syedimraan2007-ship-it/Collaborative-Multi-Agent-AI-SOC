"""
Linux Auth / Syslog Ingestion Adapter.
Parses auth.log lines for SSH failed / accepted logins, sudo executions, and invalid users.
"""
import hashlib
import re
from datetime import datetime, timezone
from typing import List, Union
from soc.ingestion.base import BaseIngestionAdapter
from soc.schemas.events import CanonicalSecurityEvent, EventCategory, EventOutcome


SSH_FAIL_REGEX = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2",
    re.IGNORECASE,
)
SSH_ACCEPT_REGEX = re.compile(
    r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2",
    re.IGNORECASE,
)


class LinuxAuthAdapter(BaseIngestionAdapter):
    source_type = "linux"

    def parse(self, raw_data: Union[str, List[str]]) -> List[CanonicalSecurityEvent]:
        lines = raw_data if isinstance(raw_data, list) else raw_data.strip().splitlines()
        events: List[CanonicalSecurityEvent] = []

        for line in lines:
            if not line.strip():
                continue

            raw_hash = hashlib.sha256(line.encode()).hexdigest()
            now = datetime.now(timezone.utc)

            fail_match = SSH_FAIL_REGEX.search(line)
            if fail_match:
                user, ip, port = fail_match.groups()
                event = CanonicalSecurityEvent(
                    source_type=self.source_type,
                    source_product="sshd",
                    event_timestamp=now,
                    source_ip=ip,
                    destination_port=22,
                    source_port=int(port),
                    protocol="tcp",
                    username=user,
                    event_category=EventCategory.AUTHENTICATION,
                    event_action="login_attempt",
                    event_outcome=EventOutcome.FAILURE,
                    severity=3,
                    raw_event_reference=raw_hash,
                    tags=["ssh", "auth_failure", "linux"],
                )
                events.append(event)
                continue

            accept_match = SSH_ACCEPT_REGEX.search(line)
            if accept_match:
                user, ip, port = accept_match.groups()
                event = CanonicalSecurityEvent(
                    source_type=self.source_type,
                    source_product="sshd",
                    event_timestamp=now,
                    source_ip=ip,
                    destination_port=22,
                    source_port=int(port),
                    protocol="tcp",
                    username=user,
                    event_category=EventCategory.AUTHENTICATION,
                    event_action="login_success",
                    event_outcome=EventOutcome.SUCCESS,
                    severity=2,
                    raw_event_reference=raw_hash,
                    tags=["ssh", "auth_success", "linux"],
                )
                events.append(event)

        return events
