"""
Canonical Security Event Schema (v1.0.0).
Provides strict Pydantic v2 validation for all ingested and normalized telemetry.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from uuid import uuid4
from pydantic import BaseModel, Field, field_validator


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    DNS = "dns"
    CONFIGURATION = "configuration"
    SYSTEM = "system"


class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class CanonicalSecurityEvent(BaseModel):
    """Normalized, immutable security event structure across Wazuh, Suricata, Sysmon, and Linux."""
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    schema_version: str = Field(default="1.0.0")
    source_type: str = Field(..., description="Telemetry source adapter: wazuh, suricata, sysmon, linux, synthetic")
    source_product: str = Field(default="generic-sensor")
    event_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ingestion_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Target and Host
    host_id: Optional[str] = None
    hostname: Optional[str] = None
    
    # Network Layer
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = None
    
    # Identity and Process
    username: Optional[str] = None
    user_id: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_id: Optional[int] = None
    process_command_line: Optional[str] = None
    process_hash: Optional[str] = None
    
    # DNS / Web Indicators
    domain: Optional[str] = None
    query_type: Optional[str] = None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    
    # Canonical Categorization
    event_category: EventCategory = EventCategory.SYSTEM
    event_action: str = Field(..., description="Action observed, e.g. login_attempt, port_connect, process_spawn")
    event_outcome: EventOutcome = EventOutcome.UNKNOWN
    severity: int = Field(default=1, ge=1, le=5, description="Normalized severity 1 (Info) to 5 (Critical)")
    
    # Provenance and Traceability
    raw_event_reference: Optional[str] = Field(default=None, description="SHA256 or reference to raw telemetry")
    tags: List[str] = Field(default_factory=list)
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_timestamp", "ingestion_timestamp", mode="before")
    @classmethod
    def ensure_utc(cls, v: Any) -> datetime:
        if isinstance(v, str):
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc)
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)
        return datetime.now(timezone.utc)
