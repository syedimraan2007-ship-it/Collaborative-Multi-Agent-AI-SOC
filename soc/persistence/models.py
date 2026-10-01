"""
SQLAlchemy 2.0 Declarative Models for PostgreSQL / SQLite Persistence.
Ensures referential integrity, indexes, UTC timestamps, and auditability.
"""
from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy import (
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    JSON,
    Index,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class SecurityEventModel(Base):
    __tablename__ = "security_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0.0")
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    source_product: Mapped[str] = mapped_column(String(64))
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingestion_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    
    host_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    
    username: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    process_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    process_command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    process_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    
    domain: Mapped[Optional[str]] = mapped_column(String(256), nullable=True, index=True)
    event_category: Mapped[str] = mapped_column(String(32), index=True)
    event_action: Mapped[str] = mapped_column(String(128))
    event_outcome: Mapped[str] = mapped_column(String(32))
    severity: Mapped[int] = mapped_column(Integer, default=1)
    
    raw_event_reference: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)

    __table_args__ = (
        Index("ix_events_src_time", "source_ip", "event_timestamp"),
        Index("ix_events_host_time", "hostname", "event_timestamp"),
    )


class DetectionAlertModel(Base):
    __tablename__ = "detection_alerts"

    alert_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_name: Mapped[str] = mapped_column(String(256))
    rule_version: Mapped[str] = mapped_column(String(16), default="1.0.0")
    severity: Mapped[str] = mapped_column(String(32), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    mitre_technique_id: Mapped[str] = mapped_column(String(32), index=True)
    mitre_technique_name: Mapped[str] = mapped_column(String(128))
    mitre_tactic: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text)
    triggering_conditions: Mapped[str] = mapped_column(Text)
    
    source_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    affected_user: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    affected_host: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer)
    suppression_key: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class IncidentModel(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(32), default="NEW", index=True)
    severity: Mapped[str] = mapped_column(String(32), default="medium")
    priority: Mapped[int] = mapped_column(Integer, default=3)
    
    assigned_analyst: Mapped[Optional[str]] = mapped_column(String(128), default="unassigned")
    closure_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AgentTraceModel(Base):
    __tablename__ = "agent_execution_traces"

    trace_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    task_id: Mapped[str] = mapped_column(String(64), index=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    model_name: Mapped[str] = mapped_column(String(64))
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int] = mapped_column(Integer)
    prompt_tokens: Mapped[int] = mapped_column(Integer)
    completion_tokens: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32))
    sanitized_prompt_summary: Mapped[str] = mapped_column(Text)
    sanitized_response_summary: Mapped[str] = mapped_column(Text)
    error_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
