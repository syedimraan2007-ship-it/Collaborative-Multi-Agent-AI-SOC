"""
Threat Intelligence Schema (v1.0.0).
Provides indicators, reputation ratings, and enrichment observations.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    MD5 = "md5"


class ReputationLevel(str, Enum):
    BENIGN = "benign"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    CONFIRMED_MALICIOUS = "confirmed_malicious"


class ThreatIntelligenceObservation(BaseModel):
    indicator: str
    indicator_type: IndicatorType
    reputation: ReputationLevel
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    provider: str = Field(..., description="Provider source name e.g. AlienVault OTX, AbuseIPDB, VirusTotal, OfflineFixture")
    observation_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    freshness_hours: int = 1
    tags: List[str] = Field(default_factory=list)
    threat_actor: Optional[str] = None
    malware_family: Optional[str] = None
    asn_or_isp: Optional[str] = None
    country_code: Optional[str] = None
    limitations: str = "Heuristic or fixture-based intelligence"
    raw_response: Dict[str, Any] = Field(default_factory=dict)
