"""
Base Ingestion Adapter.
Standardizes parsing, timestamp normalization, deduplication, and provenance tracking.
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from soc.schemas.events import CanonicalSecurityEvent


class BaseIngestionAdapter(ABC):
    source_type: str = "generic"

    @abstractmethod
    def parse(self, raw_data: Any) -> List[CanonicalSecurityEvent]:
        """Parses raw log / alert payloads into canonical security events."""
        pass
