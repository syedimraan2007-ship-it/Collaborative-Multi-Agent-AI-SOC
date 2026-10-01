"""
Pytest configuration and shared fixtures for offline SOC test suite.
"""
import pytest
from soc.schemas.events import CanonicalSecurityEvent, EventCategory, EventOutcome
from soc.detection import create_default_detection_engine
from soc.llm.groq_client import GroqClient
from soc.agents.orchestrator import CentralOrchestrator
from soc.response.control_plane import ResponseControlPlane


@pytest.fixture
def detection_engine():
    return create_default_detection_engine()


@pytest.fixture
def mock_groq_client():
    return GroqClient(api_key="mock_key_for_testing", enable_mock_fallback=True)


@pytest.fixture
def orchestrator(mock_groq_client):
    return CentralOrchestrator(mock_groq_client)


@pytest.fixture
def control_plane():
    return ResponseControlPlane()
