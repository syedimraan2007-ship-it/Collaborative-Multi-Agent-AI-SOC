"""
Tests for Telemetry Ingestion, Normalization, and Provenance.
"""
from datetime import datetime, timezone
from soc.ingestion.wazuh_adapter import WazuhAdapter
from soc.ingestion.suricata_adapter import SuricataAdapter
from soc.ingestion.sysmon_adapter import SysmonAdapter
from soc.ingestion.linux_adapter import LinuxAuthAdapter
from soc.schemas.events import EventCategory, EventOutcome


def test_wazuh_adapter_normalization():
    adapter = WazuhAdapter()
    sample = {
        "timestamp": "2026-09-30T21:00:00.000Z",
        "rule": {"id": "5710", "level": 5, "description": "sshd: Attempt to login using a non-existent user", "groups": ["sshd", "authentication_failed"]},
        "agent": {"id": "001", "name": "srv-prod-web"},
        "data": {"srcip": "198.51.100.22", "dstuser": "oracle", "srcport": "44210"},
    }
    events = adapter.parse(sample)
    assert len(events) == 1
    ev = events[0]
    assert ev.source_type == "wazuh"
    assert ev.source_ip == "198.51.100.22"
    assert ev.username == "oracle"
    assert ev.destination_port == 22
    assert ev.event_category == EventCategory.AUTHENTICATION
    assert ev.event_outcome == EventOutcome.FAILURE
    assert ev.raw_event_reference is not None


def test_suricata_adapter_normalization():
    adapter = SuricataAdapter()
    sample = {
        "timestamp": "2026-09-30T21:05:00.000000+0000",
        "event_type": "alert",
        "src_ip": "10.0.1.55",
        "dest_ip": "198.51.100.99",
        "src_port": 50123,
        "dest_port": 4444,
        "proto": "TCP",
        "alert": {"action": "allowed", "severity": 1, "signature": "ET TROJAN Observed Meterpreter Reverse TCP", "category": "A Network Trojan was detected"},
    }
    events = adapter.parse(sample)
    assert len(events) == 1
    ev = events[0]
    assert ev.source_type == "suricata"
    assert ev.destination_port == 4444
    assert ev.severity == 5
    assert ev.event_category == EventCategory.NETWORK


def test_sysmon_adapter_process_create():
    adapter = SysmonAdapter()
    sample = {
        "EventID": 1,
        "UtcTime": "2026-09-30 21:10:00.000",
        "Computer": "WORKSTATION-01",
        "EventData": {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgAIAA...",
            "User": "CORP\\jsmith",
            "ProcessId": "3420",
        }
    }
    events = adapter.parse(sample)
    assert len(events) == 1
    ev = events[0]
    assert ev.process_name == "powershell.exe"
    assert ev.process_id == 3420
    assert ev.event_category == EventCategory.PROCESS


def test_linux_auth_adapter():
    adapter = LinuxAuthAdapter()
    log_line = "Sep 30 21:15:00 host01 sshd[1234]: Failed password for invalid user admin from 192.0.2.77 port 39822 ssh2"
    events = adapter.parse(log_line)
    assert len(events) == 1
    assert events[0].source_ip == "192.0.2.77"
    assert events[0].username == "admin"
    assert events[0].event_outcome == EventOutcome.FAILURE
