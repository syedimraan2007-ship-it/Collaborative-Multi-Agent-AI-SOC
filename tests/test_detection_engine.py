"""
Tests for Deterministic Detection Rules, Thresholds, and Suppression.
"""
from soc.detection import create_default_detection_engine
from soc.ingestion.synthetic_replay import (
    generate_ssh_bruteforce_scenario,
    generate_password_spray_scenario,
    generate_auth_fail_then_success_scenario,
    generate_port_scan_scenario,
    generate_suspicious_dns_scenario,
    generate_lolbin_execution_scenario,
    generate_unusual_c2_beacon_scenario,
    generate_benign_traffic_scenario,
)


def test_ssh_bruteforce_rule_triggers(detection_engine):
    events = generate_ssh_bruteforce_scenario(fail_count=6)
    alerts = detection_engine.analyze(events)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "RULE-DET-001"
    assert alert.mitre_technique_id == "T1110.001"
    assert alert.severity == "high"
    assert alert.event_count >= 5


def test_password_spray_rule_triggers(detection_engine):
    events = generate_password_spray_scenario()
    alerts = detection_engine.analyze(events)
    assert any(a.rule_id == "RULE-DET-002" for a in alerts)
    spray_alert = [a for a in alerts if a.rule_id == "RULE-DET-002"][0]
    assert spray_alert.mitre_technique_id == "T1110.003"


def test_auth_fail_then_success_rule(detection_engine):
    events = generate_auth_fail_then_success_scenario()
    alerts = detection_engine.analyze(events)
    assert any(a.rule_id == "RULE-DET-003" for a in alerts)
    alert = [a for a in alerts if a.rule_id == "RULE-DET-003"][0]
    assert alert.severity == "critical"
    assert alert.affected_user == "db_admin"


def test_port_scan_rule(detection_engine):
    events = generate_port_scan_scenario()
    alerts = detection_engine.analyze(events)
    assert any(a.rule_id == "RULE-DET-004" for a in alerts)


def test_suspicious_dns_dga(detection_engine):
    events = generate_suspicious_dns_scenario()
    alerts = detection_engine.analyze(events)
    assert any(a.rule_id == "RULE-DET-005" for a in alerts)


def test_lolbin_execution(detection_engine):
    events = generate_lolbin_execution_scenario()
    alerts = detection_engine.analyze(events)
    assert any(a.rule_id == "RULE-DET-007" for a in alerts)
    assert alerts[0].severity == "critical"


def test_unusual_c2_beacon(detection_engine):
    events = generate_unusual_c2_beacon_scenario()
    alerts = detection_engine.analyze(events)
    assert any(a.rule_id == "RULE-DET-006" for a in alerts)


def test_benign_traffic_no_alerts(detection_engine):
    events = generate_benign_traffic_scenario(count=25)
    alerts = detection_engine.analyze(events)
    assert len(alerts) == 0
