"""
Tests for Risk Assessment and Deterministic Formulas.
"""
from soc.agents.risk_analyst import calculate_deterministic_risk
from soc.schemas.risk import RiskSeverity


def test_deterministic_risk_critical():
    # Asset: 5.0 (Domain Controller), Threat: 5.0 (Ransomware), Exposure: 5.0 (Internet-facing)
    score, severity = calculate_deterministic_risk(
        asset_criticality=5.0,
        threat_severity=5.0,
        exposure_level=5.0,
        evidence_quality=1.0,
        confirmatory_intel=1.5,
    )
    assert score >= 80.0
    assert severity == RiskSeverity.CRITICAL


def test_deterministic_risk_low():
    # Asset: 1.0 (Dev sandbox), Threat: 2.0 (Port scan), Exposure: 1.0 (Internal LAN)
    score, severity = calculate_deterministic_risk(
        asset_criticality=1.0,
        threat_severity=2.0,
        exposure_level=1.0,
        evidence_quality=0.8,
        confirmatory_intel=1.0,
    )
    assert score < 30.0
    assert severity in [RiskSeverity.LOW, RiskSeverity.INFORMATIONAL]


def test_score_bounded_at_100():
    score, _ = calculate_deterministic_risk(
        asset_criticality=5.0,
        threat_severity=5.0,
        exposure_level=5.0,
        evidence_quality=1.0,
        confirmatory_intel=2.0,
    )
    assert score <= 100.0
