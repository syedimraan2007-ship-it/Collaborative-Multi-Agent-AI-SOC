"""
Evaluation and Benchmarking Framework.
Measures Precision, Recall, F1, False-Positive Rate, Investigation Latency, and Schema Compliance
using labeled synthetic scenarios.
"""
from dataclasses import dataclass
from typing import List, Dict, Any

from soc.detection import create_default_detection_engine
from soc.agents.orchestrator import CentralOrchestrator
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


@dataclass
class BenchmarkReport:
    total_scenarios_tested: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    mean_investigation_latency_ms: float
    schema_compliance_rate: float


def run_soc_benchmarks() -> BenchmarkReport:
    detection_engine = create_default_detection_engine()
    orchestrator = CentralOrchestrator()

    # Ground truth test set: 7 malicious scenarios, 2 benign scenarios
    test_cases = [
        {"name": "SSH Brute Force", "events": generate_ssh_bruteforce_scenario(), "is_malicious": True, "expected_rule": "RULE-DET-001"},
        {"name": "Password Spraying", "events": generate_password_spray_scenario(), "is_malicious": True, "expected_rule": "RULE-DET-002"},
        {"name": "Auth Failure then Success", "events": generate_auth_fail_then_success_scenario(), "is_malicious": True, "expected_rule": "RULE-DET-003"},
        {"name": "Port Scan Recon", "events": generate_port_scan_scenario(), "is_malicious": True, "expected_rule": "RULE-DET-004"},
        {"name": "Suspicious DNS DGA", "events": generate_suspicious_dns_scenario(), "is_malicious": True, "expected_rule": "RULE-DET-005"},
        {"name": "LOLBIN Execution", "events": generate_lolbin_execution_scenario(), "is_malicious": True, "expected_rule": "RULE-DET-007"},
        {"name": "C2 Beaconing", "events": generate_unusual_c2_beacon_scenario(), "is_malicious": True, "expected_rule": "RULE-DET-006"},
        {"name": "Benign Web Browsing", "events": generate_benign_traffic_scenario(count=20), "is_malicious": False, "expected_rule": None},
        {"name": "Benign Internal Traffic", "events": generate_benign_traffic_scenario(count=15), "is_malicious": False, "expected_rule": None},
    ]

    tp = 0
    fp = 0
    fn = 0
    latencies = []
    compliant_schemas = 0
    total_investigations = 0

    for tc in test_cases:
        alerts = detection_engine.analyze(tc["events"])
        fired = len(alerts) > 0

        if tc["is_malicious"]:
            if fired:
                tp += 1
                # Run full multi-agent investigation on detected alert
                for alert in alerts:
                    incident = orchestrator.orchestrate_incident(alert)
                    latencies.append(sum(t.duration_ms for t in orchestrator.traces[-5:]))
                    total_investigations += 1
                    # Verify strict schema compliance
                    if incident.risk_assessment and len(incident.findings) >= 5 and len(incident.response_recommendations) >= 1:
                        compliant_schemas += 1
            else:
                fn += 1
        else:
            if fired:
                fp += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + 2)  # Against benign baseline
    mean_latency = sum(latencies) / len(latencies) if latencies else 0.0
    compliance_rate = (compliant_schemas / total_investigations) if total_investigations > 0 else 1.0

    return BenchmarkReport(
        total_scenarios_tested=len(test_cases),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        mean_investigation_latency_ms=round(mean_latency, 2),
        schema_compliance_rate=round(compliance_rate, 4),
    )
