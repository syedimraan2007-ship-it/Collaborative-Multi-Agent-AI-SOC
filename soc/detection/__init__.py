from soc.detection.engine import (
    DeterministicDetectionEngine,
    DetectionAlert,
    BaseDetectionRule,
)
from soc.detection.rules import (
    SSHBruteForceRule,
    PasswordSprayingRule,
    AuthFailFollowedBySuccessRule,
    PortScanRule,
    SuspiciousDNSRule,
    UnusualOutboundRule,
    SuspiciousProcessRule,
)


def create_default_detection_engine() -> DeterministicDetectionEngine:
    engine = DeterministicDetectionEngine()
    engine.register_rule(SSHBruteForceRule())
    engine.register_rule(PasswordSprayingRule())
    engine.register_rule(AuthFailFollowedBySuccessRule())
    engine.register_rule(PortScanRule())
    engine.register_rule(SuspiciousDNSRule())
    engine.register_rule(UnusualOutboundRule())
    engine.register_rule(SuspiciousProcessRule())
    return engine


__all__ = [
    "DeterministicDetectionEngine",
    "DetectionAlert",
    "BaseDetectionRule",
    "create_default_detection_engine",
]
