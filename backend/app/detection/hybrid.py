"""
Hybrid Detection Fusion
--------------------------
Combines the Rule Engine (signature-based) and ML Engine (anomaly-based)
verdicts into one alert, with a composite risk score.

Fusion policy:
  - Either engine triggering => alert is raised (OR logic, catches more)
  - Confidence/severity is a weighted composite:
        rule hit alone      -> HIGH  (deterministic, low FP)
        ml hit alone        -> MEDIUM/HIGH depending on model confidence
        both agree          -> CRITICAL
        both disagree on type -> flagged, alert lists both hypotheses
"""

import time
import uuid
from dataclasses import dataclass, asdict
from typing import Optional

from app.detection.rule_engine import RuleEngine, RuleVerdict
from app.detection.ml_engine import MLEngine, MLVerdict
from app.features.flow_extractor import Flow, FlowTracker


@dataclass
class Alert:
    id: str
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    attack_type: str
    severity: str
    confidence: float
    sources: list  # ["rule"], ["ml"], or ["rule", "ml"]
    reason: str

    def to_dict(self):
        return asdict(self)


def _severity_from(rule_hits: list[RuleVerdict], ml_verdict: MLVerdict) -> tuple[str, float]:
    if rule_hits and ml_verdict.triggered:
        return "CRITICAL", max(ml_verdict.confidence, 0.95)
    if rule_hits:
        return "HIGH", 0.9
    if ml_verdict.triggered:
        if ml_verdict.confidence >= 0.85:
            return "HIGH", ml_verdict.confidence
        return "MEDIUM", ml_verdict.confidence
    return "INFO", ml_verdict.confidence


class HybridDetector:
    def __init__(self, ml_threshold: float = 0.6):
        self.tracker = FlowTracker()
        self.rule_engine = RuleEngine(self.tracker)
        self.ml_engine = MLEngine(threshold=ml_threshold)

    def ingest_packet(self, **packet_kwargs) -> list[Alert]:
        """Feed a single packet in, get back any alerts triggered by its flow."""
        flow = self.tracker.process_packet(**packet_kwargs)
        return self._evaluate_flow(flow)

    def _evaluate_flow(self, flow: Flow) -> list[Alert]:
        rule_hits = self.rule_engine.evaluate(flow)
        features = flow.to_feature_dict()
        ml_verdict = self.ml_engine.evaluate(features)

        if not rule_hits and not ml_verdict.triggered:
            return []

        severity, confidence = _severity_from(rule_hits, ml_verdict)

        sources = []
        attack_types = []
        reasons = []

        if rule_hits:
            sources.append("rule")
            attack_types.extend([r.attack_type for r in rule_hits])
            reasons.extend([r.reason for r in rule_hits])
        if ml_verdict.triggered:
            sources.append("ml")
            attack_types.append(ml_verdict.attack_type)
            reasons.append(
                f"ML classifier flagged '{ml_verdict.attack_type}' "
                f"with {ml_verdict.confidence:.2%} confidence"
            )

        attack_type = " + ".join(sorted(set(attack_types)))
        reason = "; ".join(reasons)

        alert = Alert(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            attack_type=attack_type,
            severity=severity,
            confidence=round(confidence, 3),
            sources=sources,
            reason=reason,
        )
        return [alert]

    def flush_expired(self) -> list[Alert]:
        """Call periodically (e.g. every second) to evaluate flows that just closed."""
        alerts = []
        for flow in self.tracker.expire_flows():
            alerts.extend(self._evaluate_flow(flow))
        return alerts
