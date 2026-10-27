"""Edge Telemetry Aggregator and CloudWatch Metrics Formatter."""

from dataclasses import dataclass
from typing import Any, Dict, List
from ..core.config import EvaluationDecision, MitigationAction


@dataclass
class EdgeMetricSnapshot:
    total_evaluated: int
    allowed_count: int
    challenged_count: int
    diverted_count: int
    blocked_count: int
    threat_ratio_percent: float
    avg_latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_evaluated": self.total_evaluated,
            "allowed_count": self.allowed_count,
            "challenged_count": self.challenged_count,
            "diverted_count": self.diverted_count,
            "blocked_count": self.blocked_count,
            "threat_ratio_percent": self.threat_ratio_percent,
            "avg_latency_ms": self.avg_latency_ms,
        }


class EdgeTelemetryStreamer:
    """Aggregates decisions into real-time SOC metrics and CloudWatch Metric format."""

    @classmethod
    def aggregate(cls, decisions: List[EvaluationDecision]) -> EdgeMetricSnapshot:
        total = len(decisions)
        if total == 0:
            return EdgeMetricSnapshot(0, 0, 0, 0, 0, 0.0, 0.0)

        allowed = sum(1 for d in decisions if d.action == MitigationAction.ALLOW)
        challenged = sum(1 for d in decisions if d.action == MitigationAction.CHALLENGE_CAPTCHA)
        diverted = sum(1 for d in decisions if d.action == MitigationAction.DIVERT_HONEYPOT)
        blocked = sum(1 for d in decisions if d.action == MitigationAction.BLOCK)

        threats = total - allowed
        threat_ratio = round((threats / total) * 100.0, 2)
        avg_lat = round(sum(d.execution_time_ms for d in decisions) / total, 3)

        return EdgeMetricSnapshot(
            total_evaluated=total,
            allowed_count=allowed,
            challenged_count=challenged,
            diverted_count=diverted,
            blocked_count=blocked,
            threat_ratio_percent=threat_ratio,
            avg_latency_ms=avg_lat,
        )

    @classmethod
    def to_cloudwatch_metric_data(cls, snapshot: EdgeMetricSnapshot) -> List[Dict[str, Any]]:
        """Formats snapshot into AWS CloudWatch PutMetricData format."""
        return [
            {"MetricName": "TotalEvaluatedRequests", "Value": snapshot.total_evaluated, "Unit": "Count"},
            {"MetricName": "BlockedRequests", "Value": snapshot.blocked_count, "Unit": "Count"},
            {"MetricName": "ChallengedRequests", "Value": snapshot.challenged_count, "Unit": "Count"},
            {"MetricName": "HoneypotDivertedRequests", "Value": snapshot.diverted_count, "Unit": "Count"},
            {"MetricName": "EvaluationLatency", "Value": snapshot.avg_latency_ms, "Unit": "Milliseconds"},
        ]
