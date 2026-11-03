"""
Rule-Based Anomaly Detector for OpenFlow Traffic Monitoring
Evaluates extracted FlowFeatureVectors against configurable operational thresholds:
1. Unusually high packet rate (PPS threshold)
2. Unusually high byte rate (BPS threshold)
3. Sudden traffic spikes (coefficient of variation / Z-score threshold)
4. Excessive connection attempts / SYN flood ratio
5. Abnormal source flow frequency (flow table exhaustion indicator)
"""
from dataclasses import dataclass, asdict
from typing import Dict, Any, List
from .feature_extractor import FlowFeatureVector


@dataclass
class RuleConfig:
    """Configurable threshold parameters for rule-based SDN anomaly detection."""
    max_packets_per_sec: float = 1200.0
    max_bytes_per_sec: float = 1_500_000.0  # 1.5 MB/s (~12 Mbps per single flow)
    max_source_flow_count: int = 35
    max_traffic_variation_cv: float = 1.15
    max_syn_flag_ratio: float = 0.65
    min_packets_for_spike: int = 150

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RuleBasedDetector:
    """Deterministic multi-indicator threshold detector."""

    def __init__(self, config: RuleConfig = None):
        self.config = config or RuleConfig()

    def update_config(self, **kwargs) -> None:
        for k, v in kwargs.items():
            if hasattr(self.config, k):
                setattr(self.config, k, v)

    def evaluate(self, fv: FlowFeatureVector) -> Dict[str, Any]:
        """
        Inspect a single FlowFeatureVector and return a structured detection decision
        containing triggered indicators, composite risk score [0, 1], and severity level.
        """
        reasons: List[str] = []
        score = 0.0

        # Indicator 1: Unusually high packet rate
        if fv.packets_per_sec >= self.config.max_packets_per_sec:
            ratio = min(3.0, fv.packets_per_sec / max(1.0, self.config.max_packets_per_sec))
            score += 0.40 * (ratio / 1.5)
            reasons.append(f"High packet rate ({fv.packets_per_sec:.0f} pps >= {self.config.max_packets_per_sec:.0f} pps)")

        # Indicator 2: Unusually high byte rate
        if fv.bytes_per_sec >= self.config.max_bytes_per_sec:
            ratio = min(3.0, fv.bytes_per_sec / max(1.0, self.config.max_bytes_per_sec))
            score += 0.30 * (ratio / 1.5)
            reasons.append(f"High byte rate ({fv.bytes_per_sec / 1e6:.2f} MB/s >= {self.config.max_bytes_per_sec / 1e6:.2f} MB/s)")

        # Indicator 3: Abnormal flow frequency from single source IP
        if fv.source_flow_count >= self.config.max_source_flow_count:
            score += 0.35
            reasons.append(f"Excessive source flow fan-out ({fv.source_flow_count} concurrent flows)")

        # Indicator 4: Sudden traffic spike / high burstiness
        if fv.traffic_variation_cv >= self.config.max_traffic_variation_cv and fv.packet_count >= self.config.min_packets_for_spike:
            score += 0.25
            reasons.append(f"Sudden traffic spike (CV={fv.traffic_variation_cv:.2f})")

        # Indicator 5: Small-packet flood / SYN flood signature
        if fv.syn_flag_ratio >= self.config.max_syn_flag_ratio and fv.packets_per_sec >= (0.4 * self.config.max_packets_per_sec):
            score += 0.30
            reasons.append(f"Excessive SYN connection attempts (SYN ratio={fv.syn_flag_ratio:.2f})")

        normalized_score = round(min(1.0, score), 4)
        is_anomalous = normalized_score >= 0.40 or len(reasons) >= 2

        if normalized_score >= 0.80:
            severity = "CRITICAL"
        elif normalized_score >= 0.55:
            severity = "HIGH"
        elif is_anomalous:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Classify likely attack subtype
        attack_type = "NORMAL"
        if is_anomalous:
            if fv.ip_proto == 1 or (fv.dst_port == 0 and fv.packets_per_sec > 1000):
                attack_type = "ICMP_FLOOD"
            elif fv.syn_flag_ratio >= 0.65 or (fv.ip_proto == 6 and fv.avg_packet_size < 120):
                attack_type = "TCP_SYN_FLOOD"
            elif fv.ip_proto == 17 or fv.bytes_per_sec >= self.config.max_bytes_per_sec:
                attack_type = "UDP_VOLUMETRIC_FLOOD"
            elif fv.source_flow_count >= self.config.max_source_flow_count:
                attack_type = "FLOW_TABLE_EXHAUSTION"
            else:
                attack_type = "ANOMALOUS_SPIKE"

        return {
            "flow_id": fv.flow_id,
            "is_anomalous": bool(is_anomalous),
            "confidence": normalized_score,
            "severity": severity,
            "attack_type": attack_type,
            "method": "RULE_BASED",
            "reasons": reasons if reasons else ["Traffic within normal threshold parameters"],
        }
