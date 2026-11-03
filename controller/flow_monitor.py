"""
OpenFlow 1.3 Flow Statistics Monitor
Coordinates periodic flow table polling (OFPFlowStatsRequest), feature extraction,
hybrid anomaly detection (Rule-Based + ML Classifier), and automated mitigation dispatch.
"""
import time
from typing import Dict, Any, List, Optional

from detection.feature_extractor import FlowFeatureExtractor, FlowFeatureVector
from detection.rule_detector import RuleBasedDetector, RuleConfig
from detection.ml_detector import MLAnomalyDetector
from .topology_manager import TopologyManager
from .mitigation_engine import ThreatMitigationEngine


class FlowMonitor:
    """Centralized flow statistics monitor and detection orchestrator."""

    def __init__(
        self,
        topology: TopologyManager,
        mitigation_engine: ThreatMitigationEngine,
        detection_mode: str = "hybrid",
        ml_model_type: str = "random_forest",
    ):
        self.topology = topology
        self.mitigation_engine = mitigation_engine
        self.feature_extractor = FlowFeatureExtractor(history_window=8)
        self.rule_detector = RuleBasedDetector(RuleConfig())
        self.ml_detector = MLAnomalyDetector(active_model=ml_model_type)
        self.detection_mode = detection_mode  # "rule", "ml", or "hybrid"
        self.ml_model_type = ml_model_type
        self.latest_flows: List[Dict[str, Any]] = []
        self.security_alerts: List[Dict[str, Any]] = []
        self.traffic_Summary_history: List[Dict[str, Any]] = []

    def process_switch_flow_stats(
        self, dpid: int, raw_flows: List[Dict[str, Any]], timestamp: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Process a batch of OpenFlow flow statistics from switch `dpid`, run anomaly
        detection on each flow, trigger automated mitigation if warranted, and return
        aggregated telemetry.
        """
        now = timestamp if timestamp is not None else time.time()
        self.mitigation_engine.expire_stale_rules()

        # Filter out traffic from sources that currently have an active DROP rule installed
        active_dropped_ips = {
            r.src_ip
            for r in self.mitigation_engine.active_rules.values()
            if r.status == "ACTIVE" and r.action == "DROP"
        }

        vectors: List[FlowFeatureVector] = self.feature_extractor.extract_from_switch_flows(dpid, raw_flows, now)
        processed_flows: List[Dict[str, Any]] = []
        new_alerts: List[Dict[str, Any]] = []
        new_mitigations: List[Dict[str, Any]] = []

        total_pps = 0.0
        total_bps = 0.0
        suspicious_count = 0

        for fv in vectors:
            # If source IP is actively blocked by an OpenFlow drop rule on switch, traffic is dropped at ingress
            is_blocked = fv.src_ip in active_dropped_ips
            effective_pps = fv.packets_per_sec * (0.02 if is_blocked else 1.0)
            effective_bps = fv.bytes_per_sec * (0.02 if is_blocked else 1.0)

            rule_res = self.rule_detector.evaluate(fv)
            ml_res = self.ml_detector.evaluate(fv, model_type=self.ml_model_type)

            if self.detection_mode == "rule":
                final_res = rule_res
            elif self.detection_mode == "ml":
                final_res = ml_res
            else:
                # Hybrid mode combines Rule-Based deterministic guarantees with ML pattern sensitivity
                comb_conf = round(0.45 * rule_res["confidence"] + 0.55 * ml_res["confidence"], 4)
                is_anom = bool(rule_res["is_anomalous"] or ml_res["is_anomalous"] or comb_conf >= 0.55)
                severity = (
                    "CRITICAL" if comb_conf >= 0.80
                    else "HIGH" if comb_conf >= 0.60
                    else "MEDIUM" if is_anom
                    else "LOW"
                )
                attack_type = ml_res["attack_type"] if ml_res["is_anomalous"] else rule_res["attack_type"]
                reasons = []
                if rule_res["is_anomalous"]:
                    reasons.extend(rule_res["reasons"])
                if ml_res["is_anomalous"]:
                    reasons.extend(ml_res["reasons"])
                if not reasons:
                    reasons = ["Normal flow profile verified by Hybrid (Rule + ML) engine"]
                final_res = {
                    "flow_id": fv.flow_id,
                    "is_anomalous": is_anom,
                    "confidence": comb_conf,
                    "severity": severity,
                    "attack_type": attack_type,
                    "method": f"HYBRID ({self.ml_model_type.upper()}+RULE)",
                    "inference_latency_ms": ml_res.get("inference_latency_ms", 0.15),
                    "reasons": reasons,
                }

            flow_record = {
                **fv.to_dict(),
                "effective_pps": round(effective_pps, 2),
                "effective_bps": round(effective_bps, 2),
                "is_anomalous": final_res["is_anomalous"],
                "confidence": final_res["confidence"],
                "severity": final_res["severity"],
                "attack_type": final_res["attack_type"],
                "detection_method": final_res["method"],
                "reasons": final_res["reasons"],
                "mitigated": is_blocked,
            }

            if final_res["is_anomalous"]:
                suspicious_count += 1
                alert = {
                    "alert_id": f"alt-{int(now * 1000)}-{fv.dpid}-{fv.src_ip.split('.')[-1]}",
                    "timestamp": now,
                    "dpid": fv.dpid,
                    "switch_name": f"s{fv.dpid}",
                    "src_ip": fv.src_ip,
                    "dst_ip": fv.dst_ip,
                    "src_port": fv.src_port,
                    "dst_port": fv.dst_port,
                    "ip_proto": fv.ip_proto,
                    "packets_per_sec": fv.packets_per_sec,
                    "bytes_per_sec": fv.bytes_per_sec,
                    "detection_method": final_res["method"],
                    "attack_type": final_res["attack_type"],
                    "severity": final_res["severity"],
                    "confidence": final_res["confidence"],
                    "reasons": final_res["reasons"],
                }
                new_alerts.append(alert)
                self.security_alerts.insert(0, alert)
                if len(self.security_alerts) > 200:
                    self.security_alerts.pop()

                mit_rule = self.mitigation_engine.mitigate_flow(fv.to_dict(), final_res)
                if mit_rule is not None:
                    flow_record["mitigated"] = True
                    flow_record["mitigation_action"] = mit_rule.action
                    flow_record["mitigation_rule_id"] = mit_rule.rule_id
                    new_mitigations.append(mit_rule.to_dict())
                    self.topology.update_host_status(
                        fv.src_ip, "BLOCKED" if mit_rule.action == "DROP" else "RATE_LIMITED"
                    )

            total_pps += effective_pps
            total_bps += effective_bps
            processed_flows.append(flow_record)

        # Keep latest flows across switches
        other_switch_flows = [f for f in self.latest_flows if f.get("dpid") != dpid]
        self.latest_flows = other_switch_flows + processed_flows

        fabric_pps = sum(float(f.get("effective_pps", f.get("packets_per_sec", 0.0))) for f in self.latest_flows)
        fabric_bps = sum(float(f.get("effective_bps", f.get("bytes_per_sec", 0.0))) for f in self.latest_flows)
        fabric_suspicious = sum(1 for f in self.latest_flows if f.get("is_anomalous"))

        summary_point = {
            "timestamp": now,
            "dpid": dpid,
            "total_pps": round(fabric_pps, 2),
            "total_bps": round(fabric_bps, 2),
            "total_mbps": round((fabric_bps * 8.0) / 1e6, 3),
            "active_flows": len(self.latest_flows),
            "suspicious_flows": fabric_suspicious,
            "active_mitigations": len(self.mitigation_engine.active_rules),
        }
        self.traffic_Summary_history.append(summary_point)
        if len(self.traffic_Summary_history) > 120:
            self.traffic_Summary_history.pop(0)

        return {
            "summary": summary_point,
            "flows": processed_flows,
            "new_alerts": new_alerts,
            "new_mitigations": new_mitigations,
        }
