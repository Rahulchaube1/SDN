"""
OpenFlow 1.3 Flow Statistics Feature Extractor
Transforms raw OFPFlowStatsReply records into normalized 7-dimensional feature vectors
suitable for both rule-based threshold inspection and ML inference.
"""
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional
import time
import numpy as np


FEATURE_NAMES = [
    "packet_count",
    "byte_count",
    "flow_duration_sec",
    "packets_per_sec",
    "bytes_per_sec",
    "source_flow_count",
    "traffic_variation_cv",
]


@dataclass
class FlowFeatureVector:
    """Structured representation of extracted OpenFlow flow features."""
    flow_id: str
    dpid: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    ip_proto: int
    packet_count: int
    byte_count: int
    flow_duration_sec: float
    packets_per_sec: float
    bytes_per_sec: float
    source_flow_count: int
    traffic_variation_cv: float
    syn_flag_ratio: float = 0.0
    avg_packet_size: float = 0.0
    timestamp: float = 0.0

    def to_numpy(self) -> np.ndarray:
        return np.array([
            float(self.packet_count),
            float(self.byte_count),
            float(self.flow_duration_sec),
            float(self.packets_per_sec),
            float(self.bytes_per_sec),
            float(self.source_flow_count),
            float(self.traffic_variation_cv),
        ], dtype=np.float64)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FlowFeatureExtractor:
    """
    Maintains sliding-window per-flow and per-source state to compute instantaneous
    and window-averaged rate features from OpenFlow OFPFlowStatsReply messages.
    """

    def __init__(self, history_window: int = 8):
        self.history_window = max(2, history_window)
        self._flow_history: Dict[str, List[Dict[str, float]]] = {}

    def extract_from_switch_flows(
        self, dpid: int, raw_flows: List[Dict[str, Any]], timestamp: Optional[float] = None
    ) -> List[FlowFeatureVector]:
        now = timestamp if timestamp is not None else time.time()

        src_flow_counts: Dict[str, int] = {}
        for f in raw_flows:
            src = str(f.get("src_ip", "0.0.0.0"))
            src_flow_counts[src] = src_flow_counts.get(src, 0) + 1

        vectors: List[FlowFeatureVector] = []
        for f in raw_flows:
            src_ip = str(f.get("src_ip", "0.0.0.0"))
            dst_ip = str(f.get("dst_ip", "0.0.0.0"))
            src_port = int(f.get("src_port", 0))
            dst_port = int(f.get("dst_port", 80))
            ip_proto = int(f.get("ip_proto", 6))
            flow_id = f.get("flow_id") or f"s{dpid}:{src_ip}:{src_port}->{dst_ip}:{dst_port}:{ip_proto}"

            pkt_count = max(0, int(f.get("packet_count", 0)))
            byte_count = max(0, int(f.get("byte_count", 0)))
            duration_sec = max(0.001, float(f.get("duration_sec", 1.0)) + float(f.get("duration_nsec", 0)) * 1e-9)
            avg_pkt_size = byte_count / max(1, pkt_count)

            hist = self._flow_history.setdefault(flow_id, [])
            if hist and pkt_count >= hist[-1]["packet_count"] and duration_sec > hist[-1]["duration_sec"]:
                dt = max(0.1, duration_sec - hist[-1]["duration_sec"])
                dpkts = pkt_count - hist[-1]["packet_count"]
                dbytes = max(0, byte_count - hist[-1]["byte_count"])
                pps = dpkts / dt
                bps = dbytes / dt
            else:
                pps = pkt_count / duration_sec
                bps = byte_count / duration_sec

            if "packets_per_sec" in f and f["packets_per_sec"] is not None:
                pps = float(f["packets_per_sec"])
            if "bytes_per_sec" in f and f["bytes_per_sec"] is not None:
                bps = float(f["bytes_per_sec"])

            hist.append({
                "timestamp": now,
                "packet_count": float(pkt_count),
                "byte_count": float(byte_count),
                "duration_sec": duration_sec,
                "pps": pps,
            })
            if len(hist) > self.history_window:
                hist.pop(0)

            if "traffic_variation_cv" in f and f["traffic_variation_cv"] is not None:
                cv = float(f["traffic_variation_cv"])
            elif len(hist) >= 2:
                pps_series = np.array([h["pps"] for h in hist], dtype=np.float64)
                mean_pps = float(np.mean(pps_series))
                std_pps = float(np.std(pps_series))
                cv = std_pps / max(1.0, mean_pps)
            else:
                cv = 0.18 if avg_pkt_size > 200 else 1.45

            src_flows = int(f.get("source_flow_count", src_flow_counts.get(src_ip, 1)))
            syn_ratio = float(f.get("syn_flag_ratio", 0.05 if avg_pkt_size > 200 else 0.85))

            vectors.append(FlowFeatureVector(
                flow_id=flow_id,
                dpid=dpid,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                ip_proto=ip_proto,
                packet_count=pkt_count,
                byte_count=byte_count,
                flow_duration_sec=round(duration_sec, 4),
                packets_per_sec=round(pps, 2),
                bytes_per_sec=round(bps, 2),
                source_flow_count=src_flows,
                traffic_variation_cv=round(cv, 4),
                syn_flag_ratio=round(syn_ratio, 4),
                avg_packet_size=round(avg_pkt_size, 2),
                timestamp=now,
            ))

        return vectors
