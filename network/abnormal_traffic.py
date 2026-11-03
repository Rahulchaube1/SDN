"""
Controlled Abnormal Traffic Simulator (`abnormal_traffic.py`)
Safety Policy:
Strictly confined to isolated simulation hosts h5 (10.0.0.5 on switch s2) and
h6 (10.0.0.6 on switch s3) inside the local virtual network. Never emits packets
to external/public IP addresses.
"""
import time
from typing import List, Dict, Any
import numpy as np


ALLOWED_SIMULATION_SOURCES = {"10.0.0.5", "10.0.0.6"}
ALLOWED_SIMULATION_TARGETS = {"10.0.0.100"}


def generate_abnormal_flow_batch(
    attack_profile: str = "syn_flood", step: int = 1, seed: int = 500
) -> List[Dict[str, Any]]:
    """
    Generate controlled anomalous OpenFlow flow records from isolated simulation hosts
    h5 (10.0.0.5) and h6 (10.0.0.6) targeting local virtual server srv1 (10.0.0.100).
    """
    rng = np.random.default_rng(seed + step * 19)
    dur = float(max(2.0, step * 2.0))
    flows: List[Dict[str, Any]] = []

    if attack_profile == "syn_flood":
        pps = float(rng.normal(2850.0, 240.0))
        pkt_size = 74.0
        src_flows = int(rng.integers(58, 96))
        cv = float(rng.uniform(1.45, 2.05))
        syn_ratio = float(rng.uniform(0.88, 0.98))
        proto = 6
        dst_port = 80
        src_ip, dpid = "10.0.0.5", 2
    elif attack_profile == "udp_flood":
        pps = float(rng.normal(3400.0, 310.0))
        pkt_size = 980.0
        src_flows = int(rng.integers(40, 75))
        cv = float(rng.uniform(1.30, 1.95))
        syn_ratio = 0.0
        proto = 17
        dst_port = 53
        src_ip, dpid = "10.0.0.6", 3
    else:
        # Multi-vector coordinated flood from both h5 and h6
        return (
            generate_abnormal_flow_batch("syn_flood", step=step, seed=seed)
            + generate_abnormal_flow_batch("udp_flood", step=step, seed=seed + 7)
        )

    assert src_ip in ALLOWED_SIMULATION_SOURCES, "Abnormal simulation restricted to isolated hosts 10.0.0.5/10.0.0.6"
    pkt_count = int(round(pps * dur))
    byte_count = int(round(pkt_count * pkt_size))
    bps = pps * pkt_size

    flows.append({
        "flow_id": f"s{dpid}:{src_ip}:4400{step}->10.0.0.100:{dst_port}:{proto}",
        "dpid": dpid,
        "src_ip": src_ip,
        "dst_ip": "10.0.0.100",
        "src_port": 44000 + step,
        "dst_port": dst_port,
        "ip_proto": proto,
        "packet_count": pkt_count,
        "byte_count": byte_count,
        "duration_sec": dur,
        "packets_per_sec": round(pps, 2),
        "bytes_per_sec": round(bps, 2),
        "source_flow_count": src_flows,
        "traffic_variation_cv": round(cv, 4),
        "syn_flag_ratio": round(syn_ratio, 4),
        "timestamp": time.time(),
    })
    return flows


if __name__ == "__main__":
    batch = generate_abnormal_flow_batch("multi_vector", step=1)
    for f in batch:
        print(f"[SIMULATED ATTACK] {f['src_ip']} -> {f['dst_ip']}:{f['dst_port']} | {f['packets_per_sec']} pps | flows={f['source_flow_count']}")
