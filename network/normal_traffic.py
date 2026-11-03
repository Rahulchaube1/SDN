"""
Normal Network Traffic Generator (`normal_traffic.py`)
Generates realistic baseline enterprise/campus traffic between normal clients
(h1: 10.0.0.1, h2: 10.0.0.2, h3: 10.0.0.3, h4: 10.0.0.4) and the protected
application server (srv1: 10.0.0.100).
"""
import time
from typing import List, Dict, Any
import numpy as np


def generate_normal_flow_batch(step: int = 1, seed: int = 100) -> List[Dict[str, Any]]:
    """
    Produce a realistic batch of OpenFlow flow records from normal clients h1-h4
    representing HTTP/HTTPS requests, REST API calls, and DNS queries.
    """
    rng = np.random.default_rng(seed + step * 13)
    clients = [
        ("10.0.0.1", 2, 80, 6, 130.0, 780.0),
        ("10.0.0.2", 2, 443, 6, 165.0, 920.0),
        ("10.0.0.3", 3, 80, 6, 115.0, 740.0),
        ("10.0.0.4", 3, 8080, 6, 140.0, 680.0),
    ]
    flows: List[Dict[str, Any]] = []
    dur = float(max(2.0, step * 2.0))

    for src_ip, dpid, dst_port, proto, base_pps, avg_pkt_bytes in clients:
        pps = float(max(25.0, rng.normal(base_pps, 22.0)))
        pkt_bytes = float(max(200.0, rng.normal(avg_pkt_bytes, 65.0)))
        pkt_count = int(round(pps * dur))
        byte_count = int(round(pkt_count * pkt_bytes))
        bps = pps * pkt_bytes

        flows.append({
            "flow_id": f"s{dpid}:{src_ip}:5010{dpid}->10.0.0.100:{dst_port}:{proto}",
            "dpid": dpid,
            "src_ip": src_ip,
            "dst_ip": "10.0.0.100",
            "src_port": 50100 + dpid,
            "dst_port": dst_port,
            "ip_proto": proto,
            "packet_count": pkt_count,
            "byte_count": byte_count,
            "duration_sec": dur,
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "source_flow_count": int(rng.integers(2, 8)),
            "traffic_variation_cv": round(float(rng.uniform(0.14, 0.42)), 4),
            "syn_flag_ratio": round(float(rng.uniform(0.02, 0.10)), 4),
            "timestamp": time.time(),
        })
    return flows


if __name__ == "__main__":
    batch = generate_normal_flow_batch(step=1)
    print(f"Generated {len(batch)} normal client flows targeting srv1 (10.0.0.100):")
    for f in batch:
        print(f"  {f['src_ip']} -> {f['dst_ip']}:{f['dst_port']} | {f['packets_per_sec']} pps | {f['bytes_per_sec']/1000:.1f} KB/s")
