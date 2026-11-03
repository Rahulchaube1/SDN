# Implementation Details — Detection & OpenFlow Mitigation

## 1. 7-Dimensional OpenFlow Feature Vector
Every 2.0 seconds, `FlowFeatureExtractor` transforms raw `OFPFlowStatsReply` counters into:
1. `packet_count` ($N_p$): Cumulative packets matched by the flow entry.
2. `byte_count` ($N_b$): Cumulative bytes matched by the flow entry.
3. `flow_duration_sec` ($T_d$): Active duration of the flow entry in seconds.
4. `packets_per_sec` ($R_p = \Delta N_p / \Delta t$): Windowed packet rate.
5. `bytes_per_sec` ($R_b = \Delta N_b / \Delta t$): Windowed byte rate.
6. `source_flow_count` ($F_{src}$): Number of concurrent active flows originating from the same source IPv4 address on the switch.
7. `traffic_variation_cv` ($CV = \sigma_{R_p} / \mu_{R_p}$): Coefficient of variation across the sliding window.

## 2. Hybrid Detection Logic
- **Rule-Based Engine (`rule_detector.py`):** Evaluates 5 configurable indicators (`max_packets_per_sec=1200`, `max_bytes_per_sec=1.5 MB/s`, `max_source_flow_count=35`, `max_traffic_variation_cv=1.15`, `max_syn_flag_ratio=0.65`).
- **ML Classifiers (`ml_detector.py`):** Applies `log1p` transformation to heavy-tailed rate/volume features followed by Z-score standardization, then runs inference through a 35-tree **Random Forest Classifier** (supervised) or a 65-tree **Isolation Forest** (semi-supervised anomaly detector).
- **Hybrid Fusion (`flow_monitor.py`):** Computes $S_{hybrid} = 0.45 S_{rule} + 0.55 S_{ML}$, achieving `97.62%` F1-score with Random Forest (`0.051 ms` per-flow inference latency).

## 3. OpenFlow 1.3 Mitigation Rule Construction
When a flow is flagged as anomalous:
- `ThreatMitigationEngine` checks the protected safelist (`10.0.0.100`).
- Constructs an `OFPFlowMod` message (`command=OFPFC_ADD`, `priority=500`, `hard_timeout=60`, `idle_timeout=30`) matching `eth_type=0x0800, ipv4_src=<attacker_ip>, ipv4_dst=10.0.0.100` with an empty instruction list (immediate hardware/kernel table drop) or attaches an `OFPInstructionMeter` (`512 kbps` rate limit).
