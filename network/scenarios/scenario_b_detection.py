"""
Demonstration Scenario B: Abnormal Traffic Detection
- Generates controlled abnormal traffic from isolated host h5 (10.0.0.5) & h6 (10.0.0.6).
- Monitors OpenFlow flow statistics with automatic mitigation temporarily disabled
  so the operator can observe raw detection alerts, confidence scores, and severity.
"""
from controller.sdn_controller import GuardianSDNController
from network.normal_traffic import generate_normal_flow_batch
from network.abnormal_traffic import generate_abnormal_flow_batch


def run_scenario_b() -> dict:
    ctrl = GuardianSDNController()
    ctrl.scenario_state = "SCENARIO_B_ABNORMAL_DETECTION"
    ctrl.mitigation.enabled = False  # Observe raw detection before mitigation

    normal_flows = generate_normal_flow_batch(step=2)
    attack_flows = generate_abnormal_flow_batch("multi_vector", step=2)
    combined = normal_flows + attack_flows

    ctrl.ingest_simulated_flows(dpid=2, raw_flows=[f for f in combined if f["dpid"] == 2])
    ctrl.ingest_simulated_flows(dpid=3, raw_flows=[f for f in combined if f["dpid"] == 3])

    snap = ctrl.get_dashboard_snapshot()
    print("=== Scenario B: Abnormal Traffic Detection ===")
    print(f"Detected Suspicious Flows: {snap['overview']['suspicious_flows']} | Active Alerts: {snap['overview']['active_alerts']}")
    for alt in snap["alerts"][:3]:
        print(f"  [ALERT] {alt['severity']} | {alt['src_ip']} -> {alt['dst_ip']} | {alt['attack_type']} | Method={alt['detection_method']} | Conf={alt['confidence']}")
    return snap


if __name__ == "__main__":
    run_scenario_b()
