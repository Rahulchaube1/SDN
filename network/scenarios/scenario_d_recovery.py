"""
Demonstration Scenario D: Network Recovery & Rule Expiration
- Stops simulated abnormal traffic from h5 and h6.
- Removes expired temporary mitigation rules from OpenFlow switch tables.
- Restores normal network behavior and displays recovery statistics.
"""
import time
from controller.sdn_controller import GuardianSDNController
from network.normal_traffic import generate_normal_flow_batch
from network.abnormal_traffic import generate_abnormal_flow_batch


def run_scenario_d() -> dict:
    ctrl = GuardianSDNController()
    ctrl.scenario_state = "SCENARIO_D_RECOVERY"
    ctrl.mitigation.enabled = True
    ctrl.mitigation.default_duration_sec = 1  # Short timeout to demonstrate automatic expiration

    # Step 1: Trigger mitigation during attack
    combined = generate_normal_flow_batch(step=1) + generate_abnormal_flow_batch("syn_flood", step=1)
    ctrl.ingest_simulated_flows(dpid=2, raw_flows=[f for f in combined if f["dpid"] == 2])

    # Step 2: Attack ceases; wait for temporary rule timeout and run normal traffic
    time.sleep(1.1)
    ctrl.mitigation.expire_stale_rules()
    ctrl.topology.update_host_status("10.0.0.5", "ONLINE")

    normal_only = generate_normal_flow_batch(step=2)
    ctrl.ingest_simulated_flows(dpid=2, raw_flows=[f for f in normal_only if f["dpid"] == 2])
    ctrl.ingest_simulated_flows(dpid=3, raw_flows=[f for f in normal_only if f["dpid"] == 3])

    snap = ctrl.get_dashboard_snapshot()
    print("=== Scenario D: Network Recovery & Automatic Rule Expiration ===")
    print(f"Active Mitigation Rules: {snap['overview']['active_mitigations']} | Historical Rules Logged: {len(snap['mitigation_history'])}")
    print(f"Post-Recovery Suspicious Flows: {snap['overview']['suspicious_flows']} | Health Score: {snap['overview']['network_health_pct']}%")
    return snap


if __name__ == "__main__":
    run_scenario_d()
