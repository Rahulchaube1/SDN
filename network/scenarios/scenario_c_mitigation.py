"""
Demonstration Scenario C: Automatic Threat Mitigation
- Identifies suspicious flows from h5 (10.0.0.5) and h6 (10.0.0.6).
- Automatically generates and installs high-priority OpenFlow 1.3 DROP rules on s2 and s3.
- Verifies rule installation and demonstrates that legitimate clients (h1-h4) continue
  communicating normally with srv1 (10.0.0.100).
"""
from controller.sdn_controller import GuardianSDNController
from network.normal_traffic import generate_normal_flow_batch
from network.abnormal_traffic import generate_abnormal_flow_batch


def run_scenario_c() -> dict:
    ctrl = GuardianSDNController()
    ctrl.scenario_state = "SCENARIO_C_AUTO_MITIGATION"
    ctrl.mitigation.enabled = True

    for step in range(1, 3):
        combined = generate_normal_flow_batch(step=step) + generate_abnormal_flow_batch("multi_vector", step=step)
        ctrl.ingest_simulated_flows(dpid=2, raw_flows=[f for f in combined if f["dpid"] == 2])
        ctrl.ingest_simulated_flows(dpid=3, raw_flows=[f for f in combined if f["dpid"] == 3])

    snap = ctrl.get_dashboard_snapshot()
    print("=== Scenario C: Automatic OpenFlow Threat Mitigation ===")
    print(f"Active Mitigation Rules Installed: {snap['overview']['active_mitigations']}")
    for rule in snap["active_mitigations"]:
        print(f"  [RULE {rule['rule_id']}] Switch={rule['switch_name']} | Src={rule['src_ip']} | Action={rule['action']} | Priority={rule['priority']} | Verified={rule['verified_on_switch']}")
    print(f"Post-Mitigation Effective Aggregate PPS (Legitimate Clients Protected): {snap['overview']['packets_per_sec']} pps")
    return snap


if __name__ == "__main__":
    run_scenario_c()
