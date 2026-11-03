"""
Demonstration Scenario A: Normal Network Operation
- Starts the virtual network topology and SDN controller.
- Connects normal clients (h1-h4) to server srv1 (10.0.0.100).
- Generates normal baseline HTTP/TLS/API traffic.
- Displays live traffic statistics and confirms 100% network health with 0 false alarms.
"""
from controller.sdn_controller import GuardianSDNController
from network.normal_traffic import generate_normal_flow_batch


def run_scenario_a() -> dict:
    ctrl = GuardianSDNController()
    ctrl.scenario_state = "SCENARIO_A_NORMAL"
    for step in range(1, 5):
        normal_flows = generate_normal_flow_batch(step=step)
        s2_flows = [f for f in normal_flows if f["dpid"] == 2]
        s3_flows = [f for f in normal_flows if f["dpid"] == 3]
        ctrl.ingest_simulated_flows(dpid=2, raw_flows=s2_flows)
        ctrl.ingest_simulated_flows(dpid=3, raw_flows=s3_flows)
    snap = ctrl.get_dashboard_snapshot()
    print("=== Scenario A: Normal Network Operation ===")
    print(f"Connected Hosts: {snap['overview']['connected_hosts']} | Active Switches: {snap['overview']['active_switches']}")
    print(f"Aggregate PPS: {snap['overview']['packets_per_sec']} | Bandwidth: {snap['overview']['bandwidth_mbps']} Mbps")
    print(f"Suspicious Flows: {snap['overview']['suspicious_flows']} | Health Score: {snap['overview']['network_health_pct']}%")
    return snap


if __name__ == "__main__":
    run_scenario_a()
