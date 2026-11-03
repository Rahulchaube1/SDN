# College Presentation & Live Demonstration Guide

## Quick 5-Minute Live Viva / Classroom Walkthrough
1. **Step 1 — Show Normal Operation (Scenario A):**
   - Run `python3 -m network.scenarios.scenario_a_normal` or click **Scenario A** on the Dashboard.
   - Point out **Page 1 (Overview)** and **Page 2 (Live Topology)**: all 3 switches (`s1, s2, s3`) and 7 hosts are online, aggregate traffic is ~`550 pps`, suspicious flows = `0`, and Network Health is `100%`.
2. **Step 2 — Trigger Simulated DDoS & Observe Detection (Scenario B):**
   - Run `python3 -m network.scenarios.scenario_b_detection` or click **Scenario B**.
   - Navigate to **Page 4 (Security Monitoring)**: show the `CRITICAL` alerts generated for isolated simulation hosts `h5 (10.0.0.5)` (`TCP_SYN_FLOOD`, `~2,850 pps`) and `h6 (10.0.0.6)` (`UDP_VOLUMETRIC_FLOOD`, `~3,400 pps`).
3. **Step 3 — Demonstrate Automated OpenFlow Mitigation (Scenario C):**
   - Run `python3 -m network.scenarios.scenario_c_mitigation` or click **Scenario C**.
   - Navigate to **Page 5 (Threat Mitigation)**: highlight the verified OpenFlow `DROP` rules (`priority=500`, `Verified on Switch = YES`) installed on `s2` and `s3`, and show that legitimate clients `h1–h4` continue communicating with `srv1 (10.0.0.100)` at `96.16%` packet delivery ratio.
4. **Step 4 — Demonstrate Recovery & Manual Unblock (Scenario D):**
   - Run `python3 -m network.scenarios.scenario_d_recovery` or click **Scenario D** (or click **Manual Unblock**).
   - Show that temporary rules expire cleanly and network health returns to `100%`.
