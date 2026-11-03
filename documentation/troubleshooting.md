# Troubleshooting Guide

## Common Operational Issues & Resolutions
1. **`Cannot find required executable ovs-vsctl` or `RTNETLINK answers: Operation not permitted`:**
   - **Cause:** Running `network/topology.py` without `sudo` or inside an unprivileged container without the Open vSwitch kernel module.
   - **Fix:** On Ubuntu/WSL2, start OVS via `sudo service openvswitch-switch start` and run Mininet with `sudo`. On restricted machines, run `python3 -m controller.sdn_controller --standalone-sim` or trigger scenarios via the FastAPI backend.
2. **Ryu `ImportError: cannot import name 'ALREADY_HANDLED' from 'eventlet.wsgi'`:**
   - **Cause:** Newer versions of `eventlet` (`>=0.31`) removed internal symbols used by `ryu==4.34`.
   - **Fix:** Pin `eventlet==0.30.2` on Python 3.9/3.10 (already pinned in `requirements.txt`), or use `os-ken>=2.6.0` on Python 3.11+.
3. **Legitimate High-Volume Client Throttled:**
   - **Cause:** Packet rate threshold (`THRESHOLD_PPS`) set too low for bulk file transfers.
   - **Fix:** Open **Page 7: Settings** in the Web Dashboard, switch Detection Mode to `Hybrid` or `ML (Random Forest)`, or raise `max_packets_per_sec` from `1200` to `1800` pps. Can also click **Manual Unblock** on **Page 5: Threat Mitigation**.
