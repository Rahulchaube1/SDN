# Installation & Environment Setup Guide

## 1. System Prerequisites
- **Linux Host or WSL2 Ubuntu 20.04 / 22.04 LTS:** Mininet requires Linux network namespaces (`ip netns`) and Open vSwitch kernel modules.
- **Python 3.9, 3.10, or 3.11:** With `venv` and `pip`.
- **Node.js 18+ / 20+:** For building or running the Vite + React frontend development server.

## 2. Step-by-Step WSL2 Ubuntu Setup for Windows Users
1. Open PowerShell as Administrator and run `wsl --install -d Ubuntu-22.04`.
2. Launch Ubuntu and start the Open vSwitch service:
   ```bash
   sudo apt-get update
   sudo apt-get install -y mininet openvswitch-switch python3-pip python3-venv iperf3 hping3
   sudo service openvswitch-switch start
   sudo ovs-vsctl show
   ```
3. Verify OpenFlow 1.3 switch creation:
   ```bash
   sudo mn --switch ovsk,protocols=OpenFlow13 --test pingall
   ```

## 3. Standalone Classroom Demo Mode (Zero Root Privileges Required)
For laptops or container environments where kernel OVS modules cannot be loaded, the entire controller, ML pipeline, FastAPI backend, 4 scenarios, and 7-page Web Dashboard run natively in userspace simulation mode:
```bash
python3 -m experiments.run_experiments
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```
