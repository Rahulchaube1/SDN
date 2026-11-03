# Technical Architecture Specification — AI-Powered SDN Network Guardian

## 1. Three-Plane SDN Security Architecture
The system implements the Open Networking Foundation (ONF) three-plane SDN model:
1. **Data Plane (Infrastructure Layer):** Three Open vSwitch (`OVS`) instances (`s1` Core Switch, `s2` Edge Switch West, `s3` Edge Switch East) forwarding packets across 7 virtual hosts (`srv1`, `h1–h4`, `h5–h6`) using OpenFlow 1.3 flow tables and meter bands.
2. **Control Plane (SDN Controller Layer):** Centralized Python controller (`controller/sdn_controller.py`) managing topology discovery (`topology_manager.py`), 2-second periodic flow counter collection (`flow_monitor.py`), and automated threat mitigation (`mitigation_engine.py`).
3. **Application & Management Plane:** Hybrid AI Anomaly Detection Engine (`detection/`), FastAPI + SQLite telemetry backend (`backend/`), and 7-page React NOC Web Dashboard (`frontend/`).

## 2. Addressing & Port Allocation Table
| Node | Role | IPv4 Address | MAC Address | Connected Switch & Port | Protected Safelist |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `c0` | Ryu OpenFlow 1.3 Controller | `127.0.0.1:6653` | Control Channel | Out-of-Band TCP `6653` | Yes |
| `srv1` | Application Server | `10.0.0.100/24` | `00:00:00:00:01:00` | `s1` — Port `1` | Yes (Never Blocked) |
| `h1` | Normal Client Host 1 | `10.0.0.1/24` | `00:00:00:00:00:01` | `s2` — Port `1` | Rate-Limit Safeguard |
| `h2` | Normal Client Host 2 | `10.0.0.2/24` | `00:00:00:00:00:02` | `s2` — Port `2` | Rate-Limit Safeguard |
| `h3` | Normal Client Host 3 | `10.0.0.3/24` | `00:00:00:00:00:03` | `s3` — Port `1` | Rate-Limit Safeguard |
| `h4` | Normal Client Host 4 | `10.0.0.4/24` | `00:00:00:00:00:04` | `s3` — Port `2` | Rate-Limit Safeguard |
| `h5` | Isolated Traffic Generator A | `10.0.0.5/24` | `00:00:00:00:00:05` | `s2` — Port `3` | No (Immediate Drop) |
| `h6` | Isolated Traffic Generator B | `10.0.0.6/24` | `00:00:00:00:00:06` | `s3` — Port `3` | No (Immediate Drop) |
