# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Isolated Testbed Safety Policy

All abnormal traffic generation and DDoS simulation modules (`network/abnormal_traffic.py` and `network/scenarios/*`) are strictly confined to isolated simulation hosts (`10.0.0.5` and `10.0.0.6`) targeting the local virtual testbed server (`10.0.0.100`) inside RFC 1918 private network namespaces. Contributions must never target external or public IP addresses.

## Reporting a Vulnerability

If you discover a security issue in the FastAPI backend, OpenFlow controller, or React frontend:
1. Open a security advisory on GitHub or report the issue with reproduction steps.
2. Include the affected component (`backend/`, `controller/`, `detection/`, `frontend/`) and proposed fix.
