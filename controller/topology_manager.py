"""
SDN Topology Manager
Maintains real-time graph state of OpenFlow switches (s1, s2, s3), hosts (h1-h4, h5-h6, srv1),
inter-switch links, and port-to-MAC mappings.
"""
import time
from typing import Dict, Any, List, Optional


class TopologyManager:
    """Tracks switches, hosts, MAC-to-port bindings, and link health in the SDN fabric."""

    def __init__(self):
        self.switches: Dict[int, Dict[str, Any]] = {}
        self.hosts: Dict[str, Dict[str, Any]] = {}
        self.links: List[Dict[str, Any]] = []
        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        self.initialize_default_topology()

    def initialize_default_topology(self) -> None:
        """
        Initialize the standard 3-switch, 7-host Mininet topology required by the specification:
        - 1 SDN Controller (c0, OpenFlow 1.3, port 6653)
        - 3 Virtual OpenFlow Switches (s1 Core/Server Switch, s2 Access Switch A, s3 Access Switch B)
        - 1 Application Server (srv1: 10.0.0.100 on s1)
        - 4 Normal Client Hosts (h1: 10.0.0.1, h2: 10.0.0.2 on s2; h3: 10.0.0.3, h4: 10.0.0.4 on s3)
        - 2 Isolated Traffic-Generation Simulation Hosts (h5: 10.0.0.5 on s2, h6: 10.0.0.6 on s3)
        """
        now = time.time()
        self.switches = {
            1: {
                "dpid": 1,
                "name": "s1",
                "role": "CORE_SWITCH",
                "openflow_version": "OF_1.3",
                "status": "ACTIVE",
                "ports": 4,
                "active_flows": 8,
                "connected_since": now,
            },
            2: {
                "dpid": 2,
                "name": "s2",
                "role": "EDGE_SWITCH_WEST",
                "openflow_version": "OF_1.3",
                "status": "ACTIVE",
                "ports": 4,
                "active_flows": 10,
                "connected_since": now,
            },
            3: {
                "dpid": 3,
                "name": "s3",
                "role": "EDGE_SWITCH_EAST",
                "openflow_version": "OF_1.3",
                "status": "ACTIVE",
                "ports": 4,
                "active_flows": 10,
                "connected_since": now,
            },
        }

        self.hosts = {
            "10.0.0.100": {
                "name": "srv1",
                "ip": "10.0.0.100",
                "mac": "00:00:00:00:01:00",
                "role": "SERVER",
                "switch_dpid": 1,
                "port": 1,
                "status": "ONLINE",
                "protected": True,
            },
            "10.0.0.1": {
                "name": "h1",
                "ip": "10.0.0.1",
                "mac": "00:00:00:00:00:01",
                "role": "NORMAL_CLIENT",
                "switch_dpid": 2,
                "port": 1,
                "status": "ONLINE",
                "protected": True,
            },
            "10.0.0.2": {
                "name": "h2",
                "ip": "10.0.0.2",
                "mac": "00:00:00:00:00:02",
                "role": "NORMAL_CLIENT",
                "switch_dpid": 2,
                "port": 2,
                "status": "ONLINE",
                "protected": True,
            },
            "10.0.0.3": {
                "name": "h3",
                "ip": "10.0.0.3",
                "mac": "00:00:00:00:00:03",
                "role": "NORMAL_CLIENT",
                "switch_dpid": 3,
                "port": 1,
                "status": "ONLINE",
                "protected": True,
            },
            "10.0.0.4": {
                "name": "h4",
                "ip": "10.0.0.4",
                "mac": "00:00:00:00:00:04",
                "role": "NORMAL_CLIENT",
                "switch_dpid": 3,
                "port": 2,
                "status": "ONLINE",
                "protected": True,
            },
            "10.0.0.5": {
                "name": "h5",
                "ip": "10.0.0.5",
                "mac": "00:00:00:00:00:05",
                "role": "TRAFFIC_GEN_ISOLATED",
                "switch_dpid": 2,
                "port": 3,
                "status": "ONLINE",
                "protected": False,
            },
            "10.0.0.6": {
                "name": "h6",
                "ip": "10.0.0.6",
                "mac": "00:00:00:00:00:06",
                "role": "TRAFFIC_GEN_ISOLATED",
                "switch_dpid": 3,
                "port": 3,
                "status": "ONLINE",
                "protected": False,
            },
        }

        self.links = [
            {"id": "c0-s1", "source": "c0", "target": "s1", "type": "OPENFLOW_CONTROL", "status": "UP", "bandwidth_mbps": 1000, "utilization_pct": 4.2},
            {"id": "c0-s2", "source": "c0", "target": "s2", "type": "OPENFLOW_CONTROL", "status": "UP", "bandwidth_mbps": 1000, "utilization_pct": 5.1},
            {"id": "c0-s3", "source": "c0", "target": "s3", "type": "OPENFLOW_CONTROL", "status": "UP", "bandwidth_mbps": 1000, "utilization_pct": 4.8},
            {"id": "s1-s2", "source": "s1", "target": "s2", "src_port": 2, "dst_port": 4, "type": "TRUNK_LINK", "status": "UP", "bandwidth_mbps": 100, "utilization_pct": 18.5},
            {"id": "s1-s3", "source": "s1", "target": "s3", "src_port": 3, "dst_port": 4, "type": "TRUNK_LINK", "status": "UP", "bandwidth_mbps": 100, "utilization_pct": 16.2},
            {"id": "s2-s3", "source": "s2", "target": "s3", "src_port": 5, "dst_port": 5, "type": "REDUNDANT_LINK", "status": "STANDBY", "bandwidth_mbps": 100, "utilization_pct": 1.0},
            {"id": "srv1-s1", "source": "srv1", "target": "s1", "port": 1, "type": "ACCESS_LINK", "status": "UP", "bandwidth_mbps": 100, "utilization_pct": 28.4},
            {"id": "h1-s2", "source": "h1", "target": "s2", "port": 1, "type": "ACCESS_LINK", "status": "UP", "bandwidth_mbps": 50, "utilization_pct": 12.0},
            {"id": "h2-s2", "source": "h2", "target": "s2", "port": 2, "type": "ACCESS_LINK", "status": "UP", "bandwidth_mbps": 50, "utilization_pct": 10.5},
            {"id": "h5-s2", "source": "h5", "target": "s2", "port": 3, "type": "ISOLATED_SIM_LINK", "status": "UP", "bandwidth_mbps": 50, "utilization_pct": 2.4},
            {"id": "h3-s3", "source": "h3", "target": "s3", "port": 1, "type": "ACCESS_LINK", "status": "UP", "bandwidth_mbps": 50, "utilization_pct": 11.2},
            {"id": "h4-s3", "source": "h4", "target": "s3", "port": 2, "type": "ACCESS_LINK", "status": "UP", "bandwidth_mbps": 50, "utilization_pct": 9.8},
            {"id": "h6-s3", "source": "h6", "target": "s3", "port": 3, "type": "ISOLATED_SIM_LINK", "status": "UP", "bandwidth_mbps": 50, "utilization_pct": 2.1},
        ]

    def register_switch(self, dpid: int, ports: int = 4) -> None:
        self.switches[dpid] = {
            "dpid": dpid,
            "name": f"s{dpid}",
            "role": "CORE_SWITCH" if dpid == 1 else f"EDGE_SWITCH_{dpid}",
            "openflow_version": "OF_1.3",
            "status": "ACTIVE",
            "ports": ports,
            "active_flows": 0,
            "connected_since": time.time(),
        }

    def learn_mac(self, dpid: int, mac: str, port: int) -> None:
        self.mac_to_port.setdefault(dpid, {})[mac] = port

    def lookup_port(self, dpid: int, mac: str) -> Optional[int]:
        return self.mac_to_port.get(dpid, {}).get(mac)

    def get_host_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        return self.hosts.get(ip)

    def update_host_status(self, ip: str, status: str) -> None:
        if ip in self.hosts:
            self.hosts[ip]["status"] = status

    def get_topology_snapshot(self) -> Dict[str, Any]:
        return {
            "controller": {
                "id": "c0",
                "name": "Ryu OpenFlow 1.3 Guardian Controller",
                "protocol": "OpenFlow 1.3 (TCP 6653)",
                "status": "ACTIVE",
            },
            "switches": list(self.switches.values()),
            "hosts": list(self.hosts.values()),
            "links": self.links,
        }
