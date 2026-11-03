"""
Mininet OpenFlow 1.3 Topology Builder (`topology.py`)
Constructs the isolated virtual SDN testbed:
- 1 Remote OpenFlow 1.3 Controller (`c0` on 127.0.0.1:6653)
- 3 Open vSwitch switches (`s1` Core, `s2` Edge West, `s3` Edge East) configured with `protocols=OpenFlow13`
- 1 Protected Application Server (`srv1` at 10.0.0.100/24 on `s1`)
- 4 Normal Client Hosts (`h1` 10.0.0.1, `h2` 10.0.0.2 on `s2`; `h3` 10.0.0.3, `h4` 10.0.0.4 on `s3`)
- 2 Isolated Traffic-Generation Hosts (`h5` 10.0.0.5 on `s2`, `h6` 10.0.0.6 on `s3`)

Safety Notice:
Operates strictly within isolated Linux network namespaces inside Mininet, or in
userspace emulation mode when invoked on machines without root/OVS kernel modules.
"""
import argparse
import json
from typing import Dict, Any

try:
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSKernelSwitch
    from mininet.link import TCLink
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info
    MININET_AVAILABLE = True
    BaseTopoClass = Topo
except ImportError:
    MININET_AVAILABLE = False
    BaseTopoClass = object


class GuardianSDNTopo(BaseTopoClass):
    """Custom 3-Switch, 7-Host Mininet Topology for SDN Security Evaluation."""

    def __init__(self, bw_trunk_mbps: int = 100, bw_access_mbps: int = 50, delay_ms: str = "2ms", **opts):
        self.bw_trunk_mbps = bw_trunk_mbps
        self.bw_access_mbps = bw_access_mbps
        self.delay_ms = delay_ms
        if MININET_AVAILABLE:
            super().__init__(**opts)
        else:
            self.nodes_spec = {}
            self.links_spec = []
            self.build()

    def build(self):
        if MININET_AVAILABLE:
            s1 = self.addSwitch("s1", cls=OVSKernelSwitch, protocols="OpenFlow13", dpid="0000000000000001")
            s2 = self.addSwitch("s2", cls=OVSKernelSwitch, protocols="OpenFlow13", dpid="0000000000000002")
            s3 = self.addSwitch("s3", cls=OVSKernelSwitch, protocols="OpenFlow13", dpid="0000000000000003")

            srv1 = self.addHost("srv1", ip="10.0.0.100/24", mac="00:00:00:00:01:00")
            h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
            h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
            h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
            h4 = self.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")
            h5 = self.addHost("h5", ip="10.0.0.5/24", mac="00:00:00:00:00:05")
            h6 = self.addHost("h6", ip="10.0.0.6/24", mac="00:00:00:00:00:06")

            # Inter-switch trunk links
            self.addLink(s1, s2, bw=self.bw_trunk_mbps, delay=self.delay_ms)
            self.addLink(s1, s3, bw=self.bw_trunk_mbps, delay=self.delay_ms)

            # Server link
            self.addLink(srv1, s1, bw=self.bw_trunk_mbps, delay="1ms")

            # Edge Switch s2 hosts (2 normal clients + 1 isolated traffic generator)
            self.addLink(h1, s2, bw=self.bw_access_mbps, delay=self.delay_ms)
            self.addLink(h2, s2, bw=self.bw_access_mbps, delay=self.delay_ms)
            self.addLink(h5, s2, bw=self.bw_access_mbps, delay=self.delay_ms)

            # Edge Switch s3 hosts (2 normal clients + 1 isolated traffic generator)
            self.addLink(h3, s3, bw=self.bw_access_mbps, delay=self.delay_ms)
            self.addLink(h4, s3, bw=self.bw_access_mbps, delay=self.delay_ms)
            self.addLink(h6, s3, bw=self.bw_access_mbps, delay=self.delay_ms)
        else:
            self.nodes_spec = {
                "controller": {"name": "c0", "ip": "127.0.0.1", "port": 6653, "protocol": "OpenFlow13"},
                "switches": ["s1", "s2", "s3"],
                "server": {"name": "srv1", "ip": "10.0.0.100/24", "switch": "s1"},
                "normal_clients": [
                    {"name": "h1", "ip": "10.0.0.1/24", "switch": "s2"},
                    {"name": "h2", "ip": "10.0.0.2/24", "switch": "s2"},
                    {"name": "h3", "ip": "10.0.0.3/24", "switch": "s3"},
                    {"name": "h4", "ip": "10.0.0.4/24", "switch": "s3"},
                ],
                "isolated_sim_hosts": [
                    {"name": "h5", "ip": "10.0.0.5/24", "switch": "s2"},
                    {"name": "h6", "ip": "10.0.0.6/24", "switch": "s3"},
                ],
            }

    def export_topology_dict(self) -> Dict[str, Any]:
        return getattr(self, "nodes_spec", {
            "controller": "c0 (127.0.0.1:6653)",
            "switches": ["s1", "s2", "s3"],
            "hosts": ["srv1", "h1", "h2", "h3", "h4", "h5", "h6"],
        })


def start_mininet_network(controller_ip: str = "127.0.0.1", controller_port: int = 6653, run_cli: bool = True):
    topo = GuardianSDNTopo()
    if not MININET_AVAILABLE:
        print("[GuardianSDNTopo] Mininet kernel daemon not active in this container; running virtual topology verification:")
        print(json.dumps(topo.export_topology_dict(), indent=2))
        return topo.export_topology_dict()

    setLogLevel("info")
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip=controller_ip, port=controller_port),
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True,
    )
    net.start()
    info("*** Testing baseline host connectivity (pingAll)\n")
    net.pingAll()
    if run_cli:
        CLI(net)
    net.stop()
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start AI-Powered SDN Network Guardian Mininet Topology")
    parser.add_argument("--controller-ip", default="127.0.0.1")
    parser.add_argument("--controller-port", type=int, default=6653)
    parser.add_argument("--no-cli", action="store_true")
    args = parser.parse_args()
    start_mininet_network(args.controller_ip, args.controller_port, run_cli=not args.no_cli)
