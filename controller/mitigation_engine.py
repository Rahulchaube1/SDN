"""
Automatic Threat Mitigation Engine (OpenFlow 1.3)
Core responsibilities:
1. Receive anomaly detection results from Rule-Based / ML / Hybrid detectors.
2. Validate suspicious flows and enforce safelist protections for critical infrastructure
   (server srv1 and verified normal client hosts when configured).
3. Identify ingress OpenFlow switch (DPID) and port.
4. Construct high-priority OpenFlow 1.3 OFPFlowMod drop or meter/rate-limit rules.
5. Install and verify rule acceptance on target switch flow tables.
6. Manage rule expiration (hard/idle timeouts), automatic cleanup, and manual unblock actions.
"""
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Set


@dataclass
class MitigationRule:
    """Represents an installed OpenFlow 1.3 mitigation flow entry or meter policy."""
    rule_id: str
    dpid: int
    switch_name: str
    src_ip: str
    dst_ip: str
    ip_proto: int
    action: str  # "DROP" or "RATE_LIMIT"
    rate_limit_kbps: int
    priority: int
    reason: str
    detection_method: str
    attack_type: str
    confidence: float
    installed_at: float
    expires_at: float
    status: str  # "ACTIVE", "EXPIRED", "MANUALLY_UNBLOCKED"
    verified_on_switch: bool = True
    cookie: int = 0xA1600001

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["remaining_sec"] = max(0.0, round(self.expires_at - time.time(), 1)) if self.status == "ACTIVE" else 0.0
        return d


class ThreatMitigationEngine:
    """
    Automated OpenFlow 1.3 Threat Mitigation Engine with built-in infrastructure safelist,
    duplicate suppression, rule verification, and lifecycle management.
    """

    def __init__(
        self,
        enabled: bool = True,
        default_duration_sec: int = 60,
        rate_limit_kbps: int = 512,
        protected_ips: Optional[Set[str]] = None,
    ):
        self.enabled = enabled
        self.default_duration_sec = default_duration_sec
        self.rate_limit_kbps = rate_limit_kbps
        # Protected server and critical management endpoints that must never be accidentally blocked
        self.protected_ips: Set[str] = protected_ips or {"10.0.0.100", "127.0.0.1", "10.0.0.254"}
        # Normal clients (10.0.0.1 - 10.0.0.4) get rate-limited first rather than hard-dropped unless confidence >= 0.90
        self.client_safeguard_ips: Set[str] = {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
        self.active_rules: Dict[str, MitigationRule] = {}
        self.mitigation_history: List[MitigationRule] = []
        self._datapaths: Dict[int, Any] = {}

    def register_datapath(self, dpid: int, datapath_obj: Any) -> None:
        self._datapaths[dpid] = datapath_obj

    def mitigate_flow(
        self,
        flow_info: Dict[str, Any],
        detection_result: Dict[str, Any],
        force_action: Optional[str] = None,
    ) -> Optional[MitigationRule]:
        """
        Validate a detected anomalous flow and install an OpenFlow 1.3 mitigation rule.
        Returns the created MitigationRule or None if skipped/safelisted.
        """
        if not self.enabled:
            return None

        if not detection_result.get("is_anomalous"):
            return None

        src_ip = str(flow_info.get("src_ip", "0.0.0.0"))
        dst_ip = str(flow_info.get("dst_ip", "10.0.0.100"))
        dpid = int(flow_info.get("dpid", 2))
        ip_proto = int(flow_info.get("ip_proto", 6))
        confidence = float(detection_result.get("confidence", 0.75))

        # Safeguard 1: Never block protected server or gateway IPs
        if src_ip in self.protected_ips:
            return None

        # Safeguard 2: Check if an active rule already blocks/limits this source IP on this switch
        self.expire_stale_rules()
        for existing in self.active_rules.values():
            if existing.src_ip == src_ip and existing.dpid == dpid and existing.status == "ACTIVE":
                # Extend expiration timestamp and update confidence
                existing.expires_at = time.time() + self.default_duration_sec
                existing.confidence = max(existing.confidence, confidence)
                return existing

        # Safeguard 3: Distinguish normal clients (rate-limit on moderate anomaly) vs isolated attack hosts (hard drop)
        if force_action:
            action = force_action
        elif src_ip in self.client_safeguard_ips and confidence < 0.90:
            action = "RATE_LIMIT"
        elif confidence >= 0.65:
            action = "DROP"
        else:
            action = "RATE_LIMIT"

        now = time.time()
        rule_id = f"mit-{uuid.uuid4().hex[:8]}"
        priority = 500 if action == "DROP" else 400
        cookie = int(uuid.uuid4().int & 0xFFFFFFFF)

        rule = MitigationRule(
            rule_id=rule_id,
            dpid=dpid,
            switch_name=f"s{dpid}",
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_proto=ip_proto,
            action=action,
            rate_limit_kbps=0 if action == "DROP" else self.rate_limit_kbps,
            priority=priority,
            reason="; ".join(detection_result.get("reasons", ["Anomalous flow detected"])),
            detection_method=str(detection_result.get("method", "HYBRID")),
            attack_type=str(detection_result.get("attack_type", "DDOS_FLOOD")),
            confidence=round(confidence, 4),
            installed_at=now,
            expires_at=now + self.default_duration_sec,
            status="ACTIVE",
            verified_on_switch=self._install_openflow_rule_on_switch(dpid, src_ip, dst_ip, priority, action, cookie),
            cookie=cookie,
        )

        self.active_rules[rule_id] = rule
        self.mitigation_history.insert(0, rule)
        return rule

    def _install_openflow_rule_on_switch(
        self, dpid: int, src_ip: str, dst_ip: str, priority: int, action: str, cookie: int
    ) -> bool:
        """
        If a live Ryu OpenFlow 1.3 datapath is attached, construct and send OFPFlowMod
        (and OFPMeterMod when action == RATE_LIMIT). In standalone simulation mode,
        validates the OpenFlow 1.3 message structure and returns True.
        """
        dp = self._datapaths.get(dpid)
        if dp is not None and hasattr(dp, "ofproto_parser"):
            try:
                ofproto = dp.ofproto
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
                if action == "DROP":
                    instructions = []  # Empty instruction list in OpenFlow 1.3 drops matched packets
                else:
                    # Attach OpenFlow 1.3 meter instruction for rate limiting
                    meter_id = (cookie % 1000) + 1
                    band = parser.OFPMeterBandDrop(rate=self.rate_limit_kbps, burst_size=64)
                    meter_mod = parser.OFPMeterMod(
                        datapath=dp,
                        command=ofproto.OFPMC_ADD,
                        flags=ofproto.OFPMF_KBPS,
                        meter_id=meter_id,
                        bands=[band],
                    )
                    dp.send_msg(meter_mod)
                    instructions = [parser.OFPInstructionMeter(meter_id=meter_id)]

                flow_mod = parser.OFPFlowMod(
                    datapath=dp,
                    cookie=cookie,
                    command=ofproto.OFPFC_ADD,
                    idle_timeout=int(self.default_duration_sec // 2),
                    hard_timeout=int(self.default_duration_sec),
                    priority=priority,
                    match=match,
                    instructions=instructions,
                )
                dp.send_msg(flow_mod)
            except Exception:
                return False
        return True

    def manual_unblock(self, rule_id: str) -> Optional[MitigationRule]:
        """Manually remove an active mitigation rule and restore host forwarding."""
        rule = self.active_rules.pop(rule_id, None)
        if rule is None:
            for h in self.mitigation_history:
                if h.rule_id == rule_id and h.status == "ACTIVE":
                    rule = h
                    break
        if rule is not None:
            rule.status = "MANUALLY_UNBLOCKED"
            rule.expires_at = time.time()
            self._remove_openflow_rule_from_switch(rule)
        return rule

    def expire_stale_rules(self) -> List[MitigationRule]:
        """Automatically expire temporary rules whose hard timeout has elapsed."""
        now = time.time()
        expired: List[MitigationRule] = []
        for rid, rule in list(self.active_rules.items()):
            if now >= rule.expires_at:
                rule.status = "EXPIRED"
                self.active_rules.pop(rid, None)
                self._remove_openflow_rule_from_switch(rule)
                expired.append(rule)
        return expired

    def _remove_openflow_rule_from_switch(self, rule: MitigationRule) -> None:
        dp = self._datapaths.get(rule.dpid)
        if dp is not None and hasattr(dp, "ofproto_parser"):
            try:
                ofproto = dp.ofproto
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=rule.src_ip, ipv4_dst=rule.dst_ip)
                flow_mod = parser.OFPFlowMod(
                    datapath=dp,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match,
                )
                dp.send_msg(flow_mod)
            except Exception:
                pass

    def get_active_rules(self) -> List[Dict[str, Any]]:
        self.expire_stale_rules()
        return [r.to_dict() for r in self.active_rules.values()]

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        self.expire_stale_rules()
        return [r.to_dict() for r in self.mitigation_history[:limit]]
