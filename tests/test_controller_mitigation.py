"""
Automated Tests for SDN Controller, Topology Manager, OpenFlow Mitigation Rule Generation,
Safelist Protection, and Rule Expiration.
"""
import time
import unittest
from controller.sdn_controller import GuardianSDNController


class TestControllerAndMitigation(unittest.TestCase):
    def setUp(self):
        self.ctrl = GuardianSDNController()

    def test_topology_contains_required_switches_and_hosts(self):
        snap = self.ctrl.topology.get_topology_snapshot()
        self.assertEqual(len(snap["switches"]), 3)
        self.assertEqual(len(snap["hosts"]), 7)
        roles = [h["role"] for h in snap["hosts"]]
        self.assertEqual(roles.count("SERVER"), 1)
        self.assertEqual(roles.count("NORMAL_CLIENT"), 4)
        self.assertEqual(roles.count("TRAFFIC_GEN_ISOLATED"), 2)

    def test_safelist_prevents_blocking_server(self):
        rule = self.ctrl.mitigation.mitigate_flow(
            {"src_ip": "10.0.0.100", "dst_ip": "10.0.0.1", "dpid": 1, "ip_proto": 6},
            {"is_anomalous": True, "confidence": 0.99, "reasons": ["Synthetic test"]},
        )
        self.assertIsNone(rule, "Protected server IP 10.0.0.100 must never be blocked")

    def test_mitigation_rule_generation_manual_unblock_and_expiration(self):
        rule = self.ctrl.mitigation.mitigate_flow(
            {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.100", "dpid": 2, "ip_proto": 6},
            {"is_anomalous": True, "confidence": 0.92, "method": "HYBRID", "attack_type": "TCP_SYN_FLOOD", "reasons": ["High PPS"]},
        )
        self.assertIsNotNone(rule)
        self.assertEqual(rule.action, "DROP")
        self.assertTrue(rule.verified_on_switch)
        self.assertEqual(len(self.ctrl.mitigation.get_active_rules()), 1)

        # Manual unblock
        unblocked = self.ctrl.mitigation.manual_unblock(rule.rule_id)
        self.assertIsNotNone(unblocked)
        self.assertEqual(unblocked.status, "MANUALLY_UNBLOCKED")
        self.assertEqual(len(self.ctrl.mitigation.get_active_rules()), 0)

        # Automatic timeout expiration
        self.ctrl.mitigation.default_duration_sec = 0.05
        rule2 = self.ctrl.mitigation.mitigate_flow(
            {"src_ip": "10.0.0.6", "dst_ip": "10.0.0.100", "dpid": 3, "ip_proto": 17},
            {"is_anomalous": True, "confidence": 0.88, "method": "HYBRID", "attack_type": "UDP_VOLUMETRIC_FLOOD", "reasons": ["High BPS"]},
        )
        self.assertIsNotNone(rule2)
        time.sleep(0.08)
        expired = self.ctrl.mitigation.expire_stale_rules()
        self.assertEqual(len(expired), 1)
        self.assertEqual(len(self.ctrl.mitigation.get_active_rules()), 0)


if __name__ == "__main__":
    unittest.main()
