"""
Automated Tests for Feature Extraction, Rule-Based Detection, and ML Model Inference.
"""
import unittest
from detection.feature_extractor import FlowFeatureExtractor
from detection.rule_detector import RuleBasedDetector, RuleConfig
from detection.ml_detector import MLAnomalyDetector
from detection.train_model import train_and_save_models


class TestDetectionLayer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        train_and_save_models(n_samples=1200, seed=2026)
        cls.extractor = FlowFeatureExtractor(history_window=6)
        cls.rule_detector = RuleBasedDetector(RuleConfig())
        cls.ml_detector = MLAnomalyDetector(active_model="random_forest")

    def test_feature_extraction_dimensions_and_rates(self):
        raw_flows = [
            {
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.100",
                "src_port": 51001,
                "dst_port": 80,
                "ip_proto": 6,
                "packet_count": 300,
                "byte_count": 240000,
                "duration_sec": 2.0,
            }
        ]
        vectors = self.extractor.extract_from_switch_flows(dpid=2, raw_flows=raw_flows)
        self.assertEqual(len(vectors), 1)
        fv = vectors[0]
        self.assertEqual(fv.to_numpy().shape, (7,))
        self.assertAlmostEqual(fv.packets_per_sec, 150.0, places=1)
        self.assertAlmostEqual(fv.bytes_per_sec, 120000.0, places=1)

    def test_rule_based_detector_distinguishes_normal_and_syn_flood(self):
        normal_fv = self.extractor.extract_from_switch_flows(2, [{
            "src_ip": "10.0.0.2", "dst_ip": "10.0.0.100", "src_port": 52000, "dst_port": 443,
            "ip_proto": 6, "packet_count": 200, "byte_count": 160000, "duration_sec": 2.0,
            "packets_per_sec": 100.0, "bytes_per_sec": 80000.0, "source_flow_count": 4,
            "traffic_variation_cv": 0.22, "syn_flag_ratio": 0.04,
        }])[0]
        res_norm = self.rule_detector.evaluate(normal_fv)
        self.assertFalse(res_norm["is_anomalous"])
        self.assertEqual(res_norm["attack_type"], "NORMAL")

        flood_fv = self.extractor.extract_from_switch_flows(2, [{
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.100", "src_port": 44001, "dst_port": 80,
            "ip_proto": 6, "packet_count": 6000, "byte_count": 444000, "duration_sec": 2.0,
            "packets_per_sec": 3000.0, "bytes_per_sec": 222000.0, "source_flow_count": 72,
            "traffic_variation_cv": 1.65, "syn_flag_ratio": 0.95,
        }])[0]
        res_flood = self.rule_detector.evaluate(flood_fv)
        self.assertTrue(res_flood["is_anomalous"])
        self.assertIn(res_flood["severity"], ("HIGH", "CRITICAL"))
        self.assertEqual(res_flood["attack_type"], "TCP_SYN_FLOOD")

    def test_ml_random_forest_and_isolation_forest_inference(self):
        normal_fv = self.extractor.extract_from_switch_flows(3, [{
            "src_ip": "10.0.0.3", "dst_ip": "10.0.0.100", "src_port": 53000, "dst_port": 80,
            "ip_proto": 6, "packet_count": 240, "byte_count": 192000, "duration_sec": 2.0,
            "packets_per_sec": 120.0, "bytes_per_sec": 96000.0, "source_flow_count": 3,
            "traffic_variation_cv": 0.20, "syn_flag_ratio": 0.05,
        }])[0]
        rf_norm = self.ml_detector.evaluate(normal_fv, model_type="random_forest")
        self.assertFalse(rf_norm["is_anomalous"])

        attack_fv = self.extractor.extract_from_switch_flows(3, [{
            "src_ip": "10.0.0.6", "dst_ip": "10.0.0.100", "src_port": 45001, "dst_port": 53,
            "ip_proto": 17, "packet_count": 7000, "byte_count": 6860000, "duration_sec": 2.0,
            "packets_per_sec": 3500.0, "bytes_per_sec": 3430000.0, "source_flow_count": 58,
            "traffic_variation_cv": 1.55, "syn_flag_ratio": 0.0,
        }])[0]
        rf_atk = self.ml_detector.evaluate(attack_fv, model_type="random_forest")
        if_atk = self.ml_detector.evaluate(attack_fv, model_type="isolation_forest")
        self.assertTrue(rf_atk["is_anomalous"])
        self.assertTrue(if_atk["is_anomalous"])


if __name__ == "__main__":
    unittest.main()
