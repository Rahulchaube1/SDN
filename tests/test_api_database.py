"""
Automated Tests for SQLite Database Operations, Configuration Validation, and FastAPI Endpoints.
"""
import os
import tempfile
import unittest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database.db import GuardianDatabase


class TestAPIAndDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp_db.close()
        self.db = GuardianDatabase(self.tmp_db.name)
        self.client = TestClient(app)

    def tearDown(self):
        if os.path.exists(self.tmp_db.name):
            os.unlink(self.tmp_db.name)

    def test_database_alert_and_mitigation_persistence(self):
        self.db.insert_alert({
            "alert_id": "alt-test-1",
            "timestamp": 1700000000.0,
            "dpid": 2,
            "switch_name": "s2",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.100",
            "src_port": 40100,
            "dst_port": 80,
            "ip_proto": 6,
            "packets_per_sec": 2900.0,
            "bytes_per_sec": 214600.0,
            "detection_method": "HYBRID",
            "attack_type": "TCP_SYN_FLOOD",
            "severity": "CRITICAL",
            "confidence": 0.94,
            "reasons": ["High PPS", "High SYN ratio"],
        })
        alerts = self.db.get_alerts(limit=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["src_ip"], "10.0.0.5")

    def test_fastapi_endpoints_and_scenario_workflow(self):
        r_health = self.client.get("/api/v1/health")
        self.assertEqual(r_health.status_code, 200)
        self.assertEqual(r_health.json()["status"], "healthy")

        # Trigger Scenario C (Automatic Mitigation)
        r_scen = self.client.post("/api/v1/scenarios/trigger", json={"scenario": "C"})
        self.assertEqual(r_scen.status_code, 200)
        state = r_scen.json()["state"]
        self.assertGreaterEqual(state["overview"]["active_mitigations"], 1)

        # Update Settings
        r_set = self.client.put("/api/v1/settings", json={
            "detection_mode": "hybrid",
            "ml_model_type": "random_forest",
            "max_packets_per_sec": 1350.0,
        })
        self.assertEqual(r_set.status_code, 200)
        self.assertEqual(r_set.json()["settings"]["max_packets_per_sec"], 1350.0)


if __name__ == "__main__":
    unittest.main()
