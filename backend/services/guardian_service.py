"""
Guardian Orchestration Service (`guardian_service.py`)
Bridges the OpenFlow 1.3 SDN Controller, SQLite Database, ML Evaluation Results,
and Scenario Simulator for the FastAPI REST and WebSocket endpoints.
"""
import os
import json
from typing import Dict, Any, Optional

from backend.config import settings
from backend.database.db import GuardianDatabase
from controller.sdn_controller import GuardianSDNController
from network.normal_traffic import generate_normal_flow_batch
from network.abnormal_traffic import generate_abnormal_flow_batch


class GuardianService:
    """Singleton-style backend orchestration service."""

    def __init__(self, db_path: Optional[str] = None):
        self.db = GuardianDatabase(db_path or settings.database_path)
        self.controller = GuardianSDNController()
        self.step_counter = 0
        self._seed_initial_telemetry()

    def _seed_initial_telemetry(self) -> None:
        """Run 3 normal baseline cycles and 1 mitigated attack cycle so dashboard & DB start populated."""
        for s in range(1, 4):
            self.step_counter += 1
            flows = generate_normal_flow_batch(step=self.step_counter)
            res2 = self.controller.ingest_simulated_flows(2, [f for f in flows if f["dpid"] == 2])
            res3 = self.controller.ingest_simulated_flows(3, [f for f in flows if f["dpid"] == 3])
            self.db.insert_traffic_metric(res2["summary"])
            self.db.insert_traffic_metric(res3["summary"])
        # Run 1 initial mitigated attack cycle so alerts, mitigations, and telemetry are populated on load
        self.trigger_scenario("C")

    def trigger_scenario(self, scenario_code: str) -> Dict[str, Any]:
        code = scenario_code.strip().upper()
        self.step_counter += 1
        normal = generate_normal_flow_batch(step=self.step_counter)

        if code in ("A", "SCENARIO_A", "NORMAL"):
            self.controller.scenario_state = "SCENARIO_A_NORMAL"
            self.controller.mitigation.enabled = True
            for rid in list(self.controller.mitigation.active_rules.keys()):
                rule = self.controller.mitigation.manual_unblock(rid)
                if rule:
                    self.db.upsert_mitigation(rule.to_dict())
            self.controller.topology.update_host_status("10.0.0.5", "ONLINE")
            self.controller.topology.update_host_status("10.0.0.6", "ONLINE")
            combined = normal
        elif code in ("B", "SCENARIO_B", "DETECTION"):
            self.controller.scenario_state = "SCENARIO_B_ABNORMAL_DETECTION"
            self.controller.mitigation.enabled = False
            for rid in list(self.controller.mitigation.active_rules.keys()):
                rule = self.controller.mitigation.manual_unblock(rid)
                if rule:
                    self.db.upsert_mitigation(rule.to_dict())
            self.controller.topology.update_host_status("10.0.0.5", "ONLINE")
            self.controller.topology.update_host_status("10.0.0.6", "ONLINE")
            combined = normal + generate_abnormal_flow_batch("multi_vector", step=self.step_counter)
        elif code in ("C", "SCENARIO_C", "MITIGATION"):
            self.controller.scenario_state = "SCENARIO_C_AUTO_MITIGATION"
            self.controller.mitigation.enabled = True
            combined = normal + generate_abnormal_flow_batch("multi_vector", step=self.step_counter)
        elif code in ("D", "SCENARIO_D", "RECOVERY"):
            self.controller.scenario_state = "SCENARIO_D_RECOVERY"
            self.controller.mitigation.enabled = True
            for rid in list(self.controller.mitigation.active_rules.keys()):
                rule = self.controller.mitigation.manual_unblock(rid)
                if rule:
                    self.db.upsert_mitigation(rule.to_dict())
            self.controller.topology.update_host_status("10.0.0.5", "ONLINE")
            self.controller.topology.update_host_status("10.0.0.6", "ONLINE")
            combined = normal
        else:
            raise ValueError(f"Unsupported scenario code: {scenario_code}")

        for dpid in (2, 3):
            res = self.controller.ingest_simulated_flows(dpid, [f for f in combined if f["dpid"] == dpid])
            self.db.insert_traffic_metric(res["summary"])
            for alt in res["new_alerts"]:
                self.db.insert_alert(alt)
            for mit in res["new_mitigations"]:
                self.db.upsert_mitigation(mit)

        return self.get_full_state()

    def manual_unblock(self, rule_id: str) -> Optional[Dict[str, Any]]:
        rule = self.controller.mitigation.manual_unblock(rule_id)
        if rule is not None:
            self.controller.topology.update_host_status(rule.src_ip, "ONLINE")
            d = rule.to_dict()
            self.db.upsert_mitigation(d)
            return d
        return None

    def update_settings(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in updates.items():
            if v is None:
                continue
            if hasattr(settings, k):
                setattr(settings, k, v)
            self.db.save_setting(k, v)

        if "detection_mode" in updates and updates["detection_mode"]:
            self.controller.flow_monitor.detection_mode = updates["detection_mode"]
        if "ml_model_type" in updates and updates["ml_model_type"]:
            self.controller.flow_monitor.ml_model_type = updates["ml_model_type"]
            self.controller.flow_monitor.ml_detector.active_model = updates["ml_model_type"]
        if "auto_mitigation_enabled" in updates and updates["auto_mitigation_enabled"] is not None:
            self.controller.mitigation.enabled = bool(updates["auto_mitigation_enabled"])
        if "rule_expiration_sec" in updates and updates["rule_expiration_sec"] is not None:
            self.controller.mitigation.default_duration_sec = int(updates["rule_expiration_sec"])

        rule_keys = {
            "max_packets_per_sec",
            "max_bytes_per_sec",
            "max_source_flow_count",
            "max_traffic_variation_cv",
            "max_syn_flag_ratio",
        }
        rule_updates = {k: v for k, v in updates.items() if k in rule_keys and v is not None}
        if rule_updates:
            self.controller.flow_monitor.rule_detector.update_config(**rule_updates)

        return self.get_settings()

    def get_settings(self) -> Dict[str, Any]:
        return {
            **settings.to_dict(),
            "rule_thresholds": self.controller.flow_monitor.rule_detector.config.to_dict(),
        }

    def get_analytics_metrics(self) -> Dict[str, Any]:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        exp_path = os.path.join(base_dir, "experiments", "results", "complete_experiment_results.json")
        ts_path = os.path.join(base_dir, "experiments", "results", "network_benchmark_summary.json")
        if os.path.exists(exp_path):
            with open(exp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if os.path.exists(ts_path):
                try:
                    with open(ts_path, "r", encoding="utf-8") as tf:
                        ts_data = json.load(tf)
                        data["benchmark_timeseries"] = ts_data.get("timeseries", [])
                except Exception:
                    pass
            return data
        return {"status": "Experiment results not yet generated"}

    def get_full_state(self) -> Dict[str, Any]:
        snap = self.controller.get_dashboard_snapshot()
        snap["settings"] = self.get_settings()
        snap["analytics"] = self.get_analytics_metrics()
        return snap
