"""Backend & Controller Runtime Configuration."""
import os
from dataclasses import dataclass, asdict


@dataclass
class Settings:
    app_name: str = "AI-Powered SDN Network Guardian API"
    version: str = "1.0.0"
    database_path: str = os.getenv(
        "DATABASE_PATH",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "database", "guardian_sdn.db"),
    )
    detection_mode: str = os.getenv("DETECTION_MODE", "hybrid")
    ml_model_type: str = os.getenv("ML_MODEL_TYPE", "random_forest")
    auto_mitigation_enabled: bool = os.getenv("AUTO_MITIGATION_ENABLED", "true").lower() == "true"
    rule_expiration_sec: int = int(os.getenv("MITIGATION_RULE_HARD_TIMEOUT_SEC", "60"))
    refresh_interval_ms: int = 2000
    max_packets_per_sec: float = float(os.getenv("THRESHOLD_PPS", "1200.0"))
    max_bytes_per_sec: float = float(os.getenv("THRESHOLD_BPS", "1500000.0"))
    max_source_flow_count: int = int(os.getenv("THRESHOLD_SOURCE_FLOW_COUNT", "35"))
    max_traffic_variation_cv: float = 1.15
    max_syn_flag_ratio: float = float(os.getenv("THRESHOLD_SYN_RATIO", "0.65"))

    def to_dict(self):
        return asdict(self)


settings = Settings()
