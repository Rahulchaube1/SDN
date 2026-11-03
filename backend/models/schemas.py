"""Pydantic Request & Response Schemas for the FastAPI Backend."""
from typing import Optional
from pydantic import BaseModel, Field


class SettingsUpdateRequest(BaseModel):
    detection_mode: Optional[str] = Field(None, description="rule, ml, or hybrid")
    ml_model_type: Optional[str] = Field(None, description="random_forest or isolation_forest")
    auto_mitigation_enabled: Optional[bool] = None
    rule_expiration_sec: Optional[int] = Field(None, ge=5, le=3600)
    refresh_interval_ms: Optional[int] = Field(None, ge=500, le=30000)
    max_packets_per_sec: Optional[float] = Field(None, ge=100.0)
    max_bytes_per_sec: Optional[float] = Field(None, ge=50000.0)
    max_source_flow_count: Optional[int] = Field(None, ge=5)
    max_traffic_variation_cv: Optional[float] = Field(None, ge=0.2)
    max_syn_flag_ratio: Optional[float] = Field(None, ge=0.1, le=1.0)


class ScenarioTriggerRequest(BaseModel):
    scenario: str = Field(..., description="A (Normal), B (Detection), C (Mitigation), or D (Recovery)")


class ManualUnblockRequest(BaseModel):
    rule_id: str = Field(..., description="ID of the OpenFlow mitigation rule to remove")
