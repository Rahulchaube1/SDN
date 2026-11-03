"""FastAPI REST & WebSocket Endpoints for the AI-Powered SDN Network Guardian Dashboard."""
import asyncio
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from backend.models.schemas import SettingsUpdateRequest, ScenarioTriggerRequest, ManualUnblockRequest
from backend.services.guardian_service import GuardianService

router = APIRouter()
guardian_service = GuardianService()


@router.get("/health")
def health_check():
    return {"status": "healthy", "service": "AI-Powered SDN Network Guardian API", "openflow_version": "1.3"}


@router.get("/dashboard/state")
def get_dashboard_state():
    return guardian_service.get_full_state()


@router.get("/topology")
def get_topology():
    return guardian_service.controller.topology.get_topology_snapshot()


@router.get("/flows")
def get_flows():
    return {"flows": guardian_service.controller.flow_monitor.latest_flows}


@router.get("/alerts")
def get_alerts(limit: int = 50):
    return {"alerts": guardian_service.db.get_alerts(limit=limit)}


@router.get("/mitigations")
def get_mitigations():
    return {
        "active": guardian_service.controller.mitigation.get_active_rules(),
        "history": guardian_service.db.get_mitigations(limit=50),
    }


@router.post("/mitigations/unblock")
def manual_unblock_flow(req: ManualUnblockRequest):
    res = guardian_service.manual_unblock(req.rule_id)
    if res is None:
        raise HTTPException(status_code=404, detail=f"Mitigation rule {req.rule_id} not found or already inactive")
    return {"status": "unblocked", "rule": res}


@router.post("/scenarios/trigger")
def trigger_scenario(req: ScenarioTriggerRequest):
    try:
        state = guardian_service.trigger_scenario(req.scenario)
        return {"status": "ok", "scenario": req.scenario, "state": state}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/analytics")
def get_analytics():
    return guardian_service.get_analytics_metrics()


@router.get("/settings")
def get_settings():
    return guardian_service.get_settings()


@router.put("/settings")
def update_settings(req: SettingsUpdateRequest):
    updated = guardian_service.update_settings((req.model_dump(exclude_none=True) if hasattr(req, "model_dump") else req.dict(exclude_none=True)))
    return {"status": "updated", "settings": updated}


@router.websocket("/ws/telemetry")
async def websocket_telemetry(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            await ws.send_json(guardian_service.get_full_state())
            await asyncio.sleep(2.0)
    except WebSocketDisconnect:
        pass
