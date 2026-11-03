"""
FastAPI Application Entrypoint (`backend/main.py`)
Serves REST endpoints under `/api/v1`, WebSocket telemetry at `/api/v1/ws/telemetry`,
and mounts the compiled dashboard UI (`frontend/dist` or `dashboard/index.html`).
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from backend.config import settings
from backend.api.routes import router as api_router

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Centralized OpenFlow 1.3 Traffic Monitoring, AI Anomaly Detection, and Automated Threat Mitigation API",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIST = os.path.join(ROOT_DIR, "frontend", "dist")
FRONTEND_ASSETS = os.path.join(FRONTEND_DIST, "assets")
DASHBOARD_HTML = os.path.join(ROOT_DIR, "dashboard", "index.html")

if os.path.isdir(FRONTEND_ASSETS):
    app.mount("/assets", StaticFiles(directory=FRONTEND_ASSETS), name="assets")


@app.get("/api")
def api_root():
    return {
        "project": "AI-Powered SDN Network Guardian",
        "authors": [
            "Rahul Chaube (RA2311003012372)",
            "Mayank Shah (RA2311003012388)",
            "Neha Mallik (RA2311003012393)",
        ],
        "docs_url": "/docs",
        "api_prefix": "/api/v1",
    }


@app.get("/")
def serve_dashboard():
    dist_index = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.isfile(dist_index):
        return FileResponse(dist_index, media_type="text/html")
    if os.path.isfile(DASHBOARD_HTML):
        return FileResponse(DASHBOARD_HTML, media_type="text/html")
    return JSONResponse(api_root())
