"""
Hybrid NIDS - FastAPI Backend
--------------------------------
Endpoints:
  GET  /api/status                current detector/simulator status
  POST /api/simulate/mode          switch simulator traffic mode
  GET  /api/alerts                 recent alerts (paginated)
  POST /api/analyze/flow           score a single hand-built flow (manual test)
  WS   /ws/live                    live alert + stats feed for the dashboard

Run:
  uvicorn app.main:app --reload --port 8000
"""

import asyncio
import time
from collections import deque
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.detection.hybrid import HybridDetector, Alert
from app.simulate.replay import TrafficSimulator

app = FastAPI(title="Hybrid NIDS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten for production
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = HybridDetector(ml_threshold=0.6)
ALERT_HISTORY = deque(maxlen=500)
CONNECTED_CLIENTS: list[WebSocket] = []

simulator = TrafficSimulator(
    detector,
    on_alert=lambda a: ALERT_HISTORY.appendleft(a.to_dict()),
)


@app.on_event("startup")
async def startup():
    asyncio.create_task(simulator.run())
    asyncio.create_task(_broadcast_loop())
    asyncio.create_task(_flow_expiry_loop())


async def _flow_expiry_loop():
    """Periodically evaluate flows that have gone idle (needed to catch
    slow/low-rate attacks whose signature only becomes clear once the flow
    has run long enough)."""
    while True:
        await asyncio.sleep(2)
        alerts = detector.flush_expired()
        for a in alerts:
            ALERT_HISTORY.appendleft(a.to_dict())


async def _broadcast_loop():
    """Pushes newest alerts + stats to all connected websocket clients."""
    last_sent_count = 0
    while True:
        await asyncio.sleep(0.5)
        if len(ALERT_HISTORY) != last_sent_count and CONNECTED_CLIENTS:
            last_sent_count = len(ALERT_HISTORY)
            newest = list(ALERT_HISTORY)[:5]
            payload = {"type": "alerts", "data": newest}
            dead = []
            for ws in CONNECTED_CLIENTS:
                try:
                    await ws.send_json(payload)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                CONNECTED_CLIENTS.remove(ws)


@app.get("/api/status")
def status():
    return {
        "mode": simulator.mode,
        "active_flows": len(detector.tracker.active_flows()),
        "total_alerts": len(ALERT_HISTORY),
        "ml_model_loaded": detector.ml_engine.loaded,
    }


class ModeRequest(BaseModel):
    mode: str  # benign | portscan | dos_volumetric | dos_slow


@app.post("/api/simulate/mode")
def set_mode(req: ModeRequest):
    simulator.set_mode(req.mode)
    return {"ok": True, "mode": simulator.mode}


@app.get("/api/alerts")
def get_alerts(limit: int = 50, severity: Optional[str] = None):
    alerts = list(ALERT_HISTORY)
    if severity:
        alerts = [a for a in alerts if a["severity"] == severity.upper()]
    return {"count": len(alerts), "alerts": alerts[:limit]}


class FlowFeatures(BaseModel):
    flow_duration: float = 1.0
    total_fwd_packets: int = 1
    total_bwd_packets: int = 0
    total_fwd_bytes: float = 60
    total_bwd_bytes: float = 0
    packets_per_sec: float = 1.0
    bytes_per_sec: float = 60.0
    avg_packet_size: float = 60.0
    max_packet_size: float = 60.0
    min_packet_size: float = 60.0
    avg_iat: float = 0.1
    syn_count: int = 1
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0


@app.post("/api/analyze/flow")
def analyze_flow(features: FlowFeatures):
    """Manually score a hand-built flow feature set through the ML engine
    (useful for report screenshots / unit testing without live traffic)."""
    fdict = features.dict()
    fdict["syn_ack_ratio"] = fdict["syn_count"] / (fdict["ack_count"] + 1)
    fdict["fwd_bwd_ratio"] = fdict["total_fwd_packets"] / (fdict["total_bwd_packets"] + 1)
    verdict = detector.ml_engine.evaluate(fdict)
    return {
        "triggered": verdict.triggered,
        "attack_type": verdict.attack_type,
        "confidence": verdict.confidence,
        "class_probabilities": verdict.class_probabilities,
    }


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    await websocket.accept()
    CONNECTED_CLIENTS.append(websocket)
    try:
        # send initial snapshot
        await websocket.send_json({"type": "alerts", "data": list(ALERT_HISTORY)[:20]})
        while True:
            # keep connection open; client doesn't need to send anything
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in CONNECTED_CLIENTS:
            CONNECTED_CLIENTS.remove(websocket)
