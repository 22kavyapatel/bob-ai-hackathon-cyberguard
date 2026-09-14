"""
main.py — FastAPI application entry point for ThreatSense AI.

Endpoints:
  GET  /health
  GET  /api/stats
  GET  /api/alerts
  GET  /api/alerts/{alert_id}/analysis
  PATCH /api/alerts/{alert_id}/status
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Search for .env in src/ then project root
_HERE = Path(__file__).resolve().parent
for _candidate in [_HERE / ".." / ".env", _HERE / ".env", _HERE / ".." / ".." / ".env"]:
    if _candidate.exists():
        load_dotenv(dotenv_path=str(_candidate))
        break

from alerts import AlertStatus, get_alert_by_id, get_all_alerts, update_alert_status
from analyzer import analyse
from correlator import correlate
from watsonx_client import generate_bluf

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="ThreatSense AI API",
    description="AI-powered threat intelligence correlation and alert prioritisation",
    version="1.0.0",
)

_FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[_FRONTEND_ORIGIN, "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class StatusUpdateRequest(BaseModel):
    status: AlertStatus


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/stats")
def get_stats() -> dict[str, Any]:
    alerts = get_all_alerts()
    return {
        "total": len(alerts),
        "high": sum(1 for a in alerts if a.severity == "HIGH"),
        "medium": sum(1 for a in alerts if a.severity == "MEDIUM"),
        "low": sum(1 for a in alerts if a.severity == "LOW"),
        "open": sum(1 for a in alerts if a.status == "open"),
        "in_review": sum(1 for a in alerts if a.status == "in_review"),
        "closed": sum(1 for a in alerts if a.status == "closed"),
    }


@app.get("/api/alerts")
def list_alerts() -> list[dict[str, Any]]:
    return [a.model_dump() for a in get_all_alerts()]


@app.get("/api/alerts/{alert_id}/analysis")
def get_analysis(alert_id: str) -> dict[str, Any]:
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    correlated = correlate(alert)
    result = analyse(alert, correlated)

    bluf = generate_bluf(
        alert_type=alert.alert_type,
        severity=alert.severity,
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        description=alert.description,
        cluster_size=len(correlated),
        mitre_techniques=result.mitre_techniques,
        classification=result.classification,
    )

    return {
        "alert": alert.model_dump(),
        "risk_score": result.risk_score,
        "classification": result.classification,
        "mitre_techniques": result.mitre_techniques,
        "recommendations": result.recommendations,
        "bluf_summary": bluf,
        "correlated_alerts": [c.model_dump() for c in correlated[:10]],
    }


@app.patch("/api/alerts/{alert_id}/status")
def update_status(alert_id: str, body: StatusUpdateRequest) -> dict[str, Any]:
    updated = update_alert_status(alert_id, body.status)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return updated.model_dump()
