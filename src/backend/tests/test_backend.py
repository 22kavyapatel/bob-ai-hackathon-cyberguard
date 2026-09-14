"""
tests/test_backend.py — Basic smoke tests for ThreatSense AI backend.
"""

import sys
import os

# Add the parent directory to sys.path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_get_stats():
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 50
    # Severity counts must add up to total
    assert data["high"] + data["medium"] + data["low"] == data["total"]
    # Status counts must add up to total
    assert data["open"] + data["in_review"] + data["closed"] == data["total"]
    # At least some HIGH alerts expected from seeded scenarios
    assert data["high"] >= 10


def test_list_alerts_count():
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    alerts = resp.json()
    assert len(alerts) == 50


def test_list_alerts_fields():
    resp = client.get("/api/alerts")
    alert = resp.json()[0]
    required_fields = {"id", "source", "timestamp", "src_ip", "dst_ip",
                       "alert_type", "severity", "status", "description"}
    assert required_fields.issubset(alert.keys())


def test_alert_analysis():
    # Use the first HIGH severity alert
    alerts = client.get("/api/alerts").json()
    high_alert = next(a for a in alerts if a["severity"] == "HIGH")
    alert_id = high_alert["id"]

    resp = client.get(f"/api/alerts/{alert_id}/analysis")
    assert resp.status_code == 200

    data = resp.json()
    assert "risk_score" in data
    assert 0 <= data["risk_score"] <= 100
    assert data["classification"] in ("Likely Threat", "Needs Investigation", "Likely False Positive")
    assert isinstance(data["mitre_techniques"], list)
    assert isinstance(data["recommendations"], list)
    assert isinstance(data["bluf_summary"], str)
    assert len(data["bluf_summary"]) > 20
    assert isinstance(data["correlated_alerts"], list)


def test_analysis_not_found():
    resp = client.get("/api/alerts/ALT-NONEXISTENT/analysis")
    assert resp.status_code == 404


def test_update_status():
    alerts = client.get("/api/alerts").json()
    open_alert = next(a for a in alerts if a["status"] == "open")
    alert_id = open_alert["id"]

    resp = client.patch(f"/api/alerts/{alert_id}/status", json={"status": "in_review"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_review"


def test_correlation_produces_results():
    """High-severity brute force alerts should have correlated events."""
    from alerts import get_all_alerts
    from correlator import correlate

    alerts = get_all_alerts()
    brute_force = next((a for a in alerts if a.alert_type == "Brute Force Login Attempt"), None)
    assert brute_force is not None

    correlated = correlate(brute_force)
    # Our seeded data has 3 brute force alerts from same IP — at least 1 should correlate
    assert len(correlated) >= 1


def test_risk_score_high_severity():
    """High severity alerts should score higher than low severity ones."""
    from alerts import get_all_alerts
    from analyzer import analyse
    from correlator import correlate

    alerts = get_all_alerts()
    high = next(a for a in alerts if a.severity == "HIGH")
    low = next(a for a in alerts if a.severity == "LOW")

    high_result = analyse(high, correlate(high))
    low_result = analyse(low, correlate(low))

    assert high_result.risk_score > low_result.risk_score
