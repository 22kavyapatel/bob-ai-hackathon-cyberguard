"""
alerts.py — Simulated SIEM alert store for ThreatSense AI.
All data is synthetic. No real IP addresses, hostnames, or user data.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel

AlertSeverity = Literal["HIGH", "MEDIUM", "LOW"]
AlertStatus = Literal["open", "in_review", "closed"]


class Alert(BaseModel):
    id: str
    source: str          # SIEM source system name
    timestamp: str       # ISO 8601
    src_ip: str
    dst_ip: str
    alert_type: str
    severity: AlertSeverity
    status: AlertStatus
    description: str


# ---------------------------------------------------------------------------
# Simulated data
# ---------------------------------------------------------------------------

_SOURCES = [
    "Firewall-IDS",
    "EDR-Sentinel",
    "WAF-CloudEdge",
    "SIEM-QRadar",
    "NetFlow-Analyzer",
    "Email-Gateway",
]

_ALERT_TEMPLATES: list[dict] = [
    {
        "alert_type": "Brute Force Login Attempt",
        "severity": "HIGH",
        "description": "Multiple failed authentication attempts detected against {dst_ip} from {src_ip}.",
    },
    {
        "alert_type": "SQL Injection Attempt",
        "severity": "HIGH",
        "description": "SQL injection payload detected in HTTP request from {src_ip} targeting {dst_ip}.",
    },
    {
        "alert_type": "Lateral Movement Detected",
        "severity": "HIGH",
        "description": "Unusual internal network scan from {src_ip} to {dst_ip} matching lateral movement pattern.",
    },
    {
        "alert_type": "Command & Control Beacon",
        "severity": "HIGH",
        "description": "Periodic outbound connection from {src_ip} to known C2 IP {dst_ip} every 60 seconds.",
    },
    {
        "alert_type": "Data Exfiltration Suspected",
        "severity": "HIGH",
        "description": "Large outbound data transfer ({src_ip} → {dst_ip}) outside business hours.",
    },
    {
        "alert_type": "Privilege Escalation",
        "severity": "HIGH",
        "description": "Process on {src_ip} attempted to escalate privileges via known kernel exploit.",
    },
    {
        "alert_type": "Suspicious PowerShell Execution",
        "severity": "MEDIUM",
        "description": "Encoded PowerShell command executed on {src_ip}; possible script-based attack.",
    },
    {
        "alert_type": "Port Scan Detected",
        "severity": "MEDIUM",
        "description": "Sequential port scan from {src_ip} targeting {dst_ip} across 1024+ ports.",
    },
    {
        "alert_type": "Malware Signature Match",
        "severity": "MEDIUM",
        "description": "File hash on {src_ip} matched known malware signature in threat intelligence feed.",
    },
    {
        "alert_type": "Phishing Link Clicked",
        "severity": "MEDIUM",
        "description": "User on {src_ip} accessed a confirmed phishing URL. Possible credential compromise.",
    },
    {
        "alert_type": "Anomalous Login Location",
        "severity": "MEDIUM",
        "description": "Successful login to {dst_ip} from {src_ip} in a country not in baseline behaviour.",
    },
    {
        "alert_type": "Weak Cipher Negotiation",
        "severity": "LOW",
        "description": "TLS connection from {src_ip} to {dst_ip} negotiated a deprecated cipher suite.",
    },
    {
        "alert_type": "DNS Tunnelling Suspected",
        "severity": "MEDIUM",
        "description": "High-frequency DNS queries with unusual subdomain entropy from {src_ip}.",
    },
    {
        "alert_type": "Failed VPN Authentication",
        "severity": "LOW",
        "description": "Repeated VPN authentication failures from {src_ip} against VPN concentrator {dst_ip}.",
    },
    {
        "alert_type": "Ransomware Behaviour Detected",
        "severity": "HIGH",
        "description": "Rapid file encryption activity on {src_ip} consistent with ransomware execution.",
    },
]

# Fixed attacker IPs to enable realistic correlation
_ATTACKER_IPS = [
    "185.220.101.42",   # Known Tor exit node range (synthetic)
    "91.108.56.77",
    "103.45.12.88",
    "198.51.100.23",    # TEST-NET (RFC 5737) — safe for demos
    "203.0.113.55",     # TEST-NET (RFC 5737)
]

_INTERNAL_IPS = [
    "10.0.1.10",
    "10.0.1.15",
    "10.0.2.20",
    "10.0.2.25",
    "10.0.3.5",
    "10.0.3.50",
    "192.168.1.100",
    "192.168.1.101",
    "192.168.2.55",
]

_SERVER_IPS = [
    "10.0.10.5",    # Web server
    "10.0.10.10",   # Database server
    "10.0.10.20",   # Auth server
    "10.0.10.30",   # File server
]


def _generate_alerts() -> list[Alert]:
    """Generate 50 deterministic simulated alerts."""
    random.seed(42)  # Deterministic — same data every run
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    alerts: list[Alert] = []

    # Seeded scenarios for realistic correlation clusters
    scenarios = [
        # Scenario A: Brute force + lateral movement campaign from 185.220.101.42
        (0, "Brute Force Login Attempt", "HIGH", "185.220.101.42", "10.0.10.20", -55),
        (1, "Brute Force Login Attempt", "HIGH", "185.220.101.42", "10.0.10.20", -50),
        (2, "Brute Force Login Attempt", "HIGH", "185.220.101.42", "10.0.10.20", -45),
        (3, "Lateral Movement Detected",  "HIGH", "10.0.10.20",   "10.0.10.10", -40),
        (4, "Lateral Movement Detected",  "HIGH", "10.0.10.20",   "10.0.10.5",  -35),
        (5, "Privilege Escalation",       "HIGH", "10.0.10.20",   "10.0.10.10", -30),
        # Scenario B: SQL injection from 91.108.56.77
        (6, "SQL Injection Attempt",      "HIGH", "91.108.56.77", "10.0.10.5",  -120),
        (7, "SQL Injection Attempt",      "HIGH", "91.108.56.77", "10.0.10.5",  -118),
        (8, "SQL Injection Attempt",      "HIGH", "91.108.56.77", "10.0.10.5",  -115),
        (9, "Data Exfiltration Suspected","HIGH", "10.0.10.5",   "91.108.56.77",-100),
        # Scenario C: C2 beaconing from 103.45.12.88
        (10, "Command & Control Beacon",  "HIGH", "10.0.1.10",   "103.45.12.88",-200),
        (11, "Command & Control Beacon",  "HIGH", "10.0.1.10",   "103.45.12.88",-199),
        (12, "Command & Control Beacon",  "HIGH", "10.0.1.15",   "103.45.12.88",-198),
        (13, "Suspicious PowerShell Execution","MEDIUM","10.0.1.10","10.0.1.10",-195),
        # Scenario D: Ransomware
        (14, "Ransomware Behaviour Detected","HIGH","10.0.2.20","10.0.2.20",   -20),
        (15, "Malware Signature Match",   "MEDIUM","10.0.2.20",  "10.0.2.20",  -25),
        (16, "Suspicious PowerShell Execution","MEDIUM","10.0.2.20","10.0.2.20",-28),
        # Scenario E: Phishing + credential compromise
        (17, "Phishing Link Clicked",     "MEDIUM","192.168.1.100","198.51.100.23",-360),
        (18, "Anomalous Login Location",  "MEDIUM","198.51.100.23","10.0.10.20", -355),
        (19, "Data Exfiltration Suspected","HIGH","198.51.100.23","10.0.10.30", -350),
    ]

    idx = 0
    for (_seq, atype, sev, src, dst, delta_min) in scenarios:
        ts = now + timedelta(minutes=delta_min)
        template = next((t for t in _ALERT_TEMPLATES if t["alert_type"] == atype), None)
        if template:
            alerts.append(Alert(
                id=f"ALT-{1000 + idx:04d}",
                source=random.choice(_SOURCES),
                timestamp=ts.isoformat(timespec="seconds") + "Z",
                src_ip=src,
                dst_ip=dst,
                alert_type=atype,
                severity=sev,
                status="open",
                description=template["description"].format(src_ip=src, dst_ip=dst),
            ))
            idx += 1

    # Fill remaining with randomised alerts
    while len(alerts) < 50:
        template = random.choice(_ALERT_TEMPLATES)
        src = random.choice(_ATTACKER_IPS + _INTERNAL_IPS)
        dst = random.choice(_INTERNAL_IPS + _SERVER_IPS)
        delta = random.randint(-720, -1)
        ts = now + timedelta(minutes=delta)
        status_choices: list[AlertStatus] = ["open", "open", "open", "in_review", "closed"]
        alerts.append(Alert(
            id=f"ALT-{1000 + idx:04d}",
            source=random.choice(_SOURCES),
            timestamp=ts.isoformat(timespec="seconds") + "Z",
            src_ip=src,
            dst_ip=dst,
            alert_type=template["alert_type"],
            severity=template["severity"],
            status=random.choice(status_choices),
            description=template["description"].format(src_ip=src, dst_ip=dst),
        ))
        idx += 1

    # Sort newest first
    alerts.sort(key=lambda a: a.timestamp, reverse=True)
    return alerts


# Module-level in-memory store (mutable for status updates)
_ALERT_STORE: list[Alert] = _generate_alerts()


def get_all_alerts() -> list[Alert]:
    return _ALERT_STORE


def get_alert_by_id(alert_id: str) -> Alert | None:
    return next((a for a in _ALERT_STORE if a.id == alert_id), None)


def update_alert_status(alert_id: str, status: AlertStatus) -> Alert | None:
    for alert in _ALERT_STORE:
        if alert.id == alert_id:
            # Pydantic v2 models are immutable by default — replace the object
            updated = alert.model_copy(update={"status": status})
            idx = _ALERT_STORE.index(alert)
            _ALERT_STORE[idx] = updated
            return updated
    return None
