"""
analyzer.py — Risk scoring, MITRE ATT&CK mapping, classification and
recommended actions engine for ThreatSense AI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from alerts import Alert

Classification = Literal["Likely Threat", "Likely False Positive", "Needs Investigation"]


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique mapping
# ---------------------------------------------------------------------------

_MITRE_MAP: dict[str, list[dict]] = {
    "Brute Force Login Attempt": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
    ],
    "SQL Injection Attempt": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    "Lateral Movement Detected": [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
        {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    ],
    "Command & Control Beacon": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "Command and Control"},
    ],
    "Data Exfiltration Suspected": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
        {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    ],
    "Privilege Escalation": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Privilege Escalation"},
    ],
    "Suspicious PowerShell Execution": [
        {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
        {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    ],
    "Port Scan Detected": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    ],
    "Malware Signature Match": [
        {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
        {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    ],
    "Phishing Link Clicked": [
        {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
        {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
    ],
    "Anomalous Login Location": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
        {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access"},
    ],
    "Weak Cipher Negotiation": [
        {"id": "T1040", "name": "Network Sniffing", "tactic": "Discovery"},
    ],
    "DNS Tunnelling Suspected": [
        {"id": "T1071.004", "name": "DNS", "tactic": "Command and Control"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    ],
    "Failed VPN Authentication": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access"},
    ],
    "Ransomware Behaviour Detected": [
        {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
        {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
    ],
}

# ---------------------------------------------------------------------------
# Recommended actions per alert type
# ---------------------------------------------------------------------------

_RECOMMENDATIONS: dict[str, list[str]] = {
    "Brute Force Login Attempt": [
        "Block source IP at perimeter firewall immediately.",
        "Enable account lockout policy on the targeted system.",
        "Review successful logins from this IP in the last 24 hours.",
        "Enable MFA on all externally accessible services.",
    ],
    "SQL Injection Attempt": [
        "Block source IP at the WAF and perimeter firewall.",
        "Review web application logs for successful SQL injection payloads.",
        "Patch or update the affected web application framework.",
        "Run a database integrity check on the targeted server.",
    ],
    "Lateral Movement Detected": [
        "Isolate the source host from the network pending investigation.",
        "Review user account activity on both source and destination hosts.",
        "Check for new scheduled tasks, services, or startup entries.",
        "Perform memory forensics on the source host.",
    ],
    "Command & Control Beacon": [
        "Block C2 destination IP/domain at the DNS layer and firewall.",
        "Isolate the beaconing host and capture a memory image.",
        "Search for the same C2 indicator across all endpoints.",
        "Submit the C2 IP to threat intelligence sharing platforms.",
    ],
    "Data Exfiltration Suspected": [
        "Block the destination IP and stop the active transfer immediately.",
        "Identify which data was transferred and assess regulatory impact.",
        "Initiate incident response and notify the security team lead.",
        "Preserve network capture logs for forensic analysis.",
    ],
    "Privilege Escalation": [
        "Revoke elevated privileges on the affected host immediately.",
        "Patch the kernel or application vulnerability exploited.",
        "Review all actions taken by the escalated process.",
        "Audit privilege escalation logs across all hosts.",
    ],
    "Suspicious PowerShell Execution": [
        "Enable PowerShell Script Block Logging on the affected host.",
        "Decode the obfuscated command and analyse intent.",
        "Check for persistence mechanisms (registry, scheduled tasks).",
        "Consider constraining PowerShell execution policy on endpoints.",
    ],
    "Port Scan Detected": [
        "Verify if the source is an authorised vulnerability scanner.",
        "Block the source IP at the perimeter if it is external.",
        "Review firewall rules to limit exposure of sensitive services.",
    ],
    "Malware Signature Match": [
        "Quarantine the affected host immediately.",
        "Run a full antimalware scan with updated signatures.",
        "Check lateral spread: search for the same hash on all endpoints.",
        "Preserve the malicious file for reverse engineering.",
    ],
    "Phishing Link Clicked": [
        "Reset credentials for the affected user account immediately.",
        "Enable MFA if not already in place.",
        "Block the phishing domain at the email gateway and DNS layer.",
        "Brief the affected user on phishing awareness.",
    ],
    "Anomalous Login Location": [
        "Verify with the user whether the login was legitimate.",
        "Temporarily suspend the account pending confirmation.",
        "Enable conditional access policies based on location.",
        "Review all actions taken during the anomalous session.",
    ],
    "Weak Cipher Negotiation": [
        "Update TLS configuration to disable deprecated cipher suites.",
        "Enforce TLS 1.2 or higher on all services.",
        "Schedule a full TLS audit across exposed services.",
    ],
    "DNS Tunnelling Suspected": [
        "Block the suspicious domain at the DNS resolver.",
        "Analyse DNS query volume and entropy from the source host.",
        "Check for data staging on the affected host.",
        "Consider DNS-over-HTTPS monitoring.",
    ],
    "Failed VPN Authentication": [
        "Temporarily block the source IP after threshold exceeded.",
        "Verify no successful logins occurred from this IP.",
        "Enable geographic restrictions on VPN access.",
    ],
    "Ransomware Behaviour Detected": [
        "Isolate the affected host from the network IMMEDIATELY.",
        "Disconnect shared drives and storage resources.",
        "Do NOT reboot — preserve memory forensics.",
        "Notify incident response team and activate recovery runbook.",
        "Assess scope: identify other hosts with similar file modification activity.",
    ],
}

_DEFAULT_RECOMMENDATIONS = [
    "Investigate the source IP for known threat intelligence matches.",
    "Review logs on the affected host for related activity.",
    "Escalate to Tier-2 analyst if suspicious activity is confirmed.",
]


# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

_SEVERITY_BASE = {"HIGH": 40, "MEDIUM": 25, "LOW": 10}
_SERVER_IPS = {"10.0.10.5", "10.0.10.10", "10.0.10.20", "10.0.10.30"}


def _cluster_bonus(cluster_size: int) -> int:
    """Extra points based on number of correlated alerts."""
    if cluster_size == 0:
        return 0
    if cluster_size <= 2:
        return 8
    if cluster_size <= 5:
        return 15
    if cluster_size <= 10:
        return 22
    return 30


def _mitre_bonus(techniques: list[dict]) -> int:
    unique_tactics = {t["tactic"] for t in techniques}
    return min(len(unique_tactics) * 5, 20)


def _asset_bonus(dst_ip: str) -> int:
    return 10 if dst_ip in _SERVER_IPS else 0


@dataclass
class AnalysisResult:
    alert_id: str
    risk_score: int                        # 0–100
    classification: Classification
    mitre_techniques: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


def analyse(alert: Alert, correlated: list[Alert]) -> AnalysisResult:
    """Compute risk score, classification and recommendations for an alert."""
    # Collect MITRE techniques from this alert and all correlated alerts
    all_types = {alert.alert_type} | {c.alert_type for c in correlated}
    techniques: list[dict] = []
    seen_ids: set[str] = set()
    for atype in all_types:
        for t in _MITRE_MAP.get(atype, []):
            if t["id"] not in seen_ids:
                seen_ids.add(t["id"])
                techniques.append(t)

    # Risk score calculation
    base = _SEVERITY_BASE.get(alert.severity, 10)
    score = (
        base
        + _cluster_bonus(len(correlated))
        + _mitre_bonus(techniques)
        + _asset_bonus(alert.dst_ip)
    )
    score = min(score, 100)

    # Classification
    has_high_correlated = any(c.severity == "HIGH" for c in correlated)
    if score >= 65 or (alert.severity == "HIGH" and len(correlated) >= 2):
        classification: Classification = "Likely Threat"
    elif score >= 35 or has_high_correlated:
        classification = "Needs Investigation"
    else:
        classification = "Likely False Positive"

    # Recommendations: this alert + any unique ones from correlated types
    rec_set: list[str] = []
    seen_recs: set[str] = set()
    for atype in [alert.alert_type] + [c.alert_type for c in correlated]:
        for rec in _RECOMMENDATIONS.get(atype, _DEFAULT_RECOMMENDATIONS):
            if rec not in seen_recs:
                seen_recs.add(rec)
                rec_set.append(rec)
        if len(rec_set) >= 6:
            break

    return AnalysisResult(
        alert_id=alert.id,
        risk_score=score,
        classification=classification,
        mitre_techniques=techniques,
        recommendations=rec_set or _DEFAULT_RECOMMENDATIONS,
    )
