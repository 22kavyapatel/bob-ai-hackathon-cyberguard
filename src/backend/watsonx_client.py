"""
watsonx_client.py — IBM watsonx.ai integration for BLUF threat summary generation.

Uses the Granite-3-8B-Instruct model via the watsonx.ai REST API.
Falls back to a deterministic rule-based summary when no API key is configured.
"""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

import httpx
from dotenv import load_dotenv

# Search for .env in src/ (one level up from backend/) then project root
_HERE = Path(__file__).resolve().parent
for _candidate in [_HERE / ".." / ".env", _HERE / ".env", _HERE / ".." / ".." / ".env"]:
    if _candidate.exists():
        load_dotenv(dotenv_path=str(_candidate))
        break

_API_KEY = os.getenv("WATSONX_API_KEY", "").strip()
_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "").strip()
_WATSONX_URL = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com").rstrip("/")
_MODEL_ID = "ibm/granite-3-8b-instruct"
_IAM_URL = "https://iam.cloud.ibm.com/identity/token"


def _get_iam_token() -> str:
    """Exchange IBM Cloud API key for a bearer token."""
    resp = httpx.post(
        _IAM_URL,
        data={
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": _API_KEY,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _build_prompt(
    alert_type: str,
    severity: str,
    src_ip: str,
    dst_ip: str,
    description: str,
    cluster_size: int,
    mitre_techniques: list[dict],
    classification: str,
) -> str:
    technique_str = ", ".join(
        f"{t['id']} ({t['name']})" for t in mitre_techniques[:4]
    ) or "none identified"

    return textwrap.dedent(f"""
        You are a cybersecurity analyst writing a BLUF (Bottom Line Up Front) threat summary
        for a Security Operations Centre dashboard. Write 2-3 concise sentences. Be direct,
        professional, and action-oriented. Do not repeat the input data verbatim.

        Alert details:
        - Type: {alert_type}
        - Severity: {severity}
        - Source IP: {src_ip}
        - Destination IP: {dst_ip}
        - Description: {description}
        - Correlated alerts in cluster: {cluster_size}
        - MITRE ATT&CK techniques: {technique_str}
        - Classification: {classification}

        Write the BLUF summary:
    """).strip()


def _fallback_summary(
    alert_type: str,
    severity: str,
    src_ip: str,
    dst_ip: str,
    cluster_size: int,
    classification: str,
) -> str:
    """Deterministic rule-based summary used when watsonx.ai is unavailable."""
    cluster_phrase = (
        f"This alert is part of a cluster of {cluster_size + 1} correlated events, "
        "indicating a sustained or multi-stage attack pattern. "
        if cluster_size > 0
        else "This appears to be an isolated event. "
    )
    severity_phrase = {
        "HIGH": "Immediate analyst attention is required.",
        "MEDIUM": "This alert warrants investigation within the current shift.",
        "LOW": "Low priority — validate whether this is expected behaviour.",
    }.get(severity, "Review required.")

    return (
        f"[Rule-based summary — configure WATSONX_API_KEY for AI-generated summaries] "
        f"A {severity.lower()}-severity {alert_type} was detected from {src_ip} targeting {dst_ip}. "
        f"{cluster_phrase}"
        f"Classification: {classification}. {severity_phrase}"
    )


def generate_bluf(
    alert_type: str,
    severity: str,
    src_ip: str,
    dst_ip: str,
    description: str,
    cluster_size: int,
    mitre_techniques: list[dict],
    classification: str,
) -> str:
    """
    Generate a BLUF threat summary.
    Uses IBM watsonx.ai Granite if credentials are available, otherwise falls back.
    """
    if not _API_KEY or not _PROJECT_ID:
        return _fallback_summary(
            alert_type, severity, src_ip, dst_ip, cluster_size, classification
        )

    try:
        token = _get_iam_token()
        prompt = _build_prompt(
            alert_type, severity, src_ip, dst_ip, description,
            cluster_size, mitre_techniques, classification,
        )

        url = f"{_WATSONX_URL}/ml/v1/text/generation?version=2023-05-29"
        payload = {
            "model_id": _MODEL_ID,
            "project_id": _PROJECT_ID,
            "input": prompt,
            "parameters": {
                "decoding_method": "greedy",
                "max_new_tokens": 150,
                "stop_sequences": ["\n\n"],
            },
        }
        resp = httpx.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=20,
        )
        resp.raise_for_status()
        result = resp.json()
        text = result["results"][0]["generated_text"].strip()
        return text if text else _fallback_summary(
            alert_type, severity, src_ip, dst_ip, cluster_size, classification
        )

    except Exception as exc:
        # Never crash the API because of watsonx.ai issues — degrade gracefully
        print(f"[watsonx_client] BLUF generation failed: {exc!r} — using fallback")
        return _fallback_summary(
            alert_type, severity, src_ip, dst_ip, cluster_size, classification
        )
