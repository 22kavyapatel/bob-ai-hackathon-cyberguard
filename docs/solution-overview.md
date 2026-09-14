# Solution Overview

## What We Built

ThreatSense AI is a web-based SOC analyst assistant that transforms a noisy stream of raw security alerts into prioritised, context-rich intelligence packages. An analyst opens the dashboard, sees alerts ranked by risk score rather than raw severity, clicks any alert to get a correlated cluster view with MITRE ATT&CK technique tags, a 0–100 risk score, an AI-generated BLUF summary, and a ready-made list of recommended actions — all in under 5 seconds.

## How It Works

1. **Alert ingestion:** The FastAPI backend serves a dataset of 50 simulated SIEM alerts covering common attack scenarios (brute force, SQL injection, lateral movement, C2 beaconing, data exfiltration). In a real deployment this would be replaced with a SIEM API connector.

2. **Correlation engine:** When an analyst requests the detail view for an alert, the `correlator.py` module scans all alerts to find those sharing the same source IP, overlapping destination IP/subnet, or the same alert type within a 2-hour time window. These become the *correlated cluster* for that alert.

3. **Risk scoring:** The `analyzer.py` module computes a 0–100 risk score from four weighted components:
   - Base severity (HIGH=40, MEDIUM=25, LOW=10)
   - Cluster size multiplier (more correlated alerts = higher score)
   - MITRE ATT&CK technique count (each unique tactic adds points)
   - Asset criticality (destination IPs tagged as servers score higher)

4. **MITRE ATT&CK mapping:** A keyword-to-technique lookup maps each alert type to one or more MITRE ATT&CK technique IDs and names (e.g., *Brute Force → T1110*, *Command & Control → T1071*).

5. **Classification:** Alerts are classified into three buckets based on risk score and false-positive signals:
   - **Likely Threat** (score ≥ 65 or HIGH severity + correlated)
   - **Needs Investigation** (score 35–64)
   - **Likely False Positive** (score < 35 or single isolated LOW alert)

6. **BLUF summary:** The `watsonx_client.py` module calls the IBM watsonx.ai `ibm/granite-3-8b-instruct` model with a structured prompt describing the alert cluster. The model returns a 2–3 sentence analyst-ready summary. If no API key is configured, a deterministic rule-based summary is generated instead.

7. **Recommended actions:** The analyzer maps alert types and MITRE techniques to a curated set of analyst playbook actions (e.g., *"Block source IP at perimeter firewall"*, *"Reset credentials for affected accounts"*).

8. **Dashboard:** The React frontend polls the backend `/api/alerts` endpoint on load and re-fetches analysis on demand. Analysts can filter by severity, source system, and status (Open / In Review / Closed), search by keyword, and update alert status in-place.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Analyst Browser                      │
│              React 18 + Tailwind CSS SPA                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  FilterBar   │  │  AlertList   │  │ AlertDetail  │  │
│  │  (severity,  │  │  (sorted by  │  │ (BLUF, score,│  │
│  │  source,     │  │  risk score) │  │ MITRE, recs) │  │
│  │  status)     │  │              │  │              │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
└─────────┼─────────────────┼─────────────────┼──────────┘
          │                 │  REST API        │
          │         ┌───────▼──────────────────▼──────┐
          │         │     FastAPI Backend (port 8000)  │
          │         │  ┌───────────┐  ┌────────────┐  │
          │         │  │ correlator│  │  analyzer  │  │
          │         │  │  .py      │  │  .py       │  │
          │         │  └─────┬─────┘  └─────┬──────┘  │
          │         │        │              │          │
          │         │  ┌─────▼──────────────▼──────┐  │
          │         │  │     alerts.py (simulated   │  │
          │         │  │     SIEM alert store)      │  │
          │         │  └───────────────────────────┘  │
          │         │  ┌───────────────────────────┐  │
          │         │  │  watsonx_client.py         │  │
          │         │  │  IBM watsonx.ai Granite    │  │
          │         │  │  (BLUF generation)         │  │
          │         │  └──────────────┬────────────┘  │
          │         └─────────────────┼───────────────┘
          │                           │ HTTPS
          │                  ┌────────▼────────┐
          │                  │  IBM watsonx.ai  │
          │                  │  Granite-3-8B    │
          └──────────────────┴─────────────────┘
```

## Key Design Decisions

| Decision | Rationale |
|---|---|
| FastAPI (Python) for the backend | Python's ecosystem (requests, IBM SDK) makes watsonx.ai integration trivial; FastAPI's async support handles concurrent analyst requests cleanly |
| React + Tailwind CSS for the frontend | Rapid iteration on the UI with professional results; Tailwind avoids the overhead of a component library for a hackathon scope |
| In-memory alert store | Eliminates a database dependency, making the project run with a single `uvicorn` command; trivially replaceable with a real SIEM API in production |
| Graceful fallback for watsonx.ai | The app is fully functional without an API key — this ensures judges and evaluators can run it locally with zero IBM Cloud setup |
| MITRE ATT&CK keyword mapping | A curated lookup table is reliable, deterministic, and auditable — important for a security tool where explainability matters |

## IBM Technologies Used

- **IBM watsonx.ai (Granite-3-8B-Instruct):** Used via direct HTTP REST API (`/ml/v1/text/generation`) to generate the BLUF threat summaries. The model receives a structured prompt containing alert type, source/destination, severity, correlated cluster size, and MITRE techniques, and returns a concise analyst-readable paragraph.

- **IBM Bob AI Assistant:** Used throughout the development workflow — generating boilerplate code, reviewing the correlation algorithm, writing documentation, and iterating on the risk scoring formula. IBM Bob was used as a pair-programmer for the entire project.
