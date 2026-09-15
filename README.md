 🛡️ ThreatSense AI

> **AI-Powered Threat Intelligence Correlation & Alert Prioritisation Assistant**
> IBM Bob AI Innovation Hackathon 2026 — Problem D2 — Track: AI

---

 Team

| Field | Value |
|---|---|
| **Team Name** | CyberGuard |
| **Track** | AI |
| **Team Lead** | CyberGuard Team Lead — d26it112@charusat.edu.in|
| **Members** | khalasi Diya, Kumud Patil, Maitry Rana |

---

 Problem Statement

Security Operations Centre (SOC) analysts are overwhelmed by hundreds of raw cybersecurity alerts per shift. Without intelligent triage, critical threats are buried in noise, leading to slow response times, analyst fatigue, and missed incidents that can result in costly data breaches.

---

 Solution

ThreatSense AI is an AI-powered threat intelligence correlation and alert prioritisation assistant. It ingests raw security alerts, correlates related events into attack clusters, calculates a risk score, maps detected techniques to MITRE ATT&CK, and generates a BLUF (Bottom Line Up Front) threat summary with recommended analyst actions — powered by IBM watsonx.ai and built with IBM Bob.

---

Key Features

- **🔗 AI-Driven Alert Correlation:** Groups related alerts by source IP, attack pattern, and time window to surface campaign-level threats rather than isolated noise.
- **📊 Risk Scoring Engine:** Calculates a 0–100 threat score per alert cluster using severity, frequency, asset criticality, and MITRE ATT&CK technique coverage.
- **🗺️ MITRE ATT&CK Mapping:** Automatically tags detected techniques (e.g., T1059, T1190, T1078) on each correlated alert cluster.
- **📝 BLUF Threat Summary:** IBM watsonx.ai Granite model generates a one-paragraph analyst-ready summary and prioritised recommended actions per alert.
- **🖥️ Interactive SOC Dashboard:** Real-time severity/status/source filtering, alert detail drill-down panel, and classification (Likely Threat / Likely False Positive / Needs Investigation).

---

 Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | Python 3.11+, TypeScript, JavaScript |
| **Frameworks** | FastAPI, React 18, Tailwind CSS, Vite |
| **IBM Technologies** | IBM watsonx.ai (Granite-3-8B-Instruct), IBM Bob AI Assistant |
| **Other** | Uvicorn, Simulated SIEM alert data |

---

 Repository Structure

```
├── src/
│   ├── backend/              # FastAPI Python backend + AI analysis engine
│   │   ├── main.py           # API entry point
│   │   ├── alerts.py         # Simulated alert data + seed generator
│   │   ├── correlator.py     # Alert correlation & risk scoring engine
│   │   ├── analyzer.py       # MITRE ATT&CK mapping + classification
│   │   ├── watsonx_client.py # IBM watsonx.ai BLUF summary integration
│   │   └── requirements.txt
│   ├── frontend/             # React + Tailwind SOC dashboard
│   │   ├── src/
│   │   │   ├── App.tsx
│   │   │   ├── components/   # Dashboard, AlertList, AlertDetail, FilterBar
│   │   │   └── types.ts
│   │   ├── package.json
│   │   └── vite.config.ts
│   └── .env.example
├── docs/
│   ├── problem-statement.md
│   ├── solution-overview.md
│   ├── architecture.md
│   └── setup-guide.md
├── demo/
│   ├── screenshots/
│   └── demo-video-link.txt
├── presentation/
├── submission.yaml
└── CONTRIBUTING.md
```

---

 How to Run

See [`docs/setup-guide.md`](docs/setup-guide.md) for full instructions.

```bash
# 1. Clone the repo
git clone https://github.com/your-org/bob-ai-hackathon-cyberguard.git
cd bob-ai-hackathon-cyberguard

# 2. Backend — Python 3.11+
cd src/backend
pip install -r requirements.txt
cp ../.env.example ../.env   # then edit .env with your watsonx.ai keys
uvicorn main:app --reload --port 8000

# 3. Frontend — Node.js 18+ (new terminal)
cd src/frontend
npm install
npm run dev
```

Open **http://localhost:5173** — the dashboard connects to the backend at **http://localhost:8000**.

> **No API keys required to run in demo mode.** Without a watsonx.ai key the app uses a rule-based fallback for BLUF summaries. All alert data is simulated.

---

 Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🌐 Live Demo | [See demo/live-demo-url.txt](demo/live-demo-url.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/](presentation/) |

---

 Known Limitations

- Alert data is simulated, not ingested from a live SIEM or EDR platform.
- The watsonx.ai BLUF summary requires a valid IBM Cloud API key; a rule-based fallback activates automatically when no key is provided.
- Correlation logic uses heuristic time-window and IP-overlap rules rather than a trained clustering model.
- Not hardened for production deployment (no auth, no rate limiting).

---

 What We're Most Proud Of

The end-to-end AI pipeline: raw noisy alerts enter, and within seconds the analyst sees correlated attack clusters, MITRE ATT&CK technique tags, a risk score, a human-readable BLUF summary, and concrete recommended actions — all running locally with no external dependencies beyond watsonx.ai. **IBM Bob** was integral to the development workflow, used to generate boilerplate, make architecture decisions, write documentation, and rapidly iterate on the correlation and scoring logic.

---
