# Source Code

## Structure

```
src/
  backend/              # FastAPI Python backend + AI analysis engine
  │  main.py            # API entry point (uvicorn main:app)
  │  alerts.py          # Simulated SIEM alert store (50 alerts)
  │  correlator.py      # Alert correlation engine
  │  analyzer.py        # Risk scoring, MITRE ATT&CK mapping, classification
  │  watsonx_client.py  # IBM watsonx.ai BLUF summary integration
  │  requirements.txt
  │  tests/
  │     test_backend.py
  frontend/             # React 18 + Tailwind CSS SOC dashboard
  │  src/
  │     App.tsx         # Main application component
  │     main.tsx        # Entry point
  │     api.ts          # Backend HTTP client
  │     types.ts        # Shared TypeScript types
  │     index.css       # Tailwind + global styles
  │     components/
  │        StatsBar.tsx      # Summary counts (total, HIGH, MEDIUM, LOW)
  │        FilterBar.tsx     # Severity / source / status / search filters
  │        AlertList.tsx     # Scrollable alert table
  │        AlertDetail.tsx   # Full analysis panel (BLUF, MITRE, score, recs)
  │        RiskGauge.tsx     # Circular SVG risk score indicator
  │  index.html
  │  package.json
  │  vite.config.ts
  │  tailwind.config.js
  .env.example          # Template for environment variables
```

## Running the Backend

```bash
cd src/backend
python -m venv .venv && .venv\Scripts\activate   # Windows
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## Running the Frontend

```bash
cd src/frontend
npm install
npm run dev
```

See [`docs/setup-guide.md`](../docs/setup-guide.md) for full instructions.

## Environment Variables

Copy `.env.example` to `.env` in this directory. See `.env.example` for all available variables.
Only `WATSONX_API_KEY` and `WATSONX_PROJECT_ID` are needed for AI-powered BLUF summaries.
The application runs fully without them — a rule-based fallback is used automatically.
