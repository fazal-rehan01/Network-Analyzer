# Network Traffic Analyzer & Attack Simulation Dashboard

A professional, defensible cybersecurity project that generates real controlled network traffic, captures and analyzes packets with **TShark/Wireshark** and **Zeek**, stores normalized metadata in a database, runs an explainable rule-based detection engine, and exposes everything through a modern React dashboard.

> **Lab-only tool.** All attack simulations run only against localhost, Docker containers, or explicitly controlled lab targets. This is a *defensive* learning/analysis platform — it does not target arbitrary public systems.

---

## Quick Demo

The complete end-to-end demonstration in the exact order:

1. **Start backend** — `cd backend && .\.venv\Scripts\Activate.ps1 && python -m uvicorn app.main:app --reload --port 8000`
2. **Start frontend** — `cd frontend && npm run dev` (in a new terminal)
3. **Open the dashboard** — http://localhost:5173
4. **Open Simulation** — Navigate to the Simulation page
5. **Set lab target** to `127.0.0.1` (the default)
6. **Open Capture** — Navigate to the Capture page
7. **Select the Npcap Loopback Adapter** on Windows (or loopback on Linux)
8. **Start a live capture** — click "Start Capture"
9. **Return to Simulation** — keep the capture running
10. **Run `Port Scan Simulation`** — click "Run scenario" on the Port Scan card
11. **Let the simulation finish** — watch the status go `queued` → `running` → `completed`
12. **Return to Capture and verify** — stop the capture; the PCAP row appears with packet count > 0
13. **Open Correlated** — Navigate to the Correlated page
14. **Select the new capture** — pick the capture you just created
15. **Run Normalization** — click "Run Normalization" (TShark parses → normalized records created)
15. **Open Packets and inspect** — Navigate to Packets page; inspect normalized TShark packet evidence
16. **Open Detect** — Navigate to the Detect page
17. **Run Detection** — click "Run Detection" on the selected capture
18. **Verify `Possible Port Scan` finding** — when traffic matches the detection rule, a finding appears with evidence
19. **Open the finding's evidence** — click the finding to see referenced connection records
20. **Open Incidents** — Navigate to Incidents page
21. **Promote the detection finding to an incident** — click "Create Incident" on the finding
22. **Demonstrate the incident lifecycle**:
    `NEW` → `INVESTIGATING` → `CONTAINED` → `RESOLVED`
23. **Add an investigation note** — open the incident and add a note
24. **Open Dashboard and verify** — analytics reflect the real analyzed data (packets, connections, incidents)
25. **Open Compare and inspect** — TShark vs Zeek analysis (Zeek shows as unavailable if not installed)
26. **Open Reports and generate the PDF report** — whole-database or per-capture

---

## What an Evaluator Should Verify

The project demonstrates this pipeline:

```
Simulation
    → Live Traffic
        → TShark/PCAP
            → Normalization
                → Detection
                    → Incident
                        → Analytics
                        → TShark vs Zeek Comparison
                        → Report
```

**What is real (not faked):**

- **Traffic generation** — real controlled localhost/lab traffic via Scapy and stdlib sockets
- **TShark captures** — real packets on the wire (Npcap loopback on Windows)
- **PCAP parsing** — TShark parses uploaded or captured PCAPs into structured data
- **Normalized records** — come from parsed TShark/Zeek traffic, correlated by 5-tuple + time + UID
- **Detections** — rule-based, explainable, with evidence references back to normalized records
- **Incidents** — persisted in the database with full lifecycle and audit history
- **Dashboard analytics** — computed from database data (counts, rates, distributions, charts)
- **Reports** — generated from stored project data (professional PDF via reportlab)

---

## Zeek Runtime Note

**Zeek integration and log parsing are implemented.**

If the Zeek executable is **not installed** on the host machine, the application reports Zeek as unavailable instead of fabricating results. The application can still analyze TShark/PCAP data, and Zeek-format fixtures are available for parser/correlation testing when a live Zeek runtime is unavailable.

**Make no mistake:**

- **TShark runtime is required** for live packet capture and PCAP parsing.
- **Zeek runtime is optional.** The Comparison UI honestly reports unavailable states.
- **No fake Zeek events** are ever claimed or generated.
- **Live Zeek execution on Windows has not been verified** — the code path exists but is untested on Windows in this environment.

---

## Quick Start (Windows)

### Terminal 1 — Backend

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --port 8000
```

### Terminal 2 — Frontend

```powershell
cd frontend
npm install
npm run dev
```

Then open **http://localhost:5173** (dashboard calls **http://localhost:8000**).

> **Note:** If the virtual environment doesn't exist, create it first:
> ```powershell
> cd backend
> python -m venv .venv
> .\.venv\Scripts\Activate.ps1
> pip install -r requirements.txt
> ```

---

## Environment Variables

Copy `backend/.env.example` → `backend/.env` and adjust. See `docs/setup.md`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | `sqlite:///./traffic.db` | SQLAlchemy DB URL |
| `TSHARK_PATH` | auto-detect | Path to tshark binary |
| `ZEEK_PATH` | auto-detect | Path to zeek binary |
| `STORAGE_DIR` | `backend/storage` | Uploads, pcap, reports, zeek logs |
| `MAX_UPLOAD_MB` | 100 | Max PCAP upload size |

---

## Development / Testing Commands

```powershell
# Backend tests
cd backend
.\.venv\Scripts\Activate.ps1
pytest -v

# Frontend typecheck + lint + build
cd frontend
npm run typecheck
npm run lint
npm run build
```

---

## Project Structure

```
backend/
  app/
    api/v1/        # FastAPI routers (system, simulations, captures, normalize, zeek, detect, incidents, analytics, compare, reports)
    core/          # config, security, dependencies
    models/        # SQLAlchemy models
    schemas/       # Pydantic schemas
    services/      # orchestration & domain services (capture, normalize, detect, incident, analytics, compare, report, zeek)
    analysis/      # external tool parsers (tshark, zeek)
    detection/     # rule engine
    utils/         # subprocess, tools detection, filtering
  tests/
  storage/         # pcaps, uploads, reports, zeek logs (gitignored)
frontend/
  src/
    components/    # charts, tables, badges, dialogs
    pages/         # dashboard, simulation, packets, zeek, compare, alerts, reports, settings
    api/           # typed API client
    hooks/         # data fetching, polling
docs/              # architecture, api, detection-rules, simulation, setup, demo
```

---

## Project Limitations

- **Zeek is optional.** If not installed, the app reports it as unavailable and keeps everything else functional.
- The app supports **SQLite** out of the box for local dev; **PostgreSQL** config is provided via `DATABASE_URL`/Docker compose.
- Live capture requires TShark and a usable capture interface (Npcap on Windows).
- Detection is **rule-based and explainable** by design — it flags *patterns* (port scan, connection burst, DNS anomaly), not definitive malware.

---

## Documentation

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/api.md`](docs/api.md)
- [`docs/simulation.md`](docs/simulation.md)
- [`docs/detection-rules.md`](docs/detection-rules.md)
- [`docs/incidents.md`](docs/incidents.md)
- [`docs/comparison.md`](docs/comparison.md)
- [`docs/reporting.md`](docs/reporting.md)
- [`docs/e2e-testing.md`](docs/e2e-testing.md)
- [`docs/polish.md`](docs/polish.md)
- [`docs/validation.md`](docs/validation.md)
- [`docs/setup.md`](docs/setup.md)
- [`docs/demo.md`](docs/demo.md)

---

## Status / Milestones

Development proceeds in small, independently verifiable milestones. Tracked in `docs/architecture.md` and mirrored in git history.

| # | Milestone | Status |
|---|-----------|--------|
| 1 | Repository audit + architecture + project skeleton | ✅ Done |
| 2 | Backend foundation + database + health checks | ✅ Done |
| 3 | Frontend shell + navigation + dashboard skeleton | ✅ Done |
| 4 | Simulation engine | ✅ Done |
| 5 | Real controlled traffic generation | ✅ Done |
| 6 | TShark integration + packet capture | ✅ Done |
| 7 | PCAP upload + packet parsing | ✅ Done |
| 8 | Zeek integration + log parsing | ✅ Done |
| 9 | Normalization/correlation layer | ✅ Done |
| 10 | Detection engine + rules | ✅ Done |
| 11 | Alerts/incidents | ✅ Done |
| 12 | Dashboard analytics + charts | ✅ Done |
| 13 | Comparison page | ✅ Done |
| 14 | Reporting | ✅ Done |
| 15 | E2E workflow tests | ✅ Done |
| 16 | UI polish + error handling + performance | ✅ Done |
| 17 | Final documentation + validation | ✅ Done |