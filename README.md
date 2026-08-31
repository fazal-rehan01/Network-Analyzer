# Network Traffic Analyzer & Attack Simulation Dashboard

A professional, defensible cybersecurity project that generates real controlled network traffic, captures and analyzes packets with **TShark/Wireshark** and **Zeek**, stores normalized metadata in a database, runs an explainable rule-based detection engine, and exposes everything through a modern React dashboard.

> **Lab-only tool.** All attack simulations run only against localhost, Docker containers, or explicitly controlled lab targets. This is a *defensive* learning/analysis platform — it does not target arbitrary public systems.

---

## Status / Milestones

Development proceeds in small, independently verifiable milestones. Tracked in `docs/architecture.md` and mirrored in git history.

| # | Milestone | Status |
|---|-----------|--------|
| 1 | Repository audit + architecture + project skeleton | ✅ Done |
| 2 | Backend foundation + database + health checks | 🔄 In progress |
| 3 | Frontend shell + navigation + dashboard skeleton | ⏳ |
| 4 | Simulation engine | ⏳ |
| 5 | Real controlled traffic generation | ⏳ |
| 6 | TShark integration + packet capture | ⏳ |
| 7 | PCAP upload + packet parsing | ⏳ |
| 8 | Zeek integration + log parsing | ⏳ |
| 9 | Normalization/correlation layer | ⏳ |
| 10 | Detection engine + rules | ⏳ |
| 11 | Alerts/incidents | ⏳ |
| 12 | Dashboard analytics + charts | ⏳ |
| 13 | Wireshark vs Zeek comparison | ⏳ |
| 14 | Reporting | ⏳ |
| 15 | End-to-end integration testing | ⏳ |
| 16 | UI polish + error handling + performance | ⏳ |
| 17 | Final documentation + validation | ⏳ |

---

## Project Overview

**Traffic Simulation → Controlled Traffic → Packet Capture/PCAP → {TShark, Zeek} → Parsed Data → Normalization → Detection Engine → Database → FastAPI → React Dashboard**

The whole system is modular: the frontend talks only to the FastAPI API and never to shell commands directly.

### Major features

1. **Dashboard** — totals, throughput, protocol distribution, top talkers, top conversations, traffic-over-time, recent alerts (from real analyzed data).
2. **Traffic Simulation Center** — 8 scenarios (normal, HTTP, DNS, ICMP, port scan, connection burst, large data transfer, DNS anomaly).
3. **Real traffic generation** — actual localhost/lab traffic via Scapy and stdlib sockets (never faked).
4. **Packet capture** — TShark-driven live capture with interface selection, duration, filter, save PCAP.
5. **PCAP upload** — validated upload → TShark parse → (Zeek) → normalize → detect → DB → dashboard.
6. **Wireshark/TShark analysis** — normalized packet model, filters, search, protocol stats, top talkers, conversations, details.
7. **Zeek analysis** — defensive parsing of conn/dns/http/ssl/files/notice logs with graceful degradation.
8. **Wireshark vs Zeek comparison** — same traffic from two perspectives, correlated evidence per connection/incident.
9. **Threat/anomaly detection** — explainable rule-based detection with configurable thresholds (no fake AI claims).
10. **Alerts/incidents** — severity, status workflow (New/Investigating/Contained/Resolved/False Positive), evidence, notes.
11. **Reporting** — exportable PDF report covering capture, simulation, traffic summary, detection, both analyses, comparison, recommendations.

---

## Prerequisites

| Tool | Versions tested | Purpose |
|------|-----------------|---------|
| Python | 3.12 | Backend (FastAPI, SQLAlchemy, Scapy) |
| Node.js | 24 | Frontend (Vite, React, TS, Tailwind) |
| npm | 11 | Frontend package manager |
| TShark/Wireshark | 4.6.x | Packet capture + analysis |
| Zeek (optional) | — | Event/connection analysis |
| Docker (optional) | — | Containers for lab targets |
| Git | 2.55 | Version control |

See `docs/setup.md` for full install instructions for each OS.

---

## Quick Start (Windows)

```powershell
# 1. Backend
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# 2. Frontend (new terminal)
cd frontend
npm install
npm run dev
```

Then open http://localhost:5173 (dashboard calls http://localhost:8000).

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
    api/v1/        # FastAPI routes (health, simulation, capture, pcap, zeek, detect, alerts, reports, dashboard)
    core/          # config, security, dependencies
    models/        # SQLAlchemy models
    schemas/       # Pydantic schemas
    services/      # orchestration logic
    simulation/    # scenario implementations (normal, http, dns, ...)
    analysis/      # tshark, zeek parsers
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

## Project Limitations

- **Zeek is optional.** If not installed, the app reports it as unavailable and keeps everything else functional.
- The app supports **SQLite** out of the box for local dev; **PostgreSQL** config is provided via `DATABASE_URL`/Docker compose.
- Live capture requires TShark and a usable capture interface (Npcap on Windows).
- Detection is **rule-based and explainable** by design — it flags *patterns* (port scan, connection burst, DNS anomaly), not definitive malware.

---

## Documentation

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/api.md`](docs/api.md)
- [`docs/detection-rules.md`](docs/detection-rules.md)
- [`docs/simulation.md`](docs/simulation.md)
- [`docs/setup.md`](docs/setup.md)
- [`docs/demo.md`](docs/demo.md)
