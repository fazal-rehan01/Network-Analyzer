# Architecture

## TL;DR

```
Traffic Simulation
        ↓
Controlled Network Traffic
        ↓
Packet Capture / PCAP
        ↓
 ┌───────────────┬───────────────┐
 │ TShark        │ Zeek          │
 │ / Wireshark   │               │
 └───────┬───────┴───────┬───────┘
         ↓               ↓
       Parsed Network/Event Data
                 ↓
          Normalization Layer
                 ↓
           Detection Engine
                 ↓
              Database
                 ↓
             FastAPI API
                 ↓
          React Dashboard
```

The system is a **modular monorepo** with three top-level concerns:

- `backend/` — Python / FastAPI application (analysis, detection, persistence, API).
- `frontend/` — React + TypeScript + Vite single-page app (SOC-style UI).
- `docs/` — architecture, API, rules, simulation, setup, demo.

The **frontend never talks to shell commands**. All analysis happens server-side; the API exposes clean typed resources.

---

## Design Principles

1. **Real data, not fake counters.** Wherever technically possible we generate real traffic (Scapy + stdlib sockets) and analyze real packets with TShark/Zeek. The dashboard renders actual stored data.
2. **Graceful degradation.** TShark, Zeek, Docker are each optional. A health/tool-status endpoint reports availability; missing tools degrade only the affected feature, never the whole app.
3. **Safe, defensive by design.** Simulation targets default to localhost / private lab IPs / Docker. No feature attacks arbitrary public systems.
4. **Explainable detection.** Rule-based engine with configurable thresholds and evidence. Wording like "Possible Port Scan", not "malware detected" without evidence.
5. **No shell-string injection.** Subprocesses are spawned with argument arrays and strict timeouts/cleanup.

---

## Data Flow (PCAP Upload Example)

```
User uploads foo.pcap
        ↓
File upload → validate (extension, size, MIME, sanitize filename)
        ↓
Save to storage/uploads/<uuid>.pcap
        ↓
Create Capture + AnalysisJob (status=parsing)
        ↓
TShark parse  ──► normalized Packet rows (metadata only)
        ↓
Zeek process (if available) ──► conn/dns/http/ssl/notice rows
        ↓
Normalization merges TShark + Zeek views into shared Connection/DNS/HTTP models
        ↓
Detection engine runs → Alerts
        ↓
Update Capture + AnalysisJob (status=done)
        ↓
Dashboard / Packets / Zeek / Compare / Alerts read from DB
```

---

## Backend

### Stack
- **FastAPI** + **Pydantic** (v2) for the REST API and schemas.
- **SQLAlchemy 2.x** (ORM) with **SQLite** default for local dev and **PostgreSQL** option.
- **Scapy** for traffic generation / crafting packets.
- **stdlib `socket`, `subprocess`, `threading`** for real traffic and tool orchestration.

### Layers (`backend/app/`)
| Layer | Dir | Responsibility |
|-------|-----|----------------|
| API | `api/v1` | HTTP routes, request validation, auth-friendly |
| Core | `core` | config (pydantic-settings), DB session, dependencies |
| Models | `models` | SQLAlchemy tables |
| Schemas | `schemas` | Pydantic request/response models |
| Services | `services` | orchestration (simulation runs, capture jobs, report generation) |
| Simulation | `simulation` | scenario implementations (one file per scenario) |
| Analysis | `analysis` | tshark + zeek subprocess/parsers |
| Detection | `detection` | rule engine + rules |
| Utils | `utils` | subprocess safety, tool detection, filtering, sizing |

### Key API namespaces (see `docs/api.md`)
- `GET /api/v1/health` — app + DB status.
- `GET /api/v1/system/status` — TShark/Zeek/Docker/Python availability.
- `GET/POST /api/v1/simulations`, `POST /api/v1/simulations/{id}/start|stop`
- `GET/POST /api/v1/captures`, `POST /api/v1/captures/{id}/start|stop|save`
- `POST /api/v1/captures/upload`
- `GET /api/v1/packets`, `/connections`, `/dns`, `/http`
- `GET /api/v1/zeek/logs`, `POST /api/v1/zeek/process`
- `GET /api/v1/alerts`, `PATCH /api/v1/alerts/{id}`
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/compare`
- `POST /api/v1/reports`

### Data model (core tables)
- `captures` — metadata about a capture/upload (name, source, duration, byte/packet counts).
- `analysis_jobs` — status tracking of analysis pipelines.
- `packets` — **normalized metadata** (ts, src/dst ip+port, proto, len, tcp flags, dns/http/icmp details). Raw payloads are **not** stored; reference to the PCAP file is kept.
- `connections` — 5-tuple flows built by normalization (aggregation of packets / matching Zeek conn.log).
- `dns_events`, `http_events`, `ssl_events` — protocol-specific normalized events (from both TShark and Zeek).
- `alerts` — detection output with type/severity/source/dest/timestamp/reason/evidence/status.
- `simulations` — scenario runs + generated-stats.
- `reports` — generated report records + path.

---

## Frontend

### Stack
- **React 18** + **TypeScript** + **Vite**.
- **Tailwind CSS** for styling (SOC-style dark theme).
- **Recharts** for charts.

### Pages
1. **Dashboard** — KPI cards, protocol donut, top talkers, conversations, traffic-over-time, recent alerts.
2. **Simulation** — scenario cards with start/stop, status, live stats.
3. **Packets** — table with filter/search/detail drawer.
4. **Zeek** — event/connection logs with defensive rendering.
5. **Compare** — Wireshark(TShark) vs Zeek correlation view.
6. **Alerts** — severity/status management + evidence drill-down.
7. **Reports** — generate/download.
8. **System** — tool availability + capture interface selection.

### Data fetching
- Thin typed API client in `frontend/src/api`.
- React hooks for polling (simulation/capture state) and mutations.

---

## Detection Engine (`backend/app/detection`)

Rule-based and explainable. Each rule defines: id, name, type, severity, thresholds, and an `evaluate(context) -> list[Alert]` that records concrete evidence.

Initial rules:
- `port_scan` — many distinct destination ports, same source→same target, short window.
- `connection_burst` — unusually high connection count in a window.
- `dns_anomaly_high_rate` — high DNS query rate in a window.
- `dns_anomaly_nxdomain` — abnormal NXDOMAIN ratio.
- `dns_anomaly_high_domains` — unusually high unique-domain count.
- `unusual_protocol` — unusual protocol/port combinations.

Thresholds are configurable (env or API).

---

## Milestone Plan

1. **M1** Skeleton: repo init, structure, `.gitignore`, README, this architecture doc, `docs/*`, tooling scaffolding. ✅
2. **M2** Backend: config, DB engine, SQLAlchemy models, health + system-status endpoints, pytest scaffold. ✅
3. **M3** Frontend shell: Vite+React+TS+Tailwind, layout/nav, dashboard skeleton, health call to backend. ✅
4. **M4** Simulation engine: abstract `Scenario` base + registry + runner + API + DB records. ✅
5. **M5** Real traffic: implement normal/http/dns/icmp/port_scan/burst/data_transfer/anomalies with Scapy+sockets. ✅
6. **M6** TShark: live capture manager (interfaces, start/stop/save, filter, timeout, cleanup). ✅
7. **M7** PCAP upload + TShark packet parser → normalized packets. ✅
8. **M8** Zeek integration + defensive log parsers. ✅
9. **M9** Normalization/correlation (packets→connections, TShark↔Zeek). ✅
10. **M10** Detection engine + rules + tests. ✅
11. **M11** Alerts/incidents endpoints + UI. ⏳
12. **M12** Dashboard analytics + charts (real data). ⏳
13. **M13** Compare page. ⏳
14. **M14** Reporting (PDF). ⏳
15. **M15** E2E integration testing. ⏳
16. **M16** UI polish, error/empty/loading states, performance. ⏳
17. **M17** Final docs + validation. ⏳
