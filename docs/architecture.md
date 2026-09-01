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
- `detection_findings` — M10 detection output (rule, severity, score, summary, detail, evidence refs).
- `incidents` — analyst-facing incident created *from* a detection finding (snapshot of severity/rule/evidence + lifecycle timestamps, status, assignee, resolution). Idempotency is enforced via a unique `detection_finding_id` and a deterministic `occurrence_key`.
- `incident_notes` — investigation note timeline per incident.
- `incident_events` — audit/history log of meaningful lifecycle changes (created, status_changed, assigned, note_added, resolved, marked_false_positive, reopened).
- `simulations` — scenario runs + generated-stats.
- `reports` — generated report records + path.

---

## Frontend

### Stack
- **React 18** + **TypeScript** + **Vite**.
- **Tailwind CSS** for styling (SOC-style dark theme).
- **Recharts** for charts.

### Pages
1. **Dashboard** — KPI cards + charts (traffic over time, protocol distribution, top talkers, detection/incident severity, DNS/HTTP activity) backed by real aggregation endpoints; global or per-capture scope.
2. **Simulation** — scenario cards with start/stop, status, live stats.
3. **Packets** — table with filter/search/detail drawer.
4. **Zeek** — event/connection logs with defensive rendering.
5. **Compare** — dedicated Wireshark/TShark (packet-level) vs Zeek (event-level) comparison: capture selector, per-connection correlation status (both / TShark only / Zeek only), side-by-side evidence tables, honest tool-unavailable states.
6. **Incidents** — SOC queue + detail (status/severity workflow, evidence, notes, history).
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

## Incident Management (`backend/app/incidents`)

M11 consumes M10 **DetectionFinding** rows (it does not re-do detection). Findings can be promoted
into **Incident** records either individually (`POST /incidents/from-finding`) or en-masse for a
capture (`POST /incidents/from-capture`).

### Data flow

```
Simulation / PCAP -> TShark -> Zeek -> Normalization (M9)
   -> DetectionFinding (M10) -> Incident (M11) -> Analyst investigation -> Resolve / False Positive
```

An incident snapshots the finding's severity, rule, capture, summary, detail and **evidence
references**, and keeps the `detection_finding_id` for full traceability. Evidence references are
resolved back to the actual normalized `connection`/`dns`/`http`/`packet` records on demand (never
raw payloads).

### Idempotency / deduplication
- `incidents.detection_finding_id` is unique — promoting the same finding twice returns the existing
  incident.
- `incidents.occurrence_key` is a deterministic fingerprint of `(capture, rule, sorted evidence ids)`
  so a finding re-emitted by a detection re-run maps to the same incident instead of creating copies.

### Status lifecycle
```
NEW -> INVESTIGATING -> CONTAINED -> RESOLVED
                 \         |
                  \        v
                   -> FALSE_POSITIVE
```
Reopen is supported and deliberate: `RESOLVED -> INVESTIGATING`, `FALSE_POSITIVE -> INVESTIGATING`,
and `CONTAINED -> INVESTIGATING`. Transitions are validated server-side (`ALLOWED_TRANSITIONS` in
`app/core/enums.py`) and rejected (400) otherwise; unknown statuses return 422.

### Key files
- `backend/app/models/incident.py` — `Incident`, `IncidentNote`, `IncidentEvent` (+ indexes).
- `backend/app/services/incident.py` — creation, idempotency, transitions, notes, history, dashboard summary.
- `backend/app/api/v1/incidents.py` — REST endpoints.
- `backend/app/core/enums.py` — centralized statuses/severities/transition map.
- `frontend/src/pages/IncidentsPage.tsx` — SOC incidents queue + detail panel.

## Dashboard Analytics (`backend/app/analytics`)

Aggregations are computed **server-side from the real database** by a single
`GET /analytics/dashboard` endpoint (global or per-capture via `?capture_id=`).
There is no second analytics data layer and no fabricated numbers — every value
traces to persisted captures/packets/connections/dns/http/detections/incidents.

### Efficiency
- Counts/sums use SQL `GROUP BY`; only top-N rows are returned to the browser.
- Traffic-over-time is bucketed per second and downsampled to at most 120 points
  so a large capture never floods the frontend.
- No N+1 patterns: per-capture vs global reuse the same queries with an optional
  capture filter.

### Key files
- `backend/app/services/analytics.py` — all aggregation helpers.
- `backend/app/api/v1/analytics.py` — `GET /analytics/dashboard`.
- `backend/app/schemas/analytics.py` — typed payload schemas.
- `frontend/src/pages/Dashboard.tsx` — KPI cards + recharts visualizations.

## Wireshark/TShark vs Zeek Comparison (`backend/app/compare`)

The comparison page answers: "for the same traffic, what does packet-level
analysis show vs what does event-level analysis show?" It is honest by design:

- The **TShark side** renders only real packet evidence (frame number, ts,
  src/dst, protocol, ports, length, TCP flags) matched to a normalized
  connection by its 5-tuple.
- The **Zeek side** renders only real conn.log (service, conn state, duration,
  orig/resp bytes), DNS, HTTP, SSL and notice events correlated to that
  connection via ``zeek_uid`` / ``connection_id`` / address pair.
- Per-connection **correlation status** is one of `both`, `tshark_only`,
  `zeek_only` — never a fabricated pairing. When Zeek is not installed the
  TShark side still works and the Zeek side is shown as absent.

### Endpoints
- `GET /compare/status` — tshark/zeek availability.
- `GET /compare/capture/{capture_id}` — summary + per-connection correlation rows.
- `GET /compare/connection/{connection_id}` — full side-by-side evidence.

### Key files
- `backend/app/services/compare.py` — correlation status + evidence snapshots.
- `backend/app/api/v1/compare.py` — endpoints.
- `backend/app/schemas/compare.py` — payload schemas.
- `frontend/src/pages/ComparePage.tsx` — comparison UI.

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
11. **M11** Alerts/incidents endpoints + UI. ✅
12. **M12** Dashboard analytics + charts (real data). ✅
13. **M13** Compare page. ✅
14. **M14** Reporting (PDF). ⏳
15. **M15** E2E integration testing. ⏳
16. **M16** UI polish, error/empty/loading states, performance. ⏳
17. **M17** Final docs + validation. ⏳
