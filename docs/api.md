# API Reference

> Populated in MILESTONE 2+ as endpoints are implemented. This file documents the FastAPI contract.

## Base URL

`http://localhost:8000/api/v1`

## Health

### `GET /health`
Returns app + database health.

## System

### `GET /system/status`
Returns tool availability (Python, TShark, Zeek, Docker, Npcap).

_(Added in M2)_

## Simulations

### `GET /simulations/scenarios`
List all scenarios with metadata and default configs.

### `GET /simulations`
List the most recent simulation runs.

### `GET /simulations/{id}`
Get a single run, including status and generated-traffic stats.

### `POST /simulations`
Create a simulation run.
```json
{ "scenario": "icmp", "name": "ping", "target": "127.0.0.1", "config": {} }
```
Refuses (400) non-lab targets.

### `POST /simulations/{id}/start`
Start the run in a background thread.

### `POST /simulations/{id}/stop`
Request cooperative stop.

_(Added in M4)_

## Zeek

### `GET /zeek/status`
Reports whether the Zeek binary is installed (`available`) and where Zeek output is stored (`zeek_dir`).

### `POST /zeek/process?capture_id={id}`
Run Zeek over a capture's saved PCAP, parse conn/dns/http/ssl/notice logs, and persist normalized event rows.
Returns `{ available, summary, logs, error, capture_id }`. Gracefully degrades when Zeek is absent (returns
`available: false` and a descriptive `error`, leaving everything else functional).

### `GET /zeek/events?capture_id={id}&log_type={conn|dns|http|ssl|notice}&limit={n}`
Query normalized Zeek events persisted for a capture. Optional `log_type` filter; `log_type` is optional and
unknown values return 400.

_(Added in M8)_

## Normalize / Correlation

### `GET /normalize/status`
Reports whether the underlying evidence tools are available:
`{ "tshark_available": bool, "zeek_available": bool }`.

### `POST /normalize/run?capture_id={id}`
Run the full normalization + correlation pipeline for a capture: parse TShark packets → aggregate into
connections, match Zeek conn rows by canonical 5-tuple, and promote Zeek DNS/HTTP (by UID) and TShark packet
HTTP/DNS hints into shared normalized events. Idempotent (re-runs clear prior normalized rows for the capture).
Returns `{ capture_id, tshark_available, zeek_available, packets_parsed, packets_persisted, connections,
dns_events, http_events, connections_with_zeek, error }`. Degrades gracefully when a tool is absent.

### `GET /normalize/connections?capture_id={id}&limit={n}`
Return normalized 5-tuple connections for a capture, each tagged with its evidence `source` (`tshark`, `zeek`,
or `tshark+zeek`) and an optional correlated `zeek_uid`.

### `GET /normalize/dns?capture_id={id}&limit={n}`
Return normalized DNS events, each tagged with `source` and either a `zeek_uid` or a `packet_ref` for traceability.

### `GET /normalize/http?capture_id={id}&limit={n}`
Return normalized HTTP events, each tagged with `source` and either a `zeek_uid` or a `packet_ref`.

### `GET /normalize/packets?capture_id={id}&limit={n}`
Return normalized per-packet metadata (TShark evidence) for a capture.

_(Added in M9)_

## Detection

### `GET /detect/rules`
List every registered detection rule: `[{ id, name, default_severity }]`.

### `POST /detect/run?capture_id={id}`
Run all detection rules over a capture's normalized data and persist findings. Idempotent (clears prior findings
for the capture, then recomputes). Returns `{ capture_id, findings, rules_evaluated, by_severity }`. Captures with
no normalized data simply yield zero findings (graceful, non-erroring).

### `GET /detect/findings?capture_id={id}&severity={s}&limit={n}`
Query persisted detection findings. Optional `severity` filter (`info|low|medium|high|critical`). Each finding
includes `rule_id`, `rule_name`, `severity`, `score`, `summary`, `detail`, and `evidence` — an array referencing
the normalized records (connection/dns/http) the finding was derived from.

### `GET /detect/summary?capture_id={id}`
Return `{ capture_id, total, by_severity }` for a capture's persisted findings.

_(Added in M10)_

## Incidents (M11)

Incidents are analyst-facing records created from M10 detection findings. Creation is
idempotent: promoting the same finding (or the same deterministic occurrence) never creates
duplicate incidents. Status transitions are validated server-side against an allowed-transition
map and recorded in incident history.

### `GET /incidents?status=&severity=&capture_id=&rule_id=&search=&sort_by=&order=&limit=&offset=`
List incidents with combined filtering, sorting and pagination. Supported filters:
- `status` — one of `NEW|INVESTIGATING|CONTAINED|RESOLVED|FALSE_POSITIVE` (else 422)
- `severity` — one of `info|low|medium|high|critical` (else 422)
- `capture_id`, `rule_id` — exact match
- `search` — substring match on title/summary/detail/rule name
- `sort_by` — `created_at` (default) | `updated_at` | `severity`
- `order` — `desc` (default) | `asc`
- `limit` (default 50, max 500), `offset` (default 0)

Returns `{ items, total, limit, offset }`. Each item is a snapshot with id, title, severity,
status, rule, capture name, timestamps, assignee, resolution.

### `POST /incidents/from-finding`
Body: `{ "detection_finding_id": "...", "title"?, "description"?, "assigned_to"? }`.
Create an incident from an M10 detection finding. Returns
`{ incident, created, skipped, existing }`. Idempotent:
- `created=1` on first creation,
- `created=0, skipped=1, existing=<id>` if an incident already exists for the finding or the same
  logical occurrence (capture + rule + evidence). 404 if the finding is unknown.

### `POST /incidents/from-capture?capture_id={id}`
Promote every finding of a capture into an incident (skipping those that already have one).
Returns aggregate `{ created, skipped, incident }`.

### `GET /incidents/summary`
Dashboard counters computed from the incidents table:
`{ total, open, critical, high, resolved, false_positive, recent }` (recent = newest 5).

### `GET /incidents/{incident_id}`
Full detail: incident fields, linked `detection_finding_id`, the original `evidence` references,
`evidence_resolved` (the actual normalized Connection/DNS/HTTP/Packet records looked up by id —
never raw payloads), `notes` (timeline), and `history` (audit events). 404 if unknown.

### `PATCH /incidents/{incident_id}`
Update an incident. Body may include `title`, `description`, `assigned_to`, `status`,
`resolution`, `resolution_notes`. Status transitions are validated against the allowed-transition
map:
- `NEW → INVESTIGATING`
- `INVESTIGATING → CONTAINED | RESOLVED | FALSE_POSITIVE`
- `CONTAINED → RESOLVED | INVESTIGATING` (reopen)
- `RESOLVED → INVESTIGATING` (reopen), `FALSE_POSITIVE → INVESTIGATING` (reopen)

Entering `RESOLVED`/`FALSE_POSITIVE` sets `closed_at` and `resolution`; reopening clears them.
Invalid transitions return 400; unknown status values return 422. 404 if unknown.

### `POST /incidents/{incident_id}/notes`
Body: `{ "text": "...", "author"? }`. Add an analyst note to the timeline (records a
`note_added` history event). Blank/empty notes return 422. 201 on success.

### `DELETE /incidents/{incident_id}`
Delete an incident (cleanup action). 204 on success, 404 if unknown._(Added in M11)_
