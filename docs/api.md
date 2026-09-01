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
