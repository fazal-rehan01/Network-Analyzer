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
