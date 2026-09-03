# Simulation

## Safety first

All simulation scenarios generate **real** traffic (Scapy + stdlib sockets + HTTP requests) but only ever target **lab endpoints**: localhost, loopback, private/IPv6-local ranges, or explicitly allowed targets. The runner validates the target and **refuses to attack non-lab hosts** (e.g. an arbitrary public IP).

## Architecture

- `app/simulation/base.py` — `Scenario` ABC and `ScenarioContext`.
- `app/simulation/registry.py` — scenario registry + `@register` decorator.
- `app/simulation/runner.py` — background-thread lifecycle runner + `is_safe_target`.
- `app/simulation/_net.py` — shared real-traffic helpers (TCP connect, DNS, ICMP).
- `app/simulation/_localserver.py` — tiny loopback HTTP test server.
- `app/simulation/<scenario>.py` — one file per scenario.
- `app/models/simulation.py` — DB record holding scenario config, status, and stats.
- `app/api/v1/simulations.py` — REST API.

Each scenario defines `key`, `name`, `description`, `default_port`, `suspicious` flag, a `default_config()`, and a `run(ctx)` method.

## Scenarios

| key | name | suspicious | target | description |
|-----|------|-----------|--------|-------------|
| `normal` | Normal Traffic | no | localhost | balanced TCP + DNS + ICMP mix |
| `http` | HTTP Traffic | no | local test server | real HTTP GET/POST |
| `dns` | DNS Traffic | no | resolver | DNS queries for control domains |
| `icmp` | ICMP Traffic | no | localhost | continuous pings |
| `port_scan` | Port Scan Simulation | yes | lab host | TCP connect scan across a port range |
| `connection_burst` | High Connection Rate | yes | lab service | burst of TCP connections |
| `data_transfer` | Large Data Transfer | no | local test server | bulk TCP payload |
| `dns_anomaly` | DNS Anomaly | yes | resolver | high query rate + NXDOMAIN-style queries |

## API

- `GET  /api/v1/simulations/scenarios` — scenario metadata + default configs.
- `GET  /api/v1/simulations` — recent runs.
- `GET  /api/v1/simulations/{id}` — single run details/stats.
- `POST /api/v1/simulations` — create (`scenario`, `target`, `target_port`, `config`).
- `POST /api/v1/simulations/{id}/start` — start in background thread.
- `POST /api/v1/simulations/{id}/stop` — request stop (cooperative cancellation).

Status lifecycle: `idle → running → completed | stopped | failed`.

## Useful config knobs (subset)

- `duration_sec`, `packet_count` / `request_count` / `query_count`
- `interval_ms` / `delay_ms` (rate control)
- `tcp_port` / `port` / `port_start` / `port_end`
- `dns_ratio`, `icmp_ratio`, `tcp_ratio`, `nxdomain_ratio`, `rate_per_sec`

## Example

```bash
POST /api/v1/simulations
{
  "scenario": "port_scan",
  "target": "127.0.0.1",
  "config": { "port_start": 1, "port_end": 200, "delay_ms": 5 }
}
POST /api/v1/simulations/{id}/start
```
