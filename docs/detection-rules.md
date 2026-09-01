# Detection Rules

> Populated in MILESTONE 10. Documents each rule: id, name, severity, thresholds, and the evidence collected.

## Design

All detection is **rule-based and explainable**. No unsubstantiated claims. Closing wording like "Possible Port Scan", "Suspicious DNS Activity", "Abnormally High Connection Rate".

Rules read from normalized packets/connections/DNS events (M9) and produce findings (alerts) with concrete `evidence` referencing the normalized records they were derived from. No AI. No fabricated counts.

### Configuration

Thresholds are configurable via environment variables / `.env` (values below are defaults):

| Env var | Default | Meaning |
|---------|---------|---------|
| `DETECT_PORTSCAN_MIN_PORTS` | 10 | Distinct TCP destination ports from one source to flag a scan |
| `DETECT_CONN_RATE_WINDOW_SEC` | 10 | Sliding window (seconds) for connection-rate |
| `DETECT_CONN_RATE_MAX_PER_WINDOW` | 100 | Max connection starts allowed inside the window |
| `DETECT_DNS_NXDOMAIN_MIN` | 5 | NXDOMAIN responses required before flagging DNS anomaly |
| `DETECT_DNS_QUERY_DIVERSITY_MIN` | 50 | Unique queries from one source before flagging diversity |
| `DETECT_SEVERITY_HIGH_MULTIPLIER` | 2.0 | observed/threshold ratio that escalates to `high` |
| `DETECT_SEVERITY_CRITICAL_MULTIPLIER` | 4.0 | observed/threshold ratio that escalates to `critical` |

### Severity

Severity starts at each rule's base severity and is scaled deterministically by how far the observed value exceeds the threshold (ratio = observed / threshold). Base severities stay `low`/`medium` unless the ratio reaches the escalation multipliers above.

## Rules

### `port_scan` — Possible Port Scan (base: medium)
A single source IP contacts **N distinct TCP destination ports** (N >= `portscan_min_ports`).
- Evidence: the matching normalized `Connection` records (type `connection`, with connection ids).

### `conn_rate` — Abnormal Connection Rate (base: medium)
The peak number of connection starts inside any sliding window of `conn_rate_window_sec` seconds exceeds `conn_rate_max_per_window`.
- Evidence: up to 10 referenced `Connection` records in the busiest window.

### `dns_anomaly` — Possible DNS Anomaly (base: medium)
At least `dns_nxdomain_min` NXDOMAIN responses observed. Frequent NXDOMAIN can indicate domain-generation algorithms (DGA) or DNS reconnaissance.
- Evidence: the matching normalized `DnsEvent` records (type `dns`).

### `dns_query_diversity` — High DNS Query Diversity (base: low)
A single source resolves at least `dns_query_diversity_min` unique query names. High query diversity can indicate DNS tunneling or reconnaissance.
- Evidence: referenced `DnsEvent` records for that source.

### `high_data_transfer` — Large Data Transfer (base: low)
A single connection transfers at least 10,000,000 bytes. Large egress on one flow can indicate exfiltration.
- Evidence: the referenced `Connection` record.

## Endpoints (M10)

- `GET /api/v1/detect/rules` — list registered rules + default severity
- `POST /api/v1/detect/run?capture_id={id}` — run all rules over a capture's normalized data (idempotent) and persist findings
- `GET /api/v1/detect/findings?capture_id={id}&severity={s}&limit={n}` — query persisted findings (optionally by severity)
- `GET /api/v1/detect/summary?capture_id={id}` — severity summary of persisted findings
