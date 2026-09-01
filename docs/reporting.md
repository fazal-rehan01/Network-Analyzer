# Security Analysis Reporting (MILESTONE 14)

## Goal

Give the analyst a single, professional PDF that condenses everything the
tooling knows about a capture (or the whole database): what was simulated,
what the traffic looked like, what the detection engine flagged, what both
analysis perspectives saw, how packet-level and event-level evidence correlate,
and what to actually do next.

## Approach

- **reportlab 4.2.x (pure Python)** builds the PDF server-side — no external
  printer/JS, no screenshots, fully deterministic.
- The report is composed **directly from the database and genuine tool
  availability**. There is no fake/static content path:
  - Traffic summary reuses the M12 analytics service.
  - The comparison section reuses the M13 compare service.
  - Detection/recommendations come from persisted `DetectionFinding` and
    `Incident` rows.

## Report structure (8 sections)

| # | Section | Source of truth |
|---|---|---|
| 1 | Capture scope | `Capture` row + summary counters |
| 2 | Simulation history | `Simulation` rows (recent) |
| 3 | Traffic summary | `analytics.dashboard_analytics` (protocols, talkers, conversations, peaks, DNS/HTTP) |
| 4 | Detection findings | `DetectionFinding` severity + latest findings |
| 5 | Packet-level analysis (Wireshark/TShark) | `Packet` rows (protocols, busiest hosts) |
| 6 | Event-level analysis (Zeek) | `ZeekConn/Dns/Http/Ssl/Notice` + normalized DNS/HTTP + service stats |
| 7 | TShark vs Zeek | compare correlation summary + `tshark_available`/`zeek_available` |
| 8 | Recommendations | Derived from the findings present in scope |

## Honest reporting rules

- If Zeek is **not installed**, section 6/7 say so (log counts will be 0) —
  Zeek events are never fabricated.
- If a capture has **no packets** (pure Zeek fixtures), section 5 reports 0
  packet records — it does not invent frames.
- If **no detection findings** exist, section 4 says so explicitly.
- Recommendations are **data-driven**: a `port_scan` finding produces a
  "harden against port scanning" recommendation; open incidents produce a
  "triage" step; high/critical findings produce a remediation step. The list is
  never a generic marketing paragraph.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/reports/options` | Scope options for the UI |
| POST | `/reports/generate` | Returns the PDF (`application/pdf` + attachment filename) |

## UI

`/reports` (sidebar "Reports"): pick "All captures" or a specific capture, click
**Generate PDF**; the browser downloads `traffic-report-<scope>-<timestamp>.pdf`.

## Testing

`test_reports.py` covers:
- generating a report on an empty (global) scope → valid `%PDF` output,
- generating for a rich seeded capture (packets + Zeek conn + DNS/HTTP +
  detection finding + incident) → substantially larger, structurally valid PDF,
- 404 for an unknown capture,
- options endpoint shape + inclusion of a seeded capture,
- global generate with `{}` body works (defaults to whole database).