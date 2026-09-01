# Wireshark/TShark vs Zeek Comparison (MILESTONE 13)

## Why compare?

Wireshark/TShark analyzes the **packet level**: every frame with its timestamp,
source/destination, protocol, ports, length and TCP flags. Zeek analyzes the
**connection/event level**: it reconstructs flows (conn.log) with service,
duration and byte counts, and produces typed events for DNS, HTTP, SSL and
notices. The same traffic therefore looks different depending on the tool.

- **Wireshark/TShark** = packet-level visibility ("what appeared on the wire").
- **Zeek** = higher-level network/event visibility ("what happened at the flow /
  application layer").

## How the comparison works

The M9 normalization layer already correlates the two views: each normalized
`Connection` row knows its `source` (`tshark`, `zeek`, or `tshark+zeek`), its
canonical 5-tuple, and — when a Zeek conn.log row matched — its `zeek_uid`.
The comparison feature presents this same traffic **side by side**:

| Aspect | Wireshark / TShark | Zeek |
|---|---|---|
| Focus | Packet-level (frames) | Flow / event-level (conn.log + typed logs) |
| Evidence | frame number, ts, src/dst, proto, ports, length, TCP flags | conn.log (uid, service, conn_state, duration, orig/resp bytes) + DNS / HTTP / SSL / notice events |
| Correlation key | canonical 5-tuple | `zeek_uid` / `connection_id` / address pair |

## Honesty rules

- **Not every packet has a Zeek event** and **not every flow has packets**.
- Per-connection `correlation_status` is one of:
  - `both` — packet + Zeek evidence present,
  - `tshark_only` — only packet evidence (no correlated Zeek event),
  - `zeek_only` — only Zeek event evidence (no/small packet samples).
- When **Zeek is unavailable**, the TShark side keeps working and the Zeek side
  is shown as absent (`present: false`) — Zeek results are never faked.
- `GET /compare/status` reports tool availability honestly from the environment.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/compare/status` | TShark / Zeek availability |
| GET | `/compare/capture/{capture_id}` | Summary + per-connection correlation |
| GET | `/compare/connection/{connection_id}` | Full side-by-side evidence |

## UI

`/compare` (sidebar "Compare"):
1. Select a capture.
2. See availability + summary (connections, both/TShark-only/Zeek-only, packet & event counts).
3. Pick a connection → side-by-side: Wireshark/TShark packet table vs Zeek
   conn + DNS + HTTP + SSL + notices.

## Testing

- Pure-Zeek fixture state (real-format `zeek_*.log` fixtures persisted via Zeek
  service, no packets) → `zeek_only`.
- Pure-TShark state (seeded packets + connection, no Zeek rows) → `tshark_only`.
- Matched state (both) → `both` with DNS evidence linked via `connection_id`.
- Missing connection / capture → 404. `test_compare.py` covers all of the above;
  it runs without Zeek being installed (fixtures simulate Zeek log output).