# End-to-End Security Analysis Workflow Test (MILESTONE 15)

## What it proves

`tests/test_e2e_workflow.py` drives one **real PCAP** through the entire public
API in a single deterministic workflow — proving the pipeline works end to end
with genuinely produced data, not synthetic mocks:

```
PCAP ─▶ capture(normalize) ─▶ detect ─▶ incident ─▶ analytics ─▶ compare ─▶ report(PDF)
```

1. **Build a real PCAP** (TCP SYNs to distinct ports + NXDOMAIN DNS responses).
2. **Normalize** it with the installed TShark via the M9 pipeline
   (`normalize_capture`) → real `Packet`/`Connection`/`DnsEvent` rows.
3. **Detect** (`POST /detect/run`) → findings whose `evidence` ids point at the
   actual normalized rows.
4. **Incident** (`POST /incidents/from-finding`) → a real incident whose
   evidence resolves to the real connection records; listed via the API.
5. **Analytics** (per-capture scope) → counters match the real processed data.
6. **Compare** (`GET /compare/capture/{id}`) → per-connection correlation
   statuses are honest (`both`/`tshark_only`/`zeek_only`), packet-level detail
   shows the real matched frames.
7. **Report** (`POST /reports/generate`) → a valid, substantial `%PDF` for that
   capture, and the capture appears in `/reports/options`.

Plus a second test asserting `/compare/status` tools and whole-database report
generation are always reachable.

## Running

```bash
cd backend
.venv/Scripts/python -m pytest tests/test_e2e_workflow.py -v
```

The workflow test skips automatically when TShark is not installed (it
genuinely parses a PCAP, so no fake modes).

## Honesty invariants asserted

- Detection evidence ids exist in the DB (real references).
- Correlation statuses are only truthful values; TShark packets/conn rows
  reflect actual parsed frames.
- The generated PDF is a valid `application/pdf` document with real size —
  never a stub.
- Everything is scoped to the created capture, so the suite stays deterministic
  on the shared test database.