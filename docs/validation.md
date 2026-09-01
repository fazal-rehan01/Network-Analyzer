# Validation (M17)

Final validation pass for the NetworkChuck security-analysis project. Every milestone was
independently verified before the next began; this document records the end state.

## How every milestone was validated

Each of M1–M16 followed the same loop, so regressions never silently accumulated:

1. **Implement** code + tests for the milestone feature.
2. **Test** the backend suite (`pytest`) and add targeted tests for the new surface.
3. **Fix** anything found before moving on (e.g. M14's `_num()` double-format bug, the M12
   memory/performance issues).
4. **Frontend gates**: `npm run typecheck`, `npm run lint`, `npm run build` (ESLint + strict TS,
   no warnings).
5. **Document** in README / `docs/architecture.md` / `docs/api.md` (+ a focused doc per feature:
   `simulation.md`, `detection-rules.md`, `incidents.md`, `comparison.md`, `reporting.md`,
   `e2e-testing.md`, `polish.md`).
6. **Commit with a milestone message, push to `main`, and verify** that
   `git rev-parse HEAD` == `git rev-parse origin/main` == `git ls-remote origin main`.

## Final automated suite

Backend — `backend/tests/` (session-scoped shared SQLite DB, uuid4-scoped fixtures so files never
interfere with each other's counts):

| Suite (file) | Covers |
|---|---|
| `test_health.py`, `test_system.py`, `test_capture.py`, `test_simulations.py` | API foundation, tool status, capture list/upload lifecycle, 8 scenarios + lifecycle |
| `test_tshark.py`, `test_zeek.py`, `test_normalization.py` | TShark parse (real 4.6.7), Zeek log import from fixtures, correlation/normalization |
| `test_detection.py`, `test_detection_integration.py` | Explainable rule engine + end-to-end trigger on a generated PCAP |
| `test_incidents.py` | SOC lifecycle, idempotency, evidence resolution |
| `test_analytics.py` | Dashboard aggregation incl. memory-safe over-time downsample |
| `test_compare.py` | TShark vs Zeek per-connection correlation (M13) |
| `test_reports.py` | 8-section PDF generation + honest data rules (M14) |
| `test_e2e_workflow.py` | One real PCAP → normalize → detect → incident → analytics → compare → report (M15) |

**Result: 159 tests passed.**

Frontend — `npm run typecheck` (no TS errors), `npm run lint` (no ESLint errors), `npm run build`
(production build, clean chunk layout).

## Honest tool status

| Tool | Installed | How validated |
|---|---|---|
| TShark / Wireshark | **Yes** (4.6.x) | Live capture, PCAP parse, comparison all run against real `tshark` output in tests |
| Zeek | **No** | App reports it as unavailable and keeps everything else functional; Zeek parsing paths are tested against committed log fixtures (`backend/tests/fixtures/zeek_*.log`), and the E2E/comparison suites assert honest `unavailable` handling |

## End-state checklist

- [x] 17 milestones delivered, each with its own verified commit on `main`.
- [x] 159 backend tests green; frontend typecheck/lint/build green.
- [x] Real (not faked) data path end-to-end: simulation → capture → TShark/Zeek → normalize →
      detect → incidents → analytics → compare → report.
- [x] Feature/API docs complete and consistent (README, `docs/api.md`, `docs/architecture.md`).
- [x] No secrets or build artifacts committed; `.env`/uploads/pcaps/DBs/reports gitignored.
- [x] Working tree clean at final commit `docs: finalize project documentation and validation`.