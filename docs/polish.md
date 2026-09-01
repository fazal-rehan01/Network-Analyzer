# UI Polish, Reliability & Performance (M16)

M16 turns the last two remaining placeholder screens into real, useful pages and hunts down
frontend reliability/performance problems.

## Simulation Center (page, real)

`frontend/src/pages/SimulationPage.tsx` now drives the actual M4/M5 simulation engine via the
`/simulations/*` API:

- Target input (defaults to `127.0.0.1`) with a note that traffic is generated on the server host.
- Scenario cards derived from `GET /simulations/scenarios` (8 scenarios: normal traffic, HTTP,
  DNS, ICMP, port scan, connection burst, large data transfer, DNS anomaly — `suspicious` ones are
  badged).
- "Run" = create the simulation (`POST /simulations`) then start it (`POST /simulations/{id}/start`);
  stop via `POST /simulations/{id}/stop`.
- Live history table (2 s poll) with status badges (`idle/running/completed/stopped/failed`),
  packet/byte/connection counts, rate, duration and per-run Stop/Refresh controls.
- Distinct loading / error / empty states; all mutation errors shown inline.

## Packets page (real)

`frontend/src/pages/PacketsPage.tsx` replaces the placeholder with a real packet inspector backed by
the M7 normalization store (`GET /normalize/packets`):

- Capture selector (from `GET /captures`), fetches up to 5000 normalized packets.
- Client-side search across frame/src/dst/ports/TCP flags/HTTP/DNS fields plus a protocol filter.
- Monospace evidence table (frame, time, 5-tuple, proto, length, flags, TShark/Zeek source badge);
  clicking a row opens a full detail panel with every normalized evidence field.

## Performance

- **Route-level code splitting** — every route now uses `React.lazy` in `App.tsx`. The initial JS
  bundle dropped from **678 kB (→ 205 kB gzip)** to **182 kB (gzip 59 kB)**; each page is an
  independently loaded chunk (charts stay out of the critical path until the Dashboard loads).
- **No more > 500 kB chunk warning**; nothing ships unneeded page code on first load.

## Reliability

- **Top-level `ErrorBoundary`** (`frontend/src/components/ErrorBoundary.tsx`) wraps the routed page
  in `Layout.tsx`. A crash in any page now shows a friendly reload screen while the sidebar/top bar
  keep working — previously a runtime error could blank the whole app.
- **Refetch-safe data hook** — `useApi` previously re-ran its effect whenever the (inline) fetcher
  closure changed identity on re-render, causing a background request storm. It now keeps the
  fetcher in a ref and triggers fetches on mount, polling, or an explicit `refetch()`; call sites
  whose fetcher depends on state (Dashboard scope, Compare capture, Incidents filters, Packets
  capture, Capture inline stats) call `refetch()` on change, eliminating double-fetch churn.

## Page states

All existing pages were already audited for loading/error/empty states in earlier milestones; the two
new pages follow the same conventions (`Spinner`, `ErrorState`, `EmptyState`, `Card` primitives).

## Verification

- `npm run typecheck`, `npm run lint`, `npm run build` — clean; each page a separate lazy chunk.
- Backend full test suite re-run after frontend changes: **159 passed** (no backend changes in M16).
- Docs updated (README, architecture) and this file added; committed as
  `fix: polish dashboard and application reliability`.