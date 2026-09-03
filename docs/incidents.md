# Incident Management (MILESTONE 11)

A SOC-style alert/incident workflow built on top of the M10 detection engine.

## Relationship to detection (M10)

M10 detects suspicious activity and persists **DetectionFinding** rows. M11 does **not** re-implement
detection. Instead it introduces an analyst-facing **Incident** that is created *from* a finding:

```
DetectionFinding (M10)
      │ creates / references
      ▼
Incident  ──▶  status, assignee, analyst notes, timestamps, resolution
      │
      └──▶  references (detection_finding_id) + evidence ids
               ▼ resolve on demand
            Connection / DnsEvent / HttpEvent / Packet (M9 normalized)
```

The incident snapshots the finding's severity, rule, capture, summary, detail and evidence references
so it stays self-contained and usable even if detection re-runs.

## Incident model

| Column                | Meaning                                                        |
|-----------------------|----------------------------------------------------------------|
| `id`                  | Incident UUID                                                   |
| `detection_finding_id`| Source M10 finding (unique — one incident per finding)           |
| `occurrence_key`      | Deterministic (capture, rule, evidence) fingerprint for dedup    |
| `capture_id`          | Capture the finding came from (indexed)                         |
| `rule_id`/`rule_name` | Detection rule that produced the finding                        |
| `title`/`description` | Analyst-editable fields                                         |
| `severity`            | `info\|low\|medium\|high\|critical` (inherited, indexed)          |
| `status`              | `NEW\|INVESTIGATING\|CONTAINED\|RESOLVED\|FALSE_POSITIVE` (indexed) |
| `score`               | Detection score                                                 |
| `summary`/`detail`    | Detection explanation snapshot                                  |
| `evidence`/`ref_type` | JSON evidence references (ids) + type                           |
| `assigned_to`         | Analyst owning the incident                                     |
| `resolution`, `resolution_notes` | Outcome when closed                             |
| `created_at`/`updated_at`        | Tracking timestamps                            |
| `first_seen_at`/`last_seen_at`   | First/last observed from the finding          |
| `closed_at`           | Set when resolved / false positive (null on reopen)             |

Indexed columns: `capture_id`, `severity`, `status`, `created_at`, `detection_finding_id` (unique),
`occurrence_key` (unique).

Supporting tables:
- `incident_notes` — analyst note timeline (`text`, `author`, `created_at`). Empty notes rejected.
- `incident_events` — audit history (`event_type`, `old_status`, `new_status`, `message`, `actor`, `created_at`).

## Status transitions (validated server-side)

| From           | Allowed to                      |
|----------------|----------------------------------|
| NEW            | INVESTIGATING                    |
| INVESTIGATING  | CONTAINED, RESOLVED, FALSE_POSITIVE |
| CONTAINED      | RESOLVED, INVESTIGATING (reopen) |
| RESOLVED       | INVESTIGATING (deliberate reopen)|
| FALSE_POSITIVE | INVESTIGATING (deliberate reopen)|

Behavior:
- Entering `RESOLVED`/`FALSE_POSITIVE` sets `closed_at` and a `resolution` marker.
- Reopening clears `closed_at`/`resolution`.
- Transitions are validated against `ALLOWED_TRANSITIONS` in `backend/app/core/enums.py`.
- Client-side-only status changes are impossible — the backend always validates + records history.

## Idempotency

Creating an incident for a finding that already has one returns the existing incident
(`created=0, skipped=1, existing=<id>`). Because findings are keyed by `detection_finding_id` and
also by the deterministic `occurrence_key`, a detection re-run (which generates new finding rows from
the same evidence) does **not** multiply incidents.

## API endpoints

| Method | Path                       | Purpose                                  |
|--------|----------------------------|------------------------------------------|
| GET    | `/incidents`               | List + filter (status/severity/capture/rule/search) + sort + paginate |
| POST   | `/incidents/from-finding`  | Create from a finding (idempotent)       |
| POST   | `/incidents/from-capture`  | Promote all findings of a capture (idempotent) |
| GET    | `/incidents/summary`       | Dashboard counters (open/critical/high/resolved/recent) |
| GET    | `/incidents/{id}`          | Full detail + evidence + notes + history |
| PATCH  | `/incidents/{id}`          | Update fields / apply validated transition |
| POST   | `/incidents/{id}/notes`    | Add analyst note (empty rejected, 422)   |
| DELETE | `/incidents/{id}`          | Delete (cleanup), 204 / 404              |

Errors: 404 unknown incident/finding, 400 invalid transition, 422 invalid status/severity/empty note.

## Investigation workflow

1. Detection produces findings → promoter creates incidents.
2. Analyst views the queue, filters by severity/status, opens an incident.
3. When warranted: `NEW → INVESTIGATING`, add a note, continue investigation.
4. `INVESTIGATING → CONTAINED` (mitigation in place), add another note.
5. `CONTAINED → RESOLVED` (sets `closed_at`/`resolution`) or `INVESTIGATING → FALSE_POSITIVE`.
6. Every step is recorded in incident history; notes form a timeline; evidence links back to the real
   normalized records.
