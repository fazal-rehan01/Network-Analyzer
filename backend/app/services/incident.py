"""Incident management service (MILESTONE 11).

Consumes the M10 detection engine output (``DetectionFinding`` rows) and turns
it into analyst-facing incidents. Key properties:

- **Idempotency**: creating an incident from a finding that already has one
  returns the existing incident (keyed on ``detection_finding_id``). A finding
  re-emitted by a detection re-run with a deterministic occurrence key
  (capture + rule + evidence ids) also maps to the same incident, so repeated
  detection runs never multiply incidents.
- **Transitions**: status changes are validated against ``ALLOWED_TRANSITIONS``
  and recorded as ``IncidentEvent`` history entries.
- **Self-contained snapshot**: incidents copy severity/rule/summary/detail/
  evidence at creation so they remain usable after a detection re-run.
"""
from __future__ import annotations

import hashlib
import json

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.enums import (
    ALLOWED_TRANSITIONS,
    CLOSED_STATUSES,
    INCIDENT_EVENT_TYPES,
    INCIDENT_STATUSES,
    OPEN_STATUSES,
    SEVERITY_VALUES,
)
from app.models.capture import Capture
from app.models.detection import DetectionFinding as FindingRow
from app.models.incident import Incident, IncidentEvent, IncidentNote
from app.models.normalized import Connection, DnsEvent, HttpEvent, Packet
from app.schemas.incident import (
    IncidentCreateResult,
    IncidentDetail,
    IncidentListResult,
    IncidentPatch,
    IncidentRead,
    IncidentSummary,
)
from app.utils.timeutil import utcnow

EVIDENCE_MODELS = {
    "connection": Connection,
    "dns": DnsEvent,
    "http": HttpEvent,
    "packet": Packet,
}

DEFAULT_LIMIT = 50
MAX_LIMIT = 500


class IncidentNotFound(LookupError):
    pass


class InvalidStatusError(ValueError):
    pass


class InvalidTransitionError(InvalidStatusError):
    pass


class EmptyNoteError(ValueError):
    pass


# --------------------------------------------------------------------------
# serialization helpers
# --------------------------------------------------------------------------


def _iso(value) -> str | None:
    return value.isoformat() if value else None


def _evidence_list(row: Incident) -> list[dict]:
    if not row.evidence:
        return []
    try:
        parsed = json.loads(row.evidence)
        return parsed if isinstance(parsed, list) else []
    except (ValueError, TypeError):
        return []


def incident_to_dict(row: Incident, db: Session | None = None) -> dict:
    capture_name = None
    if db is not None and row.capture_id:
        cap = db.get(Capture, row.capture_id)
        if cap is not None:
            capture_name = cap.name
    return {
        "id": row.id,
        "detection_finding_id": row.detection_finding_id,
        "capture_id": row.capture_id,
        "capture_name": capture_name,
        "rule_id": row.rule_id,
        "rule_name": row.rule_name,
        "title": row.title,
        "description": row.description,
        "severity": row.severity,
        "status": row.status,
        "score": row.score,
        "summary": row.summary,
        "detail": row.detail,
        "ref_type": row.ref_type,
        "assigned_to": row.assigned_to,
        "resolution": row.resolution,
        "resolution_notes": row.resolution_notes,
        "closed_at": _iso(row.closed_at),
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "first_seen_at": _iso(row.first_seen_at),
        "last_seen_at": _iso(row.last_seen_at),
    }


def resolve_evidence(db: Session, evidence: list[dict]) -> list[dict]:
    """Resolve evidence references to the actual normalized records.

    Returns stripped metadata (never raw payloads) for the referenced records.
    Missing records are reported as such rather than fabricated.
    """
    resolved: list[dict] = []
    for ev in evidence:
        ev_type = ev.get("type")
        ev_id = ev.get("id")
        model = EVIDENCE_MODELS.get(ev_type)
        if model is None:
            resolved.append(
                {"type": ev_type, "id": ev_id, "status": "unknown_type", "record": None}
            )
            continue
        record = db.get(model, ev_id) if ev_id else None
        if record is None:
            resolved.append(
                {"type": ev_type, "id": ev_id, "status": "missing", "record": None}
            )
            continue
        resolved.append(
            {
                "type": ev_type,
                "id": ev_id,
                "status": "ok",
                "record": _snapshot(record, ev_type),
            }
        )
    return resolved


def _snapshot(record, ev_type: str) -> dict:
    if ev_type == "connection":
        return {
            "src": record.src,
            "dst": record.dst,
            "proto": record.proto,
            "sport": record.sport,
            "dport": record.dport,
            "service": record.service,
            "packets": record.packets,
            "bytes_total": record.bytes_total,
            "source": record.source,
        }
    if ev_type == "dns":
        return {
            "src": record.src,
            "dst": record.dst,
            "query": record.query,
            "qtype_name": record.qtype_name,
            "rcode_name": record.rcode_name,
            "source": record.source,
        }
    if ev_type == "http":
        return {
            "src": record.src,
            "dst": record.dst,
            "method": record.method,
            "host": record.host,
            "uri": record.uri,
            "status_code": record.status_code,
            "source": record.source,
        }
    return {
        "src": record.src,
        "dst": record.dst,
        "proto": record.proto,
        "sport": record.sport,
        "dport": record.dport,
        "length": record.length,
        "source": record.source,
    }


def _notes_for(db: Session, incident_id: str) -> list[dict]:
    rows = (
        db.query(IncidentNote)
        .filter(IncidentNote.incident_id == incident_id)
        .order_by(IncidentNote.created_at.asc())
        .all()
    )
    return [
        {
            "id": r.id,
            "incident_id": r.incident_id,
            "text": r.text,
            "author": r.author,
            "created_at": _iso(r.created_at),
        }
        for r in rows
    ]


def _history_for(db: Session, incident_id: str) -> list[dict]:
    rows = (
        db.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident_id)
        .order_by(IncidentEvent.created_at.asc())
        .all()
    )
    return [
        {
            "id": r.id,
            "incident_id": r.incident_id,
            "event_type": r.event_type,
            "old_status": r.old_status,
            "new_status": r.new_status,
            "message": r.message,
            "actor": r.actor,
            "created_at": _iso(r.created_at),
        }
        for r in rows
    ]


def _occurrence_key(finding: FindingRow) -> str:
    """Deterministic fingerprint of (capture, rule, sorted evidence ids)."""
    try:
        ev = json.loads(finding.evidence) if finding.evidence else []
    except (ValueError, TypeError):
        ev = []
    ids = sorted(
        str(e.get("id", "")) for e in ev if isinstance(e, dict) and e.get("id")
    )
    raw = f"{finding.capture_id}|{finding.rule_id}|{','.join(ids)}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def _add_event(
    db: Session,
    incident: Incident,
    event_type: str,
    actor: str | None,
    old_status: str | None = None,
    new_status: str | None = None,
    message: str | None = None,
) -> IncidentEvent:
    if event_type not in INCIDENT_EVENT_TYPES:
        event_type = "status_changed"
    event = IncidentEvent(
        incident_id=incident.id,
        event_type=event_type,
        old_status=old_status,
        new_status=new_status,
        message=message,
        actor=actor,
    )
    db.add(event)
    return event


def _touch(incident: Incident) -> None:
    incident.updated_at = utcnow()


# --------------------------------------------------------------------------
# incident creation
# --------------------------------------------------------------------------


def create_from_finding(
    db: Session,
    finding_id: str,
    title: str | None = None,
    description: str | None = None,
    assigned_to: str | None = None,
) -> IncidentCreateResult:
    """Create an incident from a detection finding.

    Idempotent by construction: if an incident already references this finding,
    or an incident exists for the same deterministic occurrence key, the
    existing incident is returned and no new rows are written.
    """
    finding = db.get(FindingRow, finding_id)
    if finding is None:
        raise IncidentNotFound(f"Detection finding not found: {finding_id}")

    # Duplicate prevention: same finding, or logical re-occurrence.
    existing = (
        db.query(Incident)
        .filter(
            (Incident.detection_finding_id == finding_id)
            | (Incident.occurrence_key == _occurrence_key(finding))
        )
        .first()
    )
    if existing is not None:
        return IncidentCreateResult(
            incident=IncidentRead(**incident_to_dict(existing, db)),
            created=0,
            skipped=1,
            existing=existing.id,
        )

    now = utcnow()
    incident = Incident(
        detection_finding_id=finding.id,
        occurrence_key=_occurrence_key(finding),
        capture_id=finding.capture_id,
        rule_id=finding.rule_id,
        rule_name=finding.rule_name,
        title=(
            title
            or (finding.rule_name or "Detection finding")
            + (" — detected" if finding.rule_name else "")
        ),
        description=description,
        severity=finding.severity if finding.severity in SEVERITY_VALUES else "info",
        status=INCIDENT_STATUSES[0],
        score=finding.score,
        summary=finding.summary,
        detail=finding.detail,
        evidence=finding.evidence,
        ref_type=finding.ref_type,
        assigned_to=assigned_to,
        first_seen_at=finding.created_at or now,
        last_seen_at=finding.created_at or now,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.flush()
    _add_event(
        db,
        incident,
        event_type="created",
        actor=assigned_to,
        new_status=incident.status,
        message="Incident created from detection finding",
    )
    db.commit()
    db.refresh(incident)
    return IncidentCreateResult(
        incident=IncidentRead(**incident_to_dict(incident, db)),
        created=1,
        skipped=0,
        existing=None,
    )


def create_from_capture(db: Session, capture_id: str) -> IncidentCreateResult:
    """Promote every finding of a capture into an incident (idempotent).

    Findings that already have an incident are skipped. Returns aggregate counts
    plus the newest created incident for convenient display.
    """
    findings = (
        db.query(FindingRow)
        .filter(FindingRow.capture_id == capture_id)
        .order_by(FindingRow.created_at.asc())
        .all()
    )
    created = 0
    skipped = 0
    latest: Incident | None = None
    for finding in findings:
        result = create_from_finding(db, finding.id)
        created += result.created
        skipped += result.skipped
        if result.created and result.incident is not None:
            latest_row = db.get(Incident, result.incident.id)
            if latest_row is not None:
                latest = latest_row
    return IncidentCreateResult(
        incident=IncidentRead(**incident_to_dict(latest, db)) if latest else None,
        created=created,
        skipped=skipped,
        existing=None,
    )


# --------------------------------------------------------------------------
# retrieval
# --------------------------------------------------------------------------


def get_incident(db: Session, incident_id: str) -> Incident | None:
    return db.get(Incident, incident_id)


def incident_detail(db: Session, incident_id: str) -> IncidentDetail | None:
    row = db.get(Incident, incident_id)
    if row is None:
        return None
    evidence = _evidence_list(row)
    return IncidentDetail(
        **incident_to_dict(row, db),
        evidence=evidence,
        evidence_resolved=resolve_evidence(db, evidence),
        notes=_notes_for(db, incident_id),
        history=_history_for(db, incident_id),
    )


def list_incidents(
    db: Session,
    status: str | None = None,
    severity: str | None = None,
    capture_id: str | None = None,
    rule_id: str | None = None,
    search: str | None = None,
    sort_by: str = "created_at",
    order: str = "desc",
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> IncidentListResult:
    """List incidents with combined filtering, sorting and pagination."""
    if limit < 1:
        limit = DEFAULT_LIMIT
    limit = min(limit, MAX_LIMIT)

    q = db.query(Incident)
    if status:
        if status not in INCIDENT_STATUSES:
            raise InvalidStatusError(f"invalid status: {status}")
        q = q.filter(Incident.status == status)
    if severity:
        if severity not in SEVERITY_VALUES:
            raise InvalidStatusError(f"invalid severity: {severity}")
        q = q.filter(Incident.severity == severity)
    if capture_id:
        q = q.filter(Incident.capture_id == capture_id)
    if rule_id:
        q = q.filter(Incident.rule_id == rule_id)
    if search:
        like = f"%{search}%"
        q = q.filter(
            or_(
                Incident.title.ilike(like),
                Incident.summary.ilike(like),
                Incident.detail.ilike(like),
                Incident.rule_name.ilike(like),
            )
        )

    total = q.count()

    col = getattr(Incident, sort_by if sort_by in ("severity", "updated_at") else "created_at", Incident.created_at)
    if severity is None:
        # Default sort also gives a deterministic tie-breaker.
        col = Incident.created_at if sort_by not in ("severity", "updated_at") else col
    q = q.order_by(
        col.asc() if order == "asc" else col.desc(),
        Incident.created_at.desc(),
    )
    rows = q.offset(offset).limit(limit).all()

    items = [IncidentRead(**incident_to_dict(r, db)) for r in rows]
    return IncidentListResult(items=items, total=total, limit=limit, offset=offset)


# --------------------------------------------------------------------------
# lifecycle / transitions
# --------------------------------------------------------------------------


def change_status(
    db: Session,
    incident: Incident,
    new_status: str,
    actor: str | None = None,
    resolution: str | None = None,
    resolution_notes: str | None = None,
) -> Incident:
    """Apply a validated status transition and record it in history."""
    if new_status not in INCIDENT_STATUSES:
        raise InvalidStatusError(f"invalid status: {new_status}")

    if new_status == incident.status:
        # No-op transition: still refresh timestamps only.
        _touch(incident)
        db.commit()
        db.refresh(incident)
        return incident

    allowed = ALLOWED_TRANSITIONS.get(incident.status, ())
    if new_status not in allowed:
        raise InvalidTransitionError(
            f"cannot transition from {incident.status} to {new_status}"
        )

    old_status = incident.status
    incident.status = new_status
    _touch(incident)

    if new_status in CLOSED_STATUSES:
        incident.closed_at = incident.closed_at or utcnow()
        incident.resolution = resolution or (
            "false_positive" if new_status == "FALSE_POSITIVE" else "resolved"
        )
        if resolution_notes is not None:
            incident.resolution_notes = resolution_notes
    else:
        # Reopening clears the closed/resolution markers.
        incident.closed_at = None
        incident.resolution = None
        incident.resolution_notes = None

    event_type = {
        "RESOLVED": "resolved",
        "FALSE_POSITIVE": "marked_false_positive",
    }.get(new_status, "status_changed")
    # Reopen path.
    if old_status in CLOSED_STATUSES and new_status not in CLOSED_STATUSES:
        event_type = "reopened"

    _add_event(
        db,
        incident,
        event_type=event_type,
        actor=actor,
        old_status=old_status,
        new_status=new_status,
        message=f"Status changed: {old_status} -> {new_status}",
    )
    db.commit()
    db.refresh(incident)
    return incident


def assign(
    db: Session, incident: Incident, assigned_to: str, actor: str | None = None
) -> Incident:
    incident.assigned_to = assigned_to
    _touch(incident)
    _add_event(
        db,
        incident,
        event_type="assigned",
        actor=actor or assigned_to,
        new_status=incident.status,
        message=f"Assigned to {assigned_to}",
    )
    db.commit()
    db.refresh(incident)
    return incident


def patch_incident(
    db: Session,
    incident: Incident,
    patch: IncidentPatch,
    actor: str | None = None,
) -> Incident:
    """Apply an analyst update. Status transitions are validated."""
    changed = False
    for field, value in [
        ("title", patch.title),
        ("description", patch.description),
        ("assigned_to", patch.assigned_to),
        ("resolution", patch.resolution),
        ("resolution_notes", patch.resolution_notes),
    ]:
        if value is not None:
            setattr(incident, field, value)
            changed = True

    was_assigned = patch.assigned_to is not None
    if patch.status is not None:
        result = change_status(
            db,
            incident,
            patch.status,
            actor=actor,
            resolution=patch.resolution,
            resolution_notes=patch.resolution_notes,
        )
        return result

    if changed:
        _touch(incident)
        if was_assigned and incident.assigned_to:
            _add_event(
                db,
                incident,
                event_type="assigned",
                actor=actor or incident.assigned_to,
                new_status=incident.status,
                message=f"Assigned to {incident.assigned_to}",
            )
        else:
            _add_event(
                db,
                incident,
                event_type="status_changed",
                actor=actor,
                new_status=incident.status,
                message="Incident details updated",
            )
        db.commit()
        db.refresh(incident)
    return incident


def add_note(
    db: Session, incident: Incident, text: str, author: str | None = None
) -> IncidentNote:
    text = text.strip() if text else ""
    if not text:
        raise EmptyNoteError("note text must not be empty")

    note = IncidentNote(incident_id=incident.id, text=text, author=author)
    db.add(note)
    db.flush()
    _touch(incident)
    _add_event(
        db,
        incident,
        event_type="note_added",
        actor=author,
        new_status=incident.status,
        message="Analyst note added",
    )
    db.commit()
    db.refresh(note)
    return note


def delete_incident(db: Session, incident: Incident) -> None:
    db.delete(incident)
    db.commit()


# --------------------------------------------------------------------------
# dashboard
# --------------------------------------------------------------------------


def summary(db: Session) -> IncidentSummary:
    rows = db.query(Incident).all()
    total = len(rows)
    open_count = sum(1 for r in rows if r.status in OPEN_STATUSES)
    critical = sum(1 for r in rows if r.severity == "critical")
    high = sum(1 for r in rows if r.severity == "high")
    resolved = sum(1 for r in rows if r.status == "RESOLVED")
    false_positive = sum(1 for r in rows if r.status == "FALSE_POSITIVE")

    recent_rows = list(reversed(sorted(rows, key=lambda r: r.created_at)))[:5]
    recent = [IncidentRead(**incident_to_dict(r, db)) for r in recent_rows]

    return IncidentSummary(
        total=total,
        open=open_count,
        critical=critical,
        high=high,
        resolved=resolved,
        false_positive=false_positive,
        recent=recent,
    )