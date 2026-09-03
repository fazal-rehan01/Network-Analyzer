"""Incident management endpoints (MILESTONE 11).

Analyst-facing lifecycle management over M10 detection findings: create, list,
filter, inspect, transition, note, and (for cleanup) delete incidents.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.enums import INCIDENT_STATUSES, SEVERITY_VALUES
from app.models.incident import Incident
from app.schemas.incident import (
    IncidentCreate,
    IncidentCreateResult,
    IncidentDetail,
    IncidentListResult,
    IncidentNoteCreate,
    IncidentNoteRead,
    IncidentPatch,
    IncidentRead,
    IncidentSummary,
)
from app.services import incident as incident_svc

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _require_incident(db: Session, incident_id: str) -> Incident:
    row = incident_svc.get_incident(db, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


@router.get("", response_model=IncidentListResult)
def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    capture_id: str | None = None,
    rule_id: str | None = None,
    search: str | None = None,
    sort_by: str = "created_at",
    order: str = "desc",
    limit: int = incident_svc.DEFAULT_LIMIT,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> IncidentListResult:
    """List incidents with optional combined filtering, sorting, pagination."""
    if severity is not None and severity not in SEVERITY_VALUES:
        raise HTTPException(
            status_code=422,
            detail=f"invalid severity: {severity} (must be one of {', '.join(SEVERITY_VALUES)})",
        )
    if status is not None and status not in INCIDENT_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"invalid status: {status} (must be one of {', '.join(INCIDENT_STATUSES)})",
        )
    return incident_svc.list_incidents(
        db,
        status=status,
        severity=severity,
        capture_id=capture_id,
        rule_id=rule_id,
        search=search,
        sort_by=sort_by,
        order=order,
        limit=limit,
        offset=offset,
    )


@router.post("/from-finding", response_model=IncidentCreateResult)
def create_from_finding(
    payload: IncidentCreate, db: Session = Depends(get_db)
) -> IncidentCreateResult:
    """Create an incident from an M10 detection finding (idempotent)."""
    try:
        return incident_svc.create_from_finding(
            db,
            payload.detection_finding_id,
            title=payload.title,
            description=payload.description,
            assigned_to=payload.assigned_to,
        )
    except incident_svc.IncidentNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/from-capture", response_model=IncidentCreateResult)
def create_from_capture(
    capture_id: str, db: Session = Depends(get_db)
) -> IncidentCreateResult:
    """Promote all findings of a capture into incidents (idempotent)."""
    return incident_svc.create_from_capture(db, capture_id)


@router.get("/summary", response_model=IncidentSummary)
def incident_summary(db: Session = Depends(get_db)) -> IncidentSummary:
    """Dashboard counters computed from the real incidents table."""
    return incident_svc.summary(db)


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> IncidentDetail:
    """Full incident detail: finding reference, evidence, notes, history."""
    detail = incident_svc.incident_detail(db, incident_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return detail


@router.patch("/{incident_id}", response_model=IncidentRead)
def patch_incident(
    incident_id: str,
    payload: IncidentPatch,
    actor: str | None = None,
    db: Session = Depends(get_db),
) -> IncidentRead:
    """Update an incident (title/description/assignment/status/resolution)."""
    inc = _require_incident(db, incident_id)
    try:
        updated = incident_svc.patch_incident(db, inc, payload, actor=actor)
    except incident_svc.InvalidTransitionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except incident_svc.InvalidStatusError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return IncidentRead(**incident_svc.incident_to_dict(updated, db))


@router.post("/{incident_id}/notes", response_model=IncidentNoteRead, status_code=201)
def add_note(
    incident_id: str,
    payload: IncidentNoteCreate,
    db: Session = Depends(get_db),
) -> IncidentNoteRead:
    """Add an analyst note. Empty/blank notes are rejected."""
    inc = _require_incident(db, incident_id)
    try:
        note = incident_svc.add_note(db, inc, payload.text, author=payload.author)
    except incident_svc.EmptyNoteError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return IncidentNoteRead(
        id=note.id,
        incident_id=note.incident_id,
        text=note.text,
        author=note.author,
        created_at=note.created_at.isoformat() if note.created_at else None,
    )


@router.delete("/{incident_id}", status_code=204)
def delete_incident(incident_id: str, db: Session = Depends(get_db)):
    """Delete an incident (cleanup action). Destroys notes/history via cascade."""
    inc = _require_incident(db, incident_id)
    incident_svc.delete_incident(db, inc)
    return None