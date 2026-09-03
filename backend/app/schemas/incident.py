"""Pydantic schemas for the incident workflow (MILESTONE 11)."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import INCIDENT_STATUSES


class IncidentCreate(BaseModel):
    """Create an incident from an existing M10 detection finding."""

    detection_finding_id: str = Field(..., min_length=1)
    title: str | None = None
    description: str | None = None
    assigned_to: str | None = None


class IncidentPatch(BaseModel):
    """Update incident fields. ``status`` is validated against the
    allowed-transition map by the service layer, not trusted blindly."""

    title: str | None = None
    description: str | None = None
    status: str | None = None
    assigned_to: str | None = None
    resolution: str | None = None
    resolution_notes: str | None = None

    @field_validator("status")
    @classmethod
    def _status_valid(cls, value: str | None) -> str | None:
        if value is not None and value not in INCIDENT_STATUSES:
            raise ValueError(
                f"status must be one of {', '.join(INCIDENT_STATUSES)}"
            )
        return value


class IncidentNoteCreate(BaseModel):
    """A single analyst note. Empty notes are rejected."""

    text: str = Field(..., min_length=1)
    author: str | None = None

    @field_validator("text")
    @classmethod
    def _text_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("note text must not be empty")
        return value.strip()


class IncidentNoteRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    text: str
    author: str | None = None
    created_at: str | None = None


class IncidentEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    event_type: str
    old_status: str | None = None
    new_status: str | None = None
    message: str | None = None
    actor: str | None = None
    created_at: str | None = None


class IncidentRead(BaseModel):
    """List/detail row: enough for a dashboard table without N+1 requests."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    detection_finding_id: str
    capture_id: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    title: str
    description: str | None = None
    severity: str = "info"
    status: str = "NEW"
    score: float = 0.0
    summary: str | None = None
    detail: str | None = None
    ref_type: str | None = None
    assigned_to: str | None = None
    resolution: str | None = None
    resolution_notes: str | None = None
    closed_at: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    capture_name: str | None = None


class IncidentDetail(IncidentRead):
    """Full incident detail including evidence, notes, and history."""

    evidence: list[dict] = []
    evidence_resolved: list[dict] = []
    notes: list[IncidentNoteRead] = []
    history: list[IncidentEventRead] = []


class IncidentCreateResult(BaseModel):
    """Result of creating incident(s) from detection finding(s)."""

    incident: IncidentRead | None = None
    created: int = 0
    skipped: int = 0  # already existed (idempotent)
    existing: str | None = None  # id of the already-existing incident


class IncidentListResult(BaseModel):
    items: list[IncidentRead] = []
    total: int = 0
    limit: int = 50
    offset: int = 0


class IncidentSummary(BaseModel):
    """Dashboard counters computed from the incidents table."""

    total: int = 0
    open: int = 0
    critical: int = 0
    high: int = 0
    resolved: int = 0
    false_positive: int = 0
    recent: list[IncidentRead] = []