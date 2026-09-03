"""Incident management models (MILESTONE 11).

An :class:`Incident` is an analyst-facing record created *from* an M10
``DetectionFinding``. It snapshots the finding's severity, rule, capture and
evidence references (so it remains usable even if the detection pipeline
re-runs), references the original finding for full traceability, and tracks the
investigation lifecycle:

- status transitions (NEW -> INVESTIGATING -> CONTAINED -> RESOLVED, or
  INVESTIGATING -> FALSE_POSITIVE) recorded as :class:`IncidentEvent` history.
- analyst notes stored separately in :class:`IncidentNote`.

``occurrence_key`` is a deterministic fingerprint of (capture, rule, evidence)
used to make incident creation idempotent across detection re-runs.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.core.enums import INCIDENT_STATUSES
from app.utils.timeutil import utcnow


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return utcnow()


def _default_status() -> str:
    return INCIDENT_STATUSES[0]


class Incident(Base):
    """A SOC-style incident created from a detection finding."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    detection_finding_id: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False
    )
    # Deterministic fingerprint of (capture, rule, evidence) for dedup.
    occurrence_key: Mapped[str] = mapped_column(
        String, unique=True, index=True, nullable=False
    )
    capture_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    rule_name: Mapped[str | None] = mapped_column(String, nullable=True)

    title: Mapped[str] = mapped_column(String, default="Untitled incident")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String, index=True, default="info")
    status: Mapped[str] = mapped_column(String, index=True, default=_default_status)
    score: Mapped[float] = mapped_column(Float, default=0.0)

    # Snapshot of the finding so the incident stays self-contained.
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    ref_type: Mapped[str | None] = mapped_column(String, nullable=True)

    assigned_to: Mapped[str | None] = mapped_column(String, nullable=True)

    # Short outcome category + free text, set when closed.
    resolution: Mapped[str | None] = mapped_column(String, nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    first_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class IncidentNote(Base):
    """A single analyst note on an incident (note timeline)."""

    __tablename__ = "incident_notes"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class IncidentEvent(Base):
    """Audit/history entry recording meaningful lifecycle changes."""

    __tablename__ = "incident_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    incident_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False)  # from INCIDENT_EVENT_TYPES
    old_status: Mapped[str | None] = mapped_column(String, nullable=True)
    new_status: Mapped[str | None] = mapped_column(String, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)