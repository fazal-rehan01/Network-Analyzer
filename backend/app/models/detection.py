"""Detection finding model (M10).

Stores the output of the explainable, rule-based detection engine. Each finding
is deterministic and references the normalized evidence it was derived from so
it can be traced back to TShark/Zeek records.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.utils.timeutil import utcnow


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return utcnow()


class DetectionFinding(Base):
    """One finding produced by a detection rule for a capture."""

    __tablename__ = "detection_findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    capture_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    rule_name: Mapped[str | None] = mapped_column(String, nullable=True)
    severity: Mapped[str] = mapped_column(String, default="info")  # info|low|medium|high|critical
    score: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    ref_type: Mapped[str | None] = mapped_column(String, nullable=True)  # connection|dns|http|packet
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
