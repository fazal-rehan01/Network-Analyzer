"""Analysis job model — tracks pipeline processing of a capture."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AnalysisJob(Base):
    """Tracks the analysis pipeline for a capture (tshark parse, zeek, detect)."""

    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    capture_id: Mapped[str] = mapped_column(String, index=True)
    kind: Mapped[str] = mapped_column(String, default="upload")  # upload | live | simulation
    status: Mapped[str] = mapped_column(String, default="pending")  # pending|running|done|failed
    stage: Mapped[str] = mapped_column(String, default="queued")  # tshark|zeek|normalize|detect|done
    message: Mapped[str | None] = mapped_column(String, nullable=True)
    packets_parsed: Mapped[int] = mapped_column(Integer, default=0)
    zeek_available: Mapped[bool] = mapped_column(default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
