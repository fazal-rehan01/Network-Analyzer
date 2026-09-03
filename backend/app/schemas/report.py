"""Report request/option schemas (MILESTONE 14)."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class ReportCaptureOption(BaseModel):
    """A capture the user may choose to include in a generated report."""

    id: str
    name: str | None = None
    source: str | None = None
    status: str | None = None
    packet_count: int = 0
    byte_count: int = 0
    created_at: datetime | None = None


class ReportOptions(BaseModel):
    """What the Reports UI knows up front (scope list + capture options)."""

    global_available: bool = True
    captures: list[ReportCaptureOption] = []


class ReportGenerateRequest(BaseModel):
    """Body for PDF generation. ``capture_id=None`` means whole database."""

    capture_id: str | None = None