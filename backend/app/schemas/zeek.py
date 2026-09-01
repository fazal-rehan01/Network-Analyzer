"""Pydantic schemas for Zeek analysis results."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ZeekLogSummary(BaseModel):
    """Metadata for one Zeek log type produced (or absent)."""

    log_type: str
    filename: str
    path: str
    present: bool
    rows: int


class ZeekProcessResult(BaseModel):
    """Result of running Zeek over a PCAP / capture."""

    available: bool
    summary: list[ZeekLogSummary] = []
    logs: dict[str, list[dict]] = {}
    error: str | None = None
    capture_id: str | None = None


class ZeekEvent(BaseModel):
    """A single normalized Zeek event row (any log type)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    log_type: str
    capture_id: str | None = None
    ts: float | None = None
    uid: str | None = None
    src: str | None = None
    dst: str | None = None
    fields: dict = {}
    created_at: datetime
