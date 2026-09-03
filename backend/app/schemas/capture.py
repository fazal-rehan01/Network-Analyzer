"""Pydantic schemas for packet captures and TShark interfaces."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class InterfaceInfo(BaseModel):
    """A single capture interface detected via tshark -D."""

    index: int
    name: str
    description: str | None = None
    loopback: bool = False


class CaptureCreate(BaseModel):
    name: str | None = None
    interface: str | None = None
    interface_index: int | None = None
    filter_expr: str | None = None
    duration_sec: int | None = None


class ProtocolStat(BaseModel):
    protocol: str
    frames: int
    bytes: int


class CaptureStats(BaseModel):
    packet_count: int = 0
    byte_count: int = 0
    protocols: list[ProtocolStat] = []
    top_talkers: list[dict] = []
    time_series: list[dict] = []
    captures_count: int = 0


class CaptureRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    source: str
    filename: str | None = None
    file_path: str | None = None
    interface: str | None = None
    filter_expr: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_sec: float | None = None
    packet_count: int = 0
    byte_count: int = 0
    status: str
    error: str | None = None
    created_at: datetime
