"""Pydantic schemas for health / system status."""
from __future__ import annotations

from pydantic import BaseModel


class ComponentStatus(BaseModel):
    name: str
    installed: bool
    version: str | None = None
    path: str | None = None
    note: str | None = None


class HealthResponse(BaseModel):
    status: str
    app: str
    database: str
    version: str


class SystemStatusResponse(BaseModel):
    status: str
    components: list[ComponentStatus]
