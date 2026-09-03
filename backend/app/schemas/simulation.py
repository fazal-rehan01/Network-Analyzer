"""Pydantic schemas for simulations."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ScenarioInfo(BaseModel):
    key: str
    name: str
    description: str
    default_port: int | None = None
    suspicious: bool = False
    default_config: dict = {}


class SimulationCreate(BaseModel):
    scenario: str
    name: str | None = None
    target: str = "127.0.0.1"
    target_port: int | None = None
    config: dict = {}


class SimulationRead(BaseModel):
    id: str
    scenario: str
    name: str
    description: str | None = None
    target: str
    target_port: int | None = None
    status: str
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_sec: float | None = None
    packets_sent: int
    bytes_sent: int
    connections: int
    rates_per_sec: int
    config: dict = {}
    stats: dict = {}
    result: str | None = None
    error: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
