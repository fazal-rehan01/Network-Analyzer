"""Simulation run model."""
from __future__ import annotations

import json
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.utils.timeutil import utcnow


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return utcnow()


class Simulation(Base):
    """A run of a simulation scenario, plus generated-traffic statistics."""

    __tablename__ = "simulations"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    scenario: Mapped[str] = mapped_column(String, index=True)
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    target: Mapped[str] = mapped_column(String, default="127.0.0.1")
    target_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    status: Mapped[str] = mapped_column(String, default="idle")  # idle|running|completed|stopped|failed
    # idle,running,completed cancel an active run
    start_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_sec: Mapped[float | None] = mapped_column(nullable=True)

    packets_sent: Mapped[int] = mapped_column(Integer, default=0)
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    connections: Mapped[int] = mapped_column(Integer, default=0)
    rates_per_sec: Mapped[int] = mapped_column(Integer, default=0)

    # Config JSON passed to the scenario at start (e.g. packet count, duration)
    config_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Free-form stats produced by the scenario run
    stats_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    def set_config(self, cfg: dict) -> None:
        self.config_json = json.dumps(cfg)

    def get_config(self) -> dict:
        try:
            return json.loads(self.config_json) if self.config_json else {}
        except (TypeError, json.JSONDecodeError):
            return {}

    def set_stats(self, stats: dict) -> None:
        self.stats_json = json.dumps(stats)

    def get_stats(self) -> dict:
        try:
            return json.loads(self.stats_json) if self.stats_json else {}
        except (TypeError, json.JSONDecodeError):
            return {}
