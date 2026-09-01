"""Pydantic schemas for the detection engine (M10)."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class RuleInfo(BaseModel):
    """Metadata for a registered detection rule."""

    id: str
    name: str
    default_severity: str


class DetectionFindingRead(BaseModel):
    """A persisted detection finding with its evidence refs."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    severity: str = "info"
    score: float = 0.0
    summary: str | None = None
    detail: str | None = None
    evidence: list[dict] = []
    ref_type: str | None = None
    created_at: str | None = None


class DetectionRunResult(BaseModel):
    """Result of running the detection engine over a capture."""

    capture_id: str | None = None
    findings: int = 0
    rules_evaluated: int = 0
    by_severity: dict[str, int] = {}


class DetectionSummary(BaseModel):
    """Summary of persisted findings for a capture."""

    capture_id: str | None = None
    total: int = 0
    by_severity: dict[str, int] = {}
