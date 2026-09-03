"""Detection engine endpoints (M10).

Explainable, rule-based detection over the normalized/correlated records.
Graceful degradation: captures with no normalized data simply yield zero
findings rather than an error.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.capture import Capture
from app.schemas.detection import (
    DetectionFindingRead,
    DetectionRunResult,
    DetectionSummary,
    RuleInfo,
)
from app.services import detection as detect_svc

router = APIRouter(prefix="/detect", tags=["detect"])


def _require_capture(db: Session, capture_id: str) -> Capture:
    cap = db.get(Capture, capture_id)
    if cap is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return cap


@router.get("/rules", response_model=list[RuleInfo])
def list_rules() -> list[RuleInfo]:
    """Return metadata for every registered detection rule."""
    return detect_svc.list_rule_info()


@router.post("/run", response_model=DetectionRunResult)
def run_detection(capture_id: str, db: Session = Depends(get_db)) -> DetectionRunResult:
    """Run all detection rules over a capture's normalized data."""
    _require_capture(db, capture_id)
    return detect_svc.run_detection(db, capture_id)


@router.get("/findings", response_model=list[DetectionFindingRead])
def list_findings(
    capture_id: str,
    severity: str | None = None,
    limit: int = 200,
    db: Session = Depends(get_db),
) -> list[DetectionFindingRead]:
    """Return persisted detection findings for a capture."""
    _require_capture(db, capture_id)
    return [DetectionFindingRead(**f) for f in detect_svc.findings_for_capture(db, capture_id, severity, limit)]


@router.get("/summary", response_model=DetectionSummary)
def detection_summary(capture_id: str, db: Session = Depends(get_db)) -> DetectionSummary:
    """Return a severity summary of persisted findings for a capture."""
    _require_capture(db, capture_id)
    return detect_svc.summary_for_capture(db, capture_id)
