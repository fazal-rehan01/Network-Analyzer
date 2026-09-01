"""Wireshark/TShark vs Zeek comparison endpoints (MILESTONE 13).

Presents the same traffic from packet-level (TShark) and event-level (Zeek)
perspectives, showing which side has evidence for each connection and honest
correlation status when one side is absent or Zeek is unavailable.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.capture import Capture
from app.schemas.compare import (
    CaptureComparison,
    CompareStatus,
    ConnectionComparison,
)
from app.services import compare as compare_svc

router = APIRouter(prefix="/compare", tags=["compare"])


@router.get("/status", response_model=CompareStatus)
def compare_status() -> CompareStatus:
    """Report whether TShark and Zeek tooling is available for comparison."""
    return CompareStatus(**compare_svc.compare_status())


@router.get("/capture/{capture_id}", response_model=CaptureComparison)
def capture_comparison(capture_id: str, db: Session = Depends(get_db)) -> CaptureComparison:
    """Comparison summary + per-connection correlation for a capture."""
    cap = db.get(Capture, capture_id)
    if cap is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    result = compare_svc.compare_capture(db, capture_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return result


@router.get("/connection/{connection_id}", response_model=ConnectionComparison)
def connection_comparison(connection_id: str, db: Session = Depends(get_db)) -> ConnectionComparison:
    """Full side-by-side TShark vs Zeek evidence for one connection."""
    result = compare_svc.compare_connection(db, connection_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    return result
