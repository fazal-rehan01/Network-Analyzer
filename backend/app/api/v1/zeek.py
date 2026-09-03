"""Zeek analysis endpoints (defensive log parsing, graceful degradation)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pathlib import Path
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.capture import Capture
from app.schemas.zeek import ZeekEvent, ZeekProcessResult
from app.services import zeek as zeek_svc

router = APIRouter(prefix="/zeek", tags=["zeek"])


@router.get("/status", response_model=dict)
def zeek_status() -> dict:
    """Report whether Zeek is installed and where its storage lives."""
    return zeek_svc.log_list_available()


@router.post("/process", response_model=ZeekProcessResult)
def process_zeek(capture_id: str, db: Session = Depends(get_db)) -> ZeekProcessResult:
    """Run Zeek over a capture's PCAP and persist normalized events."""
    cap = db.get(Capture, capture_id)
    if cap is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    if not cap.file_path or not Path(cap.file_path).exists():
        raise HTTPException(status_code=400, detail="Capture has no saved PCAP file")
    result = zeek_svc.process_capture(db, Path(cap.file_path), capture_id=cap.id)
    return result


@router.get("/events", response_model=list[ZeekEvent])
def zeek_events(
    capture_id: str,
    log_type: str | None = None,
    limit: int = 200,
    db: Session = Depends(get_db),
) -> list[ZeekEvent]:
    """Return normalized Zeek events persisted for a capture."""
    if log_type and log_type not in ("conn", "dns", "http", "ssl", "notice"):
        raise HTTPException(status_code=400, detail="Unknown Zeek log type")
    cap = db.get(Capture, capture_id)
    if cap is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return [ZeekEvent(**e) for e in zeek_svc.events_for_capture(db, capture_id, log_type, limit)]
