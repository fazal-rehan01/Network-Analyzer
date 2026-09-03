"""Normalization and correlation endpoints.

Merge TShark packet evidence with Zeek event evidence into shared normalized
Connection / DNS / HTTP records. Graceful degradation: when neither tool is
available the run returns a non-erroring, empty summary.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.capture import Capture
from app.models.normalized import Connection, DnsEvent, HttpEvent, Packet
from app.schemas.normalized import (
    ConnectionRead,
    DnsEventRead,
    HttpEventRead,
    NormalizeSummary,
    PacketRead,
)
from app.services import normalize as normalize_svc

router = APIRouter(prefix="/normalize", tags=["normalize"])


def _require_capture(db: Session, capture_id: str) -> Capture:
    cap = db.get(Capture, capture_id)
    if cap is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return cap


@router.get("/status", response_model=dict)
def normalize_status() -> dict:
    """Report availability of the underlying evidence tools."""
    return {
        "tshark_available": normalize_svc.tshark_available(),
        "zeek_available": normalize_svc.zeek_available(),
    }


@router.post("/run", response_model=NormalizeSummary)
def run_normalize(
    capture_id: str,
    db: Session = Depends(get_db),
) -> NormalizeSummary:
    """Run TShark + Zeek normalization/correlation for a capture."""
    cap = _require_capture(db, capture_id)
    if not cap.file_path or not Path(cap.file_path).exists():
        raise HTTPException(status_code=400, detail="Capture has no saved PCAP file")
    return normalize_svc.normalize_capture(db, Path(cap.file_path), capture_id=cap.id)


@router.get("/connections", response_model=list[ConnectionRead])
def list_connections(
    capture_id: str,
    limit: int = 500,
    db: Session = Depends(get_db),
) -> list[ConnectionRead]:
    """Return normalized connections for a capture."""
    _require_capture(db, capture_id)
    rows = (
        db.query(Connection)
        .filter(Connection.capture_id == capture_id)
        .order_by(Connection.first_ts.asc())
        .limit(limit)
        .all()
    )
    return [ConnectionRead.model_validate(r) for r in rows]


@router.get("/dns", response_model=list[DnsEventRead])
def list_dns(
    capture_id: str,
    limit: int = 500,
    db: Session = Depends(get_db),
) -> list[DnsEventRead]:
    """Return normalized DNS events for a capture."""
    _require_capture(db, capture_id)
    rows = (
        db.query(DnsEvent)
        .filter(DnsEvent.capture_id == capture_id)
        .order_by(DnsEvent.ts.asc())
        .limit(limit)
        .all()
    )
    return [DnsEventRead.model_validate(r) for r in rows]


@router.get("/http", response_model=list[HttpEventRead])
def list_http(
    capture_id: str,
    limit: int = 500,
    db: Session = Depends(get_db),
) -> list[HttpEventRead]:
    """Return normalized HTTP events for a capture."""
    _require_capture(db, capture_id)
    rows = (
        db.query(HttpEvent)
        .filter(HttpEvent.capture_id == capture_id)
        .order_by(HttpEvent.ts.asc())
        .limit(limit)
        .all()
    )
    return [HttpEventRead.model_validate(r) for r in rows]


@router.get("/packets", response_model=list[PacketRead])
def list_packets(
    capture_id: str,
    limit: int = 500,
    db: Session = Depends(get_db),
) -> list[PacketRead]:
    """Return normalized packets for a capture."""
    _require_capture(db, capture_id)
    rows = (
        db.query(Packet)
        .filter(Packet.capture_id == capture_id)
        .order_by(Packet.ts.asc())
        .limit(limit)
        .all()
    )
    return [PacketRead.model_validate(r) for r in rows]
