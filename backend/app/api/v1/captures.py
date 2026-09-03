"""Packet capture endpoints (live capture driven by TShark)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.capture import Capture
from app.schemas.capture import CaptureCreate, CaptureRead, CaptureStats, InterfaceInfo
from app.services import capture as cap_svc
from app.utils.timeutil import utcnow
import uuid

router = APIRouter(prefix="/captures", tags=["captures"])


def _to_read(cap: Capture) -> CaptureRead:
    return CaptureRead(
        id=cap.id,
        name=cap.name,
        source=cap.source,
        filename=cap.filename,
        file_path=cap.file_path,
        interface=cap.interface,
        filter_expr=cap.filter_expr,
        start_time=cap.start_time,
        end_time=cap.end_time,
        duration_sec=cap.duration_sec,
        packet_count=cap.packet_count,
        byte_count=cap.byte_count,
        status=cap.status,
        error=cap.error,
        created_at=cap.created_at,
    )


@router.get("/interfaces", response_model=list[InterfaceInfo])
def list_interfaces() -> list[InterfaceInfo]:
    """List available capture interfaces via tshark -D."""
    return cap_svc.list_interfaces()


@router.get("", response_model=list[CaptureRead])
def list_captures(db: Session = Depends(get_db)) -> list[CaptureRead]:
    rows = db.execute(
        select(Capture).order_by(Capture.created_at.desc()).limit(100)
    ).scalars().all()
    return [_to_read(c) for c in rows]


@router.post("", response_model=CaptureRead, status_code=201)
def start_capture(payload: CaptureCreate, db: Session = Depends(get_db)) -> CaptureRead:
    if payload.interface_index is None:
        raise HTTPException(status_code=400, detail="interface_index is required")
    try:
        cap = cap_svc.start_live_capture(
            db,
            name=payload.name or "",
            interface_index=payload.interface_index,
            filter_expr=payload.filter_expr,
            duration_sec=payload.duration_sec,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return _to_read(cap)


@router.get("/{capture_id}", response_model=CaptureRead)
def get_capture(capture_id: str, db: Session = Depends(get_db)) -> CaptureRead:
    cap = db.get(Capture, capture_id)
    if cap is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return _to_read(cap)


@router.get("/{capture_id}/stats", response_model=CaptureStats)
def get_capture_stats(capture_id: str, db: Session = Depends(get_db)) -> CaptureStats:
    cap = db.get(Capture, capture_id)
    if cap is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    if cap.status == "running":
        raise HTTPException(status_code=409, detail="Capture still in progress")
    return cap_svc.get_capture_stats(cap)


@router.post("/{capture_id}/stop", response_model=CaptureRead)
def stop_capture(capture_id: str, db: Session = Depends(get_db)) -> CaptureRead:
    cap = db.get(Capture, capture_id)
    if cap is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    if cap.status == "running":
        cap_svc.stop_live_capture(capture_id)
        db.refresh(cap)
    return _to_read(cap)


@router.post("/upload", response_model=CaptureRead, status_code=201)
async def upload_capture(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> CaptureRead:
    if not file.filename or not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="File must be a PCAP/PCAPNG capture")

    settings = get_settings()
    upload_dir = settings.upload_dir_abs
    upload_dir.mkdir(parents=True, exist_ok=True)

    safe_name = f"upload-{uuid.uuid4().hex[:8]}-{file.filename}"
    dest = upload_dir / safe_name

    content = await file.read()
    if len(content) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_upload_mb} MB limit")
    dest.write_bytes(content)

    stats = cap_svc.analyze_pcap(dest)

    cap = Capture(
        name=file.filename,
        source="upload",
        filename=file.filename,
        file_path=str(dest),
        interface=None,
        filter_expr=None,
        start_time=None,
        end_time=None,
        duration_sec=None,
        packet_count=stats.packet_count,
        byte_count=stats.byte_count,
        status="done",
    )
    db.add(cap)
    db.commit()
    db.refresh(cap)
    return _to_read(cap)


@router.delete("/{capture_id}", status_code=204)
def delete_capture(capture_id: str, db: Session = Depends(get_db)):
    cap = db.get(Capture, capture_id)
    if cap is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    if cap.status == "running":
        cap_svc.stop_live_capture(capture_id)
    db.delete(cap)
    db.commit()
    if cap.file_path:
        path = Path(cap.file_path)
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass
    return None
