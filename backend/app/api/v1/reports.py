"""Report endpoints: options + PDF generation (MILESTONE 14)."""
from __future__ import annotations

import re
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.capture import Capture
from app.schemas.report import ReportGenerateRequest, ReportOptions
from app.services import report as report_svc

router = APIRouter(prefix="/reports", tags=["reports"])


def _slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_-]+", "-", value)
    return value.strip("-").lower() or "traffic"


@router.get("/options", response_model=ReportOptions)
def report_options(db: Session = Depends(get_db)) -> ReportOptions:
    """Available scopes (whole-database + every capture) for the Reports UI."""
    return report_svc.list_report_options(db)


@router.post("/generate")
def generate_report(
    payload: ReportGenerateRequest,
    db: Session = Depends(get_db),
) -> Response:
    """Build and return a PDF security analysis report for the requested scope."""
    if payload.capture_id:
        cap = db.get(Capture, payload.capture_id)
        if cap is None:
            raise HTTPException(status_code=404, detail="Capture not found")
        scope = _slug(cap.name or cap.id)
    else:
        scope = "all-captures"

    try:
        pdf = report_svc.build_report_pdf(db, payload.capture_id)
    except Exception as exc:  # defensive: a PDF bug must not 500-cheat the client
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}") from exc

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"traffic-report-{scope}-{stamp}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )