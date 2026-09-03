"""Analytics/dashboard aggregation endpoints (MILESTONE 12).

Aggregations are computed server-side from the real database so the browser
never has to download huge normalized datasets. Supports a global scope (all
captures) or a single-capture scope via ``capture_id``.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.capture import Capture
from app.schemas.analytics import DashboardAnalytics
from app.services import analytics as analytics_svc

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/dashboard", response_model=DashboardAnalytics)
def dashboard(
    capture_id: str | None = None, db: Session = Depends(get_db)
) -> DashboardAnalytics:
    """Aggregated analytics for the dashboard (global or per-capture)."""
    if capture_id is not None:
        cap = db.get(Capture, capture_id)
        if cap is None:
            raise HTTPException(status_code=404, detail="Capture not found")
    return analytics_svc.dashboard_analytics(db, capture_id=capture_id)
