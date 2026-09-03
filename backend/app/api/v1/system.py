"""Health and system status endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.schemas.system import ComponentStatus, HealthResponse, SystemStatusResponse
from app.utils.tools import all_tool_status

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    """Liveness + database reachability check."""
    database = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001
        database = "error"
    cfg = get_settings()
    return HealthResponse(
        status="ok" if database == "ok" else "degraded",
        app=cfg.app_name,
        database=database,
        version="0.1.0",
    )


@router.get("/system/status", response_model=SystemStatusResponse)
def system_status() -> SystemStatusResponse:
    """Report availability of external tools (TShark, Zeek, Docker, Python)."""
    components = all_tool_status()
    installed = sum(1 for c in components if c.installed)
    return SystemStatusResponse(
        status="ready" if installed >= len(components) - 1 else "degraded",
        components=[ComponentStatus(**c.to_dict()) for c in components],
    )
