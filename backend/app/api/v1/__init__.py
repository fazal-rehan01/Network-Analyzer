"""API v1 router aggregator."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    analytics,
    captures,
    compare,
    detect,
    incidents,
    normalize,
    reports,
    simulations,
    system,
    zeek,
)

api_router = APIRouter()
api_router.include_router(system.router)
api_router.include_router(simulations.router)
api_router.include_router(captures.router)
api_router.include_router(zeek.router)
api_router.include_router(normalize.router)
api_router.include_router(detect.router)
api_router.include_router(incidents.router)
api_router.include_router(analytics.router)
api_router.include_router(compare.router)
api_router.include_router(reports.router)
