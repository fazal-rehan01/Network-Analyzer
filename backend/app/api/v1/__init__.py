"""API v1 router aggregator."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import captures, normalize, simulations, system, zeek

api_router = APIRouter()
api_router.include_router(system.router)
api_router.include_router(simulations.router)
api_router.include_router(captures.router)
api_router.include_router(zeek.router)
api_router.include_router(normalize.router)
