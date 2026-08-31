"""API v1 router aggregator."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import system

api_router = APIRouter()
api_router.include_router(system.router)
