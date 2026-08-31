"""Shared UTC datetime helpers.

SQLite stores datetimes without a timezone, so we standardise on *naive* UTC
datetimes throughout to avoid aware/naive subtraction errors.
"""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Return the current UTC time as a naive datetime (no tzinfo)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
