"""Centralized enums/constants for the incident workflow (MILESTONE 11).

Keeping these in one place avoids scattering arbitrary status/severity strings
throughout the codebase. Shared by the ORM models, schemas, service, and API.
"""
from __future__ import annotations

# Severity values are shared with the M10 detection engine.
SEVERITY_VALUES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

INCIDENT_STATUSES: tuple[str, ...] = (
    "NEW",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
    "FALSE_POSITIVE",
)

# Statuses that count as "open" (still being worked).
OPEN_STATUSES: tuple[str, ...] = ("NEW", "INVESTIGATING", "CONTAINED")

# Statuses that close an incident (populate closed_at / resolution).
CLOSED_STATUSES: tuple[str, ...] = ("RESOLVED", "FALSE_POSITIVE")

# Explicit, deliberate transition map. Backwards steps are only allowed where
# noted (reopen paths), otherwise rejected by the service layer.
ALLOWED_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "NEW": ("INVESTIGATING",),
    "INVESTIGATING": ("CONTAINED", "RESOLVED", "FALSE_POSITIVE"),
    "CONTAINED": ("RESOLVED", "INVESTIGATING"),  # reopen contained -> investigate
    "RESOLVED": ("INVESTIGATING",),  # deliberate reopen of a resolved incident
    "FALSE_POSITIVE": ("INVESTIGATING",),  # deliberate reopen of a mis-classified FP
}

INCIDENT_EVENT_TYPES: tuple[str, ...] = (
    "created",
    "status_changed",
    "assigned",
    "note_added",
    "resolved",
    "marked_false_positive",
    "reopened",
)

# Rule-id suffix -> normalized model type (used to resolve evidence references).
EVIDENCE_MODEL_KEYS: tuple[str, ...] = ("connection", "dns", "http", "packet")