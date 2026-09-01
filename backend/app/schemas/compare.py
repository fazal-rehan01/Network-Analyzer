"""Pydantic schemas for the Wireshark/TShark vs Zeek comparison (M13).

The comparison presents the *same* traffic from two analytical perspectives:
packet-level (TShark/Wireshark) and event-level (Zeek). Each side contains only
the evidence that actually exists for a connection -- unmatched/absent sides are
reported honestly rather than fabricated.
"""
from __future__ import annotations

from pydantic import BaseModel


class TsharkSide(BaseModel):
    present: bool = False
    description: str = "Packet-level evidence (TShark / Wireshark)"
    src: str | None = None
    dst: str | None = None
    proto: str | None = None
    sport: int | None = None
    dport: int | None = None
    packet_count: int = 0
    bytes: int = 0
    first_ts: float | None = None
    last_ts: float | None = None
    packets: list[dict] = []


class ZeekConnSide(BaseModel):
    present: bool = False
    uid: str | None = None
    service: str | None = None
    conn_state: str | None = None
    duration: float | None = None
    orig_bytes: int | None = None
    resp_bytes: int | None = None
    src: str | None = None
    dst: str | None = None
    proto: str | None = None
    sport: int | None = None
    dport: int | None = None


class ZeekSide(BaseModel):
    present: bool = False
    description: str = "Event-level evidence (Zeek)"
    uid: str | None = None
    conn: ZeekConnSide | None = None
    dns: list[dict] = []
    http: list[dict] = []
    ssl: list[dict] = []
    notices: list[dict] = []
    event_count: int = 0


class ConnectionComparison(BaseModel):
    id: str
    src: str | None = None
    dst: str | None = None
    proto: str | None = None
    sport: int | None = None
    dport: int | None = None
    service: str | None = None
    packets: int = 0
    bytes_total: int = 0
    zeek_uid: str | None = None
    source: str = "tshark"
    correlation_status: str = "tshark_only"
    correlation_summary: str = ""
    tshark: TsharkSide = TsharkSide()
    zeek: ZeekSide = ZeekSide()
    evidence: dict[str, list[str]] = {}


class CaptureComparisonSummary(BaseModel):
    connections_total: int = 0
    both: int = 0
    tshark_only: int = 0
    zeek_only: int = 0
    packets_tshark: int = 0
    zeek_events: int = 0


class CaptureComparison(BaseModel):
    capture_id: str
    capture_name: str | None = None
    tshark_available: bool = False
    zeek_available: bool = False
    summary: CaptureComparisonSummary = CaptureComparisonSummary()
    connections: list[dict] = []


class CompareStatus(BaseModel):
    tshark_available: bool = False
    zeek_available: bool = False
