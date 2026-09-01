"""Pydantic schemas for the analytics/dashboard aggregation (M12).

These describe the aggregated payloads computed from the real database by
``app.services.analytics``. Every value is derived from persisted records
(captures, packets, connections, dns/http events, detections, incidents) --
never fabricated.
"""
from __future__ import annotations

from pydantic import BaseModel


class AnalyticsSummary(BaseModel):
    captures: int = 0
    packets: int = 0
    connections: int = 0
    bytes_total: int = 0
    packets_per_sec: float = 0.0
    open_incidents: int = 0
    high_critical_incidents: int = 0
    resolved_incidents: int = 0


class ProtocolSlice(BaseModel):
    proto: str
    count: int = 0
    bytes: int = 0


class TalkerSlice(BaseModel):
    ip: str
    packets: int = 0
    bytes: int = 0


class ConversationSlice(BaseModel):
    src: str
    dst: str
    proto: str = ""
    packets: int = 0
    bytes: int = 0


class TrafficPoint(BaseModel):
    ts: int
    packets: int = 0
    bytes: int = 0


class DnsStats(BaseModel):
    total: int = 0
    unique_queries: int = 0
    by_rcode: dict[str, int] = {}
    top_queries: list[dict] = []


class HttpStats(BaseModel):
    total: int = 0
    by_method: dict[str, int] = {}
    by_status: dict[str, int] = {}
    top_hosts: list[dict] = []


class SeverityCount(BaseModel):
    total: int = 0
    info: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0


class DashboardAnalytics(BaseModel):
    scope: str = "global"
    capture_id: str | None = None
    summary: AnalyticsSummary = AnalyticsSummary()
    protocol_distribution: list[ProtocolSlice] = []
    top_sources: list[TalkerSlice] = []
    top_destinations: list[TalkerSlice] = []
    top_conversations: list[ConversationSlice] = []
    traffic_over_time: list[TrafficPoint] = []
    dns_stats: DnsStats = DnsStats()
    http_stats: HttpStats = HttpStats()
    detection: SeverityCount = SeverityCount()
    incidents: SeverityCount = SeverityCount()
    recent_incidents: list[dict] = []
