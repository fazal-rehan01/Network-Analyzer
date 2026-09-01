"""Real-database analytics aggregation (MILESTONE 12).

Computes dashboard analytics directly from persisted records using grouped SQL
queries. No fake/static numbers, no second analytics data layer -- every value
traces to captures/packets/connections/dns/http/detections/incidents.

Designed to avoid N+1 patterns: counts/sums are computed with GROUP BY, only
top-N rows are returned, and per-capture vs global scoping reuses the same code
with an optional capture filter.
"""
from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.capture import Capture
from app.models.detection import DetectionFinding
from app.models.incident import Incident
from app.models.normalized import Connection, DnsEvent, HttpEvent, Packet
from app.schemas.analytics import (
    AnalyticsSummary,
    ConversationSlice,
    DashboardAnalytics,
    DnsStats,
    HttpStats,
    ProtocolSlice,
    SeverityCount,
    TalkerSlice,
    TrafficPoint,
)

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
OPEN_STATUSES = ("NEW", "INVESTIGATING", "CONTAINED")
TOP_N = 10


def _severity_counts(rows: list[tuple[str]]) -> SeverityCount:
    counts = {s: 0 for s in SEVERITY_ORDER}
    total = 0
    for (sev,) in rows:
        if sev in counts:
            counts[sev] += 1
        total += 1
    return SeverityCount(total=total, **counts)


def _summary(db: Session, capture_id: str | None) -> AnalyticsSummary:
    """Global / per-capture headline counters (efficient grouped queries)."""
    cap_q = db.query(Capture)
    if capture_id:
        cap_q = cap_q.filter(Capture.id == capture_id)

    captures = cap_q.count()

    packet_q = db.query(func.count(Packet.id), func.sum(Packet.length))
    conn_q = db.query(func.count(Connection.id), func.sum(Connection.bytes_total))
    if capture_id:
        packet_q = packet_q.filter(Packet.capture_id == capture_id)
        conn_q = conn_q.filter(Connection.capture_id == capture_id)
    packets, packet_bytes = packet_q.first() or (0, None)
    conns, conn_bytes = conn_q.first() or (0, None)
    packets = int(packets or 0)
    conns = int(conns or 0)
    bytes_total = int((conn_bytes or packet_bytes or 0) or 0)

    # Time span from connection first/last timestamps for a rate denominator.
    ts_q = db.query(
        func.min(Connection.first_ts), func.max(Connection.last_ts)
    )
    if capture_id:
        ts_q = ts_q.filter(Connection.capture_id == capture_id)
    first_ts, last_ts = ts_q.first() or (None, None)
    duration = 0.0
    if first_ts and last_ts and last_ts > first_ts:
        duration = float(last_ts - first_ts)
    pps = (packets / duration) if duration > 0 else 0.0

    inc_q = db.query(Incident)
    open_inc = inc_q.filter(Incident.status.in_(OPEN_STATUSES))
    hi_crit = inc_q.filter(Incident.severity.in_(("high", "critical")))
    resolved = inc_q.filter(Incident.status == "RESOLVED")
    if capture_id:
        open_inc = open_inc.filter(Incident.capture_id == capture_id)
        hi_crit = hi_crit.filter(Incident.capture_id == capture_id)
        resolved = resolved.filter(Incident.capture_id == capture_id)

    return AnalyticsSummary(
        captures=int(captures),
        packets=int(packets),
        connections=int(conns),
        bytes_total=int(bytes_total),
        packets_per_sec=round(pps, 2),
        open_incidents=int(open_inc.count()),
        high_critical_incidents=int(hi_crit.count()),
        resolved_incidents=int(resolved.count()),
    )


def _protocol_distribution(db: Session, capture_id: str | None) -> list[ProtocolSlice]:
    """Top protocols by connection count, with aggregate bytes."""
    q = db.query(
        Connection.proto,
        func.count(Connection.id),
        func.sum(Connection.bytes_total),
    ).group_by(Connection.proto)
    if capture_id:
        q = q.filter(Connection.capture_id == capture_id)
    rows = q.order_by(func.count(Connection.id).desc()).limit(TOP_N).all()
    return [
        ProtocolSlice(
            proto=proto or "unknown",
            count=int(count),
            bytes=int(bytes or 0),
        )
        for proto, count, bytes in rows
    ]


def _top_talkers(
    db: Session, capture_id: str | None, column, label: str
) -> list[TalkerSlice]:
    q = db.query(
        column,
        func.count(column),
        func.sum(Connection.bytes_total),
    ).group_by(column)
    if capture_id:
        q = q.filter(Connection.capture_id == capture_id)
    rows = q.order_by(func.count(column).desc()).limit(TOP_N).all()
    return [
        TalkerSlice(ip=ip or label, packets=int(count), bytes=int(bytes or 0))
        for ip, count, bytes in rows
    ]


def _top_conversations(db: Session, capture_id: str | None) -> list[ConversationSlice]:
    q = db.query(
        Connection.src,
        Connection.dst,
        Connection.proto,
        Connection.packets,
        Connection.bytes_total,
    )
    if capture_id:
        q = q.filter(Connection.capture_id == capture_id)
    rows = (
        q.order_by(Connection.bytes_total.desc())
        .limit(TOP_N)
        .all()
    )
    return [
        ConversationSlice(
            src=src or "?",
            dst=dst or "?",
            proto=proto or "",
            packets=int(pkts or 0),
            bytes=int(b or 0),
        )
        for src, dst, proto, pkts, b in rows
    ]


def _traffic_over_time(db: Session, capture_id: str | None, max_points: int = 120) -> list[TrafficPoint]:
    """Per-second packet traffic buckets, collapsed to at most ``max_points``
    evenly-spaced segments so a large capture never floods the browser."""
    q = db.query(Packet.ts, Packet.length)
    if capture_id:
        q = q.filter(Packet.capture_id == capture_id)
    rows = q.order_by(Packet.ts.asc()).all()
    if not rows:
        return []
    buckets: dict[int, list[int]] = {}
    for ts, length in rows:
        if ts is None:
            continue
        bucket = int(ts)
        buckets.setdefault(bucket, [0, 0])
        buckets[bucket][0] += 1
        buckets[bucket][1] += int(length or 0)

    ordered = sorted(buckets.items())
    if len(ordered) <= max_points:
        return [
            TrafficPoint(ts=ts, packets=cnt, bytes=byt)
            for ts, (cnt, byt) in ordered
        ]
    # Downsample: spread the full time span into exactly max_points equal-width
    # bins (float width so every packet is preserved, none dropped).
    first, last = ordered[0][0], ordered[-1][0]
    span = last - first
    width = max(1.0, span / float(max_points))
    merged: dict[int, TrafficPoint] = {}
    for ts, (cnt, byt) in ordered:
        idx = min(int((ts - first) / width), max_points - 1)
        cur = merged.setdefault(idx, TrafficPoint(ts=first + idx))
        cur.packets += cnt
        cur.bytes += byt
    merged_list = list(merged.values())
    merged_list.sort(key=lambda p: p.ts)
    return merged_list[:max_points]


def _dns_stats(db: Session, capture_id: str | None) -> DnsStats:
    base = db.query(DnsEvent)
    if capture_id:
        base = base.filter(DnsEvent.capture_id == capture_id)

    total = base.count()

    uniq_q = db.query(func.count(func.distinct(DnsEvent.query)))
    if capture_id:
        uniq_q = uniq_q.filter(DnsEvent.capture_id == capture_id)
    unique_queries = int(uniq_q.scalar() or 0)

    rcode_q = db.query(DnsEvent.rcode_name, func.count(DnsEvent.id)).group_by(DnsEvent.rcode_name)
    if capture_id:
        rcode_q = rcode_q.filter(DnsEvent.capture_id == capture_id)
    by_rcode = {rcode or "?" : int(c) for rcode, c in rcode_q.all()}

    top_q = db.query(DnsEvent.query, func.count(DnsEvent.id)).group_by(DnsEvent.query)
    if capture_id:
        top_q = top_q.filter(DnsEvent.capture_id == capture_id)
    top_q = top_q.order_by(func.count(DnsEvent.id).desc()).limit(5)
    top_queries = [
        {"query": query or "?", "count": int(count)} for query, count in top_q.all()
    ]

    return DnsStats(
        total=int(total),
        unique_queries=unique_queries,
        by_rcode=by_rcode,
        top_queries=top_queries,
    )


def _http_stats(db: Session, capture_id: str | None) -> HttpStats:
    base_q = db.query(func.count(HttpEvent.id))
    if capture_id:
        base_q = base_q.filter(HttpEvent.capture_id == capture_id)
    total = int(base_q.scalar() or 0)

    method_q = db.query(HttpEvent.method, func.count(HttpEvent.id)).group_by(HttpEvent.method)
    if capture_id:
        method_q = method_q.filter(HttpEvent.capture_id == capture_id)
    by_method = {m or "?" : int(c) for m, c in method_q.all()}

    status_q = db.query(HttpEvent.status_code, func.count(HttpEvent.id)).group_by(HttpEvent.status_code)
    if capture_id:
        status_q = status_q.filter(HttpEvent.capture_id == capture_id)
    by_status = {f"{s}" if s is not None else "?" : int(c) for s, c in status_q.all()}

    host_q = db.query(HttpEvent.host, func.count(HttpEvent.id)).group_by(HttpEvent.host)
    if capture_id:
        host_q = host_q.filter(HttpEvent.capture_id == capture_id)
    host_q = host_q.order_by(func.count(HttpEvent.id).desc()).limit(5)
    top_hosts = [{"host": h or "?", "count": int(c)} for h, c in host_q.all()]

    return HttpStats(total=total, by_method=by_method, by_status=by_status, top_hosts=top_hosts)


def _detection_counts(db: Session, capture_id: str | None) -> SeverityCount:
    q = db.query(DetectionFinding.severity)
    if capture_id:
        q = q.filter(DetectionFinding.capture_id == capture_id)
    return _severity_counts(q.all())


def _incident_counts(db: Session, capture_id: str | None) -> SeverityCount:
    q = db.query(Incident.severity)
    if capture_id:
        q = q.filter(Incident.capture_id == capture_id)
    return _severity_counts(q.all())


def _recent_incidents(db: Session, capture_id: str | None, limit: int = 5) -> list[dict]:
    q = db.query(Incident)
    if capture_id:
        q = q.filter(Incident.capture_id == capture_id)
    q = q.order_by(Incident.created_at.desc()).limit(limit)
    return [
        {
            "id": r.id,
            "title": r.title,
            "severity": r.severity,
            "status": r.status,
            "rule_name": r.rule_name,
            "rule_id": r.rule_id,
            "capture_id": r.capture_id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in q.all()
    ]


def dashboard_analytics(db: Session, capture_id: str | None = None) -> DashboardAnalytics:
    """Compute a complete analytics payload for the requested scope."""
    return DashboardAnalytics(
        scope="capture" if capture_id else "global",
        capture_id=capture_id,
        summary=_summary(db, capture_id),
        protocol_distribution=_protocol_distribution(db, capture_id),
        top_sources=_top_talkers(db, capture_id, Connection.src, "source"),
        top_destinations=_top_talkers(db, capture_id, Connection.dst, "destination"),
        top_conversations=_top_conversations(db, capture_id),
        traffic_over_time=_traffic_over_time(db, capture_id),
        dns_stats=_dns_stats(db, capture_id),
        http_stats=_http_stats(db, capture_id),
        detection=_detection_counts(db, capture_id),
        incidents=_incident_counts(db, capture_id),
        recent_incidents=_recent_incidents(db, capture_id),
    )
