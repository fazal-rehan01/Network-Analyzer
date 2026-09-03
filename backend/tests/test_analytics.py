"""Tests for the real-database analytics aggregation (MILESTONE 12).

Verifies the service computes aggregates directly from persisted normalized
data, packets, detections and incidents -- never fabricated. Because the test
DB is shared across files, deterministic assertions use a per-capture scope with
a unique capture id; the global scope is checked for structure/types only.
"""
from __future__ import annotations

import uuid

import pytest

from app.core.database import SessionLocal
from app.models.incident import Incident
from app.models.capture import Capture
from app.models.detection import DetectionFinding as FindingRow
from app.models.normalized import Connection, DnsEvent, HttpEvent, Packet
from app.services import analytics as analytics_svc


@pytest.fixture()
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _mk_incident(capture_id: str, severity: str, status: str) -> Incident:
    return Incident(
        id=str(uuid.uuid4()),
        detection_finding_id=f"find-{uuid.uuid4().hex}",
        occurrence_key=str(uuid.uuid4()),
        capture_id=capture_id,
        title="analytics incident",
        severity=severity,
        status=status,
    )


@pytest.fixture()
def seeded_analytics(db_session):
    """Unique capture with a known mix of normalized data for deterministic checks."""
    cap = Capture(name=f"analytics-{uuid.uuid4().hex}", source="upload", status="done")
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)
    cid = cap.id

    # Packets: 3 per second over 2 seconds (ts 1000,1001).
    packets = [
        Packet(capture_id=cid, ts=1000.0, src="10.0.0.1", dst="10.0.0.2", proto="tcp",
               sport=1, dport=80, length=60, source="tshark"),
        Packet(capture_id=cid, ts=1000.5, src="10.0.0.1", dst="10.0.0.2", proto="tcp",
               sport=1, dport=80, length=40, source="tshark"),
        Packet(capture_id=cid, ts=1001.0, src="10.0.0.1", dst="10.0.0.3", proto="udp",
               sport=2, dport=53, length=30, source="tshark"),
    ]
    db_session.add_all(packets)

    # Connections.
    conns = [
        Connection(capture_id=cid, conn_key="tcp|10.0.0.1|10.0.0.2|1|80",
                   src="10.0.0.1", dst="10.0.0.2", proto="tcp", sport=1, dport=80,
                   packets=10, bytes_total=1000, first_ts=1000.0, last_ts=1001.0, source="tshark"),
        Connection(capture_id=cid, conn_key="tcp|10.0.0.1|10.0.0.3|2|53",
                   src="10.0.0.1", dst="10.0.0.3", proto="udp", sport=2, dport=53,
                   packets=5, bytes_total=200, first_ts=1000.0, last_ts=1002.0, source="tshark"),
    ]
    db_session.add_all(conns)

    # DNS events.
    db_session.add_all([
        DnsEvent(capture_id=cid, src="10.0.0.1", dst="8.8.8.8", query="a.example", rcode_name="NOERROR", source="zeek"),
        DnsEvent(capture_id=cid, src="10.0.0.1", dst="8.8.8.8", query="a.example", rcode_name="NOERROR", source="zeek"),
        DnsEvent(capture_id=cid, src="10.0.0.1", dst="8.8.8.8", query="b.example", rcode_name="NXDOMAIN", source="zeek"),
    ])

    # HTTP events.
    db_session.add_all([
        HttpEvent(capture_id=cid, src="10.0.0.1", dst="10.0.0.2", method="GET", host="web.test", status_code=200, source="zeek"),
        HttpEvent(capture_id=cid, src="10.0.0.1", dst="10.0.0.2", method="POST", host="web.test", status_code=500, source="zeek"),
    ])

    # Detection findings by severity.
    db_session.add_all([
        FindingRow(capture_id=cid, rule_id="port_scan", rule_name="Port scan", severity="high", score=8.0),
        FindingRow(capture_id=cid, rule_id="dns_anomaly", rule_name="DNS anomaly", severity="medium", score=5.0),
        FindingRow(capture_id=cid, rule_id="dns_anomaly", rule_name="DNS anomaly", severity="info", score=2.0),
    ])

    # Incidents by severity + status (one resolved critical, one open high).
    db_session.add_all([
        _mk_incident(cid, "critical", "RESOLVED"),
        _mk_incident(cid, "high", "INVESTIGATING"),
    ])
    db_session.commit()
    return cid


def test_empty_capture_scope_returns_zeros(db_session):
    cap = Capture(name=f"empty-{uuid.uuid4().hex}", source="upload", status="done")
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)
    a = analytics_svc.dashboard_analytics(db_session, capture_id=cap.id)
    assert a.summary.packets == 0
    assert a.summary.connections == 0
    assert a.summary.bytes_total == 0
    assert a.protocol_distribution == []
    assert a.top_sources == []
    assert a.traffic_over_time == []
    assert a.dns_stats.total == 0
    assert a.http_stats.total == 0
    assert a.detection.total == 0
    assert a.incidents.total == 0
    assert a.recent_incidents == []


def test_summary_counts(seeded_analytics, db_session):
    a = analytics_svc.dashboard_analytics(db_session, capture_id=seeded_analytics)
    s = a.summary
    assert s.packets == 3
    assert s.connections == 2
    assert s.bytes_total == 1200  # sum of connection bytes
    assert s.captures == 1
    assert s.open_incidents == 1
    assert s.high_critical_incidents == 2
    assert s.resolved_incidents == 1


def test_protocol_distribution(seeded_analytics, db_session):
    a = analytics_svc.dashboard_analytics(db_session, capture_id=seeded_analytics)
    by_proto = {p.proto: p for p in a.protocol_distribution}
    assert by_proto["tcp"].count == 1
    assert by_proto["tcp"].bytes == 1000
    assert by_proto["udp"].count == 1


def test_top_talkers_and_conversations(seeded_analytics, db_session):
    a = analytics_svc.dashboard_analytics(db_session, capture_id=seeded_analytics)
    assert a.top_sources[0].ip == "10.0.0.1"
    assert a.top_sources[0].packets == 2
    dst_ips = {t.ip for t in a.top_destinations}
    assert {"10.0.0.2", "10.0.0.3"} <= dst_ips
    # conversations sorted by bytes desc
    assert a.top_conversations[0].src == "10.0.0.1"
    assert a.top_conversations[0].dst == "10.0.0.2"
    assert a.top_conversations[0].bytes == 1000


def test_traffic_over_time(seeded_analytics, db_session):
    a = analytics_svc.dashboard_analytics(db_session, capture_id=seeded_analytics)
    points = a.traffic_over_time
    assert len(points) >= 2
    total_packets = sum(p.packets for p in points)
    assert total_packets == 3
    total_bytes = sum(p.bytes for p in points)
    assert total_bytes == 130  # 60+40+30


def test_dns_stats(seeded_analytics, db_session):
    a = analytics_svc.dashboard_analytics(db_session, capture_id=seeded_analytics)
    d = a.dns_stats
    assert d.total == 3
    assert d.unique_queries == 2
    assert d.by_rcode.get("NOERROR") == 2
    assert d.by_rcode.get("NXDOMAIN") == 1
    assert any(t["query"] == "a.example" and t["count"] == 2 for t in d.top_queries)


def test_http_stats(seeded_analytics, db_session):
    a = analytics_svc.dashboard_analytics(db_session, capture_id=seeded_analytics)
    h = a.http_stats
    assert h.total == 2
    assert h.by_method.get("GET") == 1
    assert h.by_method.get("POST") == 1
    assert h.by_status.get("200") == 1
    assert h.by_status.get("500") == 1
    assert h.top_hosts[0]["host"] == "web.test"


def test_detection_and_incident_counts(seeded_analytics, db_session):
    a = analytics_svc.dashboard_analytics(db_session, capture_id=seeded_analytics)
    assert a.detection.total == 3
    assert a.detection.high == 1
    assert a.detection.medium == 1
    assert a.detection.info == 1
    assert a.incidents.total == 2
    assert a.incidents.critical == 1
    assert a.incidents.high == 1
    assert len(a.recent_incidents) == 2


def test_traffic_downsample_capped(db_session):
    cap = Capture(name=f"big-{uuid.uuid4().hex}", source="upload", status="done")
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)
    for i in range(500, 5000):
        db_session.add(Packet(
            capture_id=cap.id, ts=float(i), src="1.1.1.1", dst="2.2.2.2",
            proto="tcp", length=50, source="tshark",
        ))
    db_session.commit()
    a = analytics_svc.dashboard_analytics(db_session, capture_id=cap.id)
    assert len(a.traffic_over_time) <= 120
    assert sum(p.packets for p in a.traffic_over_time) == 4500


def test_global_scope_returns_structured_payload(seeded_analytics, db_session):
    a = analytics_svc.dashboard_analytics(db_session)
    assert a.scope == "global"
    # Structure/types only -- global counts are cumulative across the shared DB.
    assert a.summary.packets >= 0
    assert isinstance(a.protocol_distribution, list)
    assert isinstance(a.dns_stats.by_rcode, dict)
    assert isinstance(a.incidents.total, int)
    assert a.capture_id is None


# --------------------------------------------------------------- API endpoints


def test_analytics_dashboard_endpoint(client, seeded_analytics):
    resp = client.get("/api/v1/analytics/dashboard", params={"capture_id": seeded_analytics})
    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"]["packets"] == 3
    assert body["summary"]["connections"] == 2
    assert body["summary"]["bytes_total"] == 1200
    assert len(body["protocol_distribution"]) == 2
    assert len(body["traffic_over_time"]) >= 2
    assert body["dns_stats"]["total"] == 3
    assert body["http_stats"]["total"] == 2
    assert body["detection"]["total"] == 3
    assert body["incidents"]["total"] == 2
    assert len(body["recent_incidents"]) == 2


def test_analytics_endpoint_global(client):
    resp = client.get("/api/v1/analytics/dashboard")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scope"] == "global"
    assert "summary" in body
    assert "top_sources" in body
    assert "top_conversations" in body


def test_analytics_endpoint_invalid_capture(client):
    resp = client.get("/api/v1/analytics/dashboard", params={"capture_id": "does-not-exist"})
    assert resp.status_code == 404
