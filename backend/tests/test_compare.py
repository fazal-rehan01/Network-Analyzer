"""Tests for the Wireshark/TShark vs Zeek comparison (MILESTONE 13).

Uses the real-format Zeek TSV fixtures plus hand-seeded TShark packet evidence to
verify: pure-Zeek state, pure-TShark state, matched (both) state, missing
evidence handled honestly, and the API endpoints. Zeek need not be installed --
fixtures simulate Zeek log output just as ``test_normalize`` does.
"""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from app.analysis.zeek import LOG_TYPES, parse_zeek_tsv
from app.core.database import SessionLocal
from app.models.capture import Capture
from app.models.normalized import Connection, DnsEvent, HttpEvent, Packet
from app.models.zeek import ZeekConn
from app.services import compare as compare_svc
from app.services import normalize as normalize_svc
from app.services import zeek as zeek_svc

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(log_type: str):
    return FIXTURES / f"zeek_{log_type}.log"


@pytest.fixture()
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def zeek_only_capture(db_session):
    """Capture with only Zeek fixture logs: 3 connections, no TShark packets."""
    cap = Capture(name=f"compare-zeek-{uuid.uuid4().hex}", source="upload", status="done")
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)
    logs = {t: parse_zeek_tsv(_fixture(t)) for t in LOG_TYPES}
    zeek_svc.persist_logs(db_session, cap.id, logs)
    normalize_svc.correlate_zeek_conn(db_session, cap.id)
    normalize_svc.promote_zeek_dns(db_session, cap.id)
    normalize_svc.promote_zeek_http(db_session, cap.id)
    db_session.commit()
    return cap.id


@pytest.fixture()
def tshark_only_capture(db_session):
    """Capture with a TShark-derived connection + packets, no Zeek rows."""
    cap = Capture(name=f"compare-tshark-{uuid.uuid4().hex}", source="upload", status="done")
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)
    conn = Connection(
        id=str(uuid.uuid4()),
        capture_id=cap.id,
        conn_key="tcp|10.0.0.1|10.0.0.2|12345|8080",
        src="10.0.0.1", dst="10.0.0.2", proto="tcp", sport=12345, dport=8080,
        packets=2, bytes_total=300, first_ts=100.0, last_ts=100.5,
        source="tshark",
    )
    db_session.add(conn)
    db_session.add_all([
        Packet(capture_id=cap.id, frame_number=1, ts=100.0, src="10.0.0.1", dst="10.0.0.2",
               proto="tcp", sport=12345, dport=8080, length=150, source="tshark", tcp_flags="[SYN]"),
        Packet(capture_id=cap.id, frame_number=2, ts=100.5, src="10.0.0.1", dst="10.0.0.2",
               proto="tcp", sport=12345, dport=8080, length=150, source="tshark", tcp_flags="[ACK]"),
    ])
    db_session.commit()
    return {"capture_id": cap.id, "connection_id": conn.id}


@pytest.fixture()
def both_capture(db_session):
    """Capture where a connection has both TShark packets and Zeek evidence."""
    cap = Capture(name=f"compare-both-{uuid.uuid4().hex}", source="upload", status="done")
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)
    conn = Connection(
        id=str(uuid.uuid4()),
        capture_id=cap.id,
        conn_key="tcp|192.0.2.1|192.0.2.2|40000|443",
        src="192.0.2.1", dst="192.0.2.2", proto="tcp", sport=40000, dport=443,
        packets=3, bytes_total=900, first_ts=200.0, last_ts=201.0,
        source="tshark+zeek", zeek_uid="Z9", service="ssl",
    )
    db_session.add(conn)
    db_session.add_all([
        Packet(capture_id=cap.id, frame_number=10, ts=200.0, src="192.0.2.1", dst="192.0.2.2",
               proto="tcp", sport=40000, dport=443, length=300, source="tshark"),
    ])
    db_session.add(ZeekConn(
        id=str(uuid.uuid4()), capture_id=cap.id, ts=200.0, uid="Z9",
        src="192.0.2.1", dst="192.0.2.2", proto="tcp", sport=40000, dport=443,
        service="ssl", duration=1.0, orig_bytes=400, resp_bytes=500, conn_state="SF",
    ))
    db_session.add(DnsEvent(
        id=str(uuid.uuid4()), capture_id=cap.id, connection_id=conn.id, ts=200.2,
        src="192.0.2.1", dst="8.8.8.8", query="example.org", rcode_name="NOERROR",
        source="zeek", zeek_uid="ZD1",
    ))
    db_session.commit()
    return {"capture_id": cap.id, "connection_id": conn.id}


# ------------------------------------------------------------- capture-level


def test_compare_zeek_only_summary(zeek_only_capture, db_session):
    comp = compare_svc.compare_capture(db_session, zeek_only_capture)
    assert comp is not None
    assert comp.summary.connections_total == 3
    assert comp.summary.zeek_only == 3
    assert comp.summary.both == 0
    assert comp.summary.tshark_only == 0
    assert comp.summary.zeek_events >= 1
    # Zeek availability reported honestly from the environment.
    assert isinstance(comp.zeek_available, bool)


def test_compare_tshark_only_summary(tshark_only_capture, db_session):
    comp = compare_svc.compare_capture(db_session, tshark_only_capture["capture_id"])
    assert comp.summary.connections_total == 1
    assert comp.summary.tshark_only == 1
    assert comp.summary.packets_tshark == 2
    row = comp.connections[0]
    assert row["correlation_status"] == "tshark_only"
    assert row["zeek_uid"] is None


def test_compare_both_summary(both_capture, db_session):
    comp = compare_svc.compare_capture(db_session, both_capture["capture_id"])
    assert comp.summary.connections_total == 1
    assert comp.summary.both == 1


# -------------------------------------------------------- connection-level


def test_compare_connection_pure_zeek(zeek_only_capture, db_session):
    conn = db_session.query(Connection).filter(Connection.capture_id == zeek_only_capture).first()
    detail = compare_svc.compare_connection(db_session, conn.id)
    assert detail.correlation_status == "zeek_only"
    # TShark side honestly absent; Zeek side present.
    assert detail.tshark.present is False
    assert detail.zeek.present is True
    assert detail.zeek.conn is not None


def test_compare_connection_tshark_only(tshark_only_capture, db_session):
    res = compare_svc.compare_connection(db_session, tshark_only_capture["connection_id"])
    assert res.correlation_status == "tshark_only"
    assert res.tshark.present is True
    assert res.tshark.packet_count == 2
    assert len(res.tshark.packets) == 2
    assert res.tshark.packets[0]["frame_number"] == 1
    assert res.zeek.present is False
    # Correlation summary is honest about the missing Zeek side.
    assert "TShark" in res.correlation_summary


def test_compare_connection_both(both_capture, db_session):
    res = compare_svc.compare_connection(db_session, both_capture["connection_id"])
    assert res.correlation_status == "both"
    assert res.tshark.present is True
    assert res.zeek.present is True
    assert res.zeek.conn is not None
    assert res.zeek.conn.uid == "Z9"
    assert res.zeek.conn.service == "ssl"
    assert len(res.zeek.dns) == 1
    assert res.zeek.dns[0]["query"] == "example.org"
    # Both sides' evidence referenced.
    assert res.evidence["tshark"]
    assert res.evidence["zeek"]


def test_compare_connection_dns_evidence_linked(zeek_only_capture, db_session):
    conn = db_session.query(Connection).filter(Connection.capture_id == zeek_only_capture).first()
    detail = compare_svc.compare_connection(db_session, conn.id)
    # DNS events correlated to this connection appear on the Zeek side.
    dns = db_session.query(DnsEvent).filter(DnsEvent.connection_id == conn.id).all()
    assert len(detail.zeek.dns) == len(dns)


# ---------------------------------------------------------------- API layer


def test_compare_status_endpoint(client):
    resp = client.get("/api/v1/compare/status")
    assert resp.status_code == 200
    body = resp.json()
    assert "tshark_available" in body
    assert "zeek_available" in body


def test_compare_capture_endpoint(client, zeek_only_capture):
    resp = client.get(f"/api/v1/compare/capture/{zeek_only_capture}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["capture_id"] == zeek_only_capture
    assert body["summary"]["connections_total"] == 3
    assert len(body["connections"]) == 3


def test_compare_capture_endpoint_missing(client):
    resp = client.get("/api/v1/compare/capture/does-not-exist")
    assert resp.status_code == 404


def test_compare_connection_endpoint(client, tshark_only_capture):
    resp = client.get(f"/api/v1/compare/connection/{tshark_only_capture['connection_id']}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["correlation_status"] == "tshark_only"
    assert body["tshark"]["present"] is True
    assert body["zeek"]["present"] is False


def test_compare_connection_endpoint_missing(client):
    resp = client.get("/api/v1/compare/connection/does-not-exist")
    assert resp.status_code == 404
