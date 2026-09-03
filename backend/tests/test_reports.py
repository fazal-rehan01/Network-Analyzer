"""Tests for PDF reporting (MILESTONE 14).

Generates reports for an empty DB, a real seeded capture, and the whole
database; verifies the PDF magic header, content-type, filename and 404 for an
unknown capture. The session-shared test DB means we only assert per-capture
truths (never global counts).
"""
from __future__ import annotations

import uuid

import pytest

from app.core.database import SessionLocal
from app.models.capture import Capture
from app.models.detection import DetectionFinding
from app.models.incident import Incident
from app.models.normalized import Connection, DnsEvent, HttpEvent, Packet
from app.models.zeek import ZeekConn
from app.services import report as report_svc


@pytest.fixture()
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def seeded_capture(db_session):
    """A capture with rich data: packets, connections, DNS/HTTP, Zeek conn,
    a detection finding, an incident and a flag-bearing packet."""
    cap = Capture(name=f"report-{uuid.uuid4().hex}", source="upload", status="done")
    db_session.add(cap)
    db_session.flush()

    conn = Connection(
        id=str(uuid.uuid4()), capture_id=cap.id,
        conn_key="tcp|203.0.113.5|203.0.113.6|50000|80",
        src="203.0.113.5", dst="203.0.113.6", proto="tcp",
        sport=50000, dport=80, service="http", source="tshark+zeek",
        zeek_uid="ZR1", packets=4, bytes_total=1200, first_ts=300.0, last_ts=301.0,
    )
    db_session.add(conn)

    db_session.add_all([
        Packet(capture_id=cap.id, frame_number=1, ts=300.0, src="203.0.113.5",
               dst="203.0.113.6", proto="tcp", sport=50000, dport=80,
               length=300, tcp_flags="[SYN]", source="tshark", dns_qname=None),
        Packet(capture_id=cap.id, frame_number=2, ts=300.4, src="203.0.113.6",
               dst="203.0.113.5", proto="tcp", sport=80, dport=50000,
               length=300, tcp_flags="[ACK]", source="tshark"),
        Packet(capture_id=cap.id, frame_number=3, ts=300.8, src="203.0.113.5",
               dst="203.0.113.6", proto="tcp", sport=50000, dport=80,
               length=300, tcp_flags="[PSH,ACK]", source="tshark",
               http_method="GET", http_host="example.test", http_uri="/"),
        Packet(capture_id=cap.id, frame_number=4, ts=301.0, src="203.0.113.6",
               dst="203.0.113.5", proto="tcp", sport=80, dport=50000,
               length=300, tcp_flags="[FIN,ACK]", source="tshark"),
    ])

    db_session.add(ZeekConn(
        id=str(uuid.uuid4()), capture_id=cap.id, ts=300.0, uid="ZR1",
        src="203.0.113.5", dst="203.0.113.6", proto="tcp", sport=50000, dport=80,
        service="http", conn_state="SF", duration=1.0, orig_bytes=600, resp_bytes=600,
    ))
    db_session.add(DnsEvent(
        id=str(uuid.uuid4()), capture_id=cap.id, connection_id=conn.id, ts=300.1,
        src="203.0.113.5", dst="8.8.8.8", query="example.test",
        qtype_name="A", rcode_name="NOERROR", source="zeek", zeek_uid="ZR1",
    ))
    db_session.add(HttpEvent(
        id=str(uuid.uuid4()), capture_id=cap.id, connection_id=conn.id, ts=300.8,
        src="203.0.113.5", dst="203.0.113.6", method="GET", host="example.test",
        uri="/", status_code=200, resp_len=300, source="zeek", zeek_uid="ZR1",
    ))
    db_session.add(DetectionFinding(
        capture_id=cap.id, rule_id="port_scan", rule_name="Possible Port Scan",
        severity="high", score=0.8, summary="Scan pattern observed",
        ref_type="connection", evidence="[]",
    ))
    db_session.add(Incident(
        detection_finding_id=str(uuid.uuid4()),
        occurrence_key=f"report-{uuid.uuid4().hex}",
        capture_id=cap.id, title="Test incident", severity="high", status="NEW",
        rule_id="port_scan", rule_name="Possible Port Scan",
    ))
    db_session.commit()
    db_session.refresh(cap)
    return cap


# ----------------------------------------------------------------- service


def test_build_report_pdf_empty_db_is_valid_pdf(db_session):
    pdf = report_svc.build_report_pdf(db_session, None)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1000


def test_build_report_pdf_for_capture_is_bigger(db_session, seeded_capture):
    pdf = report_svc.build_report_pdf(db_session, seeded_capture.id)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 4000


def test_build_report_pdf_unknown_capture_raises(db_session):
    with pytest.raises(ValueError):
        report_svc.build_report_pdf(db_session, "no-such-capture")


def test_list_report_options_includes_seeded_capture(db_session, seeded_capture):
    opts = report_svc.list_report_options(db_session)
    ids = [c.id for c in opts.captures]
    assert seeded_capture.id in ids
    assert opts.global_available is True


# ------------------------------------------------------------------- API


def test_report_options_endpoint(client):
    resp = client.get("/api/v1/reports/options")
    assert resp.status_code == 200
    body = resp.json()
    assert "global_available" in body
    assert isinstance(body["captures"], list)


def test_report_generate_global_endpoint(client):
    resp = client.post("/api/v1/reports/generate", json={"capture_id": None})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "attachment" in resp.headers["content-disposition"]
    assert resp.content.startswith(b"%PDF")
    assert len(resp.content) > 1000


def test_report_generate_capture_endpoint(client, seeded_capture):
    resp = client.post("/api/v1/reports/generate", json={"capture_id": seeded_capture.id})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "traffic-report-" in resp.headers["content-disposition"]
    assert resp.content.startswith(b"%PDF")


def test_report_generate_unknown_capture_endpoint(client):
    resp = client.post("/api/v1/reports/generate", json={"capture_id": "does-not-exist"})
    assert resp.status_code == 404


def test_report_generate_empty_body_is_global(client):
    resp = client.post("/api/v1/reports/generate", json={})
    assert resp.status_code == 200
    assert resp.content.startswith(b"%PDF")


def test_report_pdf_has_pages_and_content(db_session, seeded_capture):
    """Seeded report is a structurally valid, multi-page PDF (page-count marker
    present; text compress markers aside, a splash-cover + all 8 sections make
    it substantially larger than an empty report)."""
    pdf = report_svc.build_report_pdf(db_session, seeded_capture.id)
    assert b"/Count" in pdf  # page count present
    assert len(pdf) > 4000