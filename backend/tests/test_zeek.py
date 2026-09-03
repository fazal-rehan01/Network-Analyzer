"""Tests for Zeek integration (MILESTONE 8).

Zeek is optional on dev machines, so these tests validate the parser and
pipeline logic against realistic Zeek log fixtures (the TSV format Zeek writes)
regardless of whether the Zeek binary is installed. Graceful degradation when
Zeek is missing is also covered.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.analysis.zeek import LOG_TYPES, parse_zeek_tsv, process_pcap, zeek_available
from app.core.database import SessionLocal
from app.models.capture import Capture
from app.models.zeek import ZEK_MODEL_BY_TYPE
from app.services import zeek as zeek_svc

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(log_type: str) -> Path:
    return FIXTURES / f"zeek_{log_type}.log"


@pytest.fixture()
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def persisted_capture_id(db_session):
    """Create a capture row and persist all fixture logs to it."""
    cap = Capture(name="zeek-test", source="upload", status="done")
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)
    cap_id = cap.id

    logs = {t: parse_zeek_tsv(_fixture(t)) for t in LOG_TYPES}
    zeek_svc.persist_logs(db_session, cap_id, logs)
    return cap_id


def test_available_log_types_defined():
    assert set(LOG_TYPES) == {"conn", "dns", "http", "ssl", "notice"}


def test_models_registered_for_each_log_type():
    assert set(ZEK_MODEL_BY_TYPE.keys()) == set(LOG_TYPES)


@pytest.mark.parametrize("log_type,expected_rows", [
    ("conn", 3),
    ("dns", 2),
    ("http", 2),
    ("ssl", 1),
    ("notice", 1),
])
def test_parse_zeek_tsv_fixtures(log_type, expected_rows):
    rows = parse_zeek_tsv(_fixture(log_type))
    assert len(rows) == expected_rows


def test_parse_zeek_tsv_fields():
    rows = parse_zeek_tsv(_fixture("conn"))
    row = rows[0]
    assert row["id.orig_h"] == "192.168.1.10"
    assert row["proto"] == "tcp"
    assert row["conn_state"] == "SF"
    assert row["uid"] == "C1"


def test_parse_zeek_tsv_missing_file(tmp_path):
    assert parse_zeek_tsv(tmp_path / "nope.log") == []


def test_parse_zeek_tsv_vector_fields():
    # The answers field is a comma-joined vector; it should be preserved as-is.
    rows = parse_zeek_tsv(_fixture("dns"))
    assert rows[0]["answers"] == "93.184.216.34"


def test_process_pcap_missing_zeek_degrades(tmp_path):
    if zeek_available():
        pytest.skip("Zeek installed; degradation path not exercised")
    pcap = tmp_path / "fake.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
    result = process_pcap(pcap, workdir=tmp_path / "out")
    assert result["available"] is False
    assert result["error"]
    assert result["logs"] == {}
    # summary should still list all 5 known log types as absent.
    assert {s["log_type"] for s in result["summary"]} == set(LOG_TYPES)


def test_persist_logs_counts(persisted_capture_id, db_session):
    from app.models import zeek as zeek_models
    counts = {
        t: db_session.query(ZEK_MODEL_BY_TYPE[t]).filter(
            ZEK_MODEL_BY_TYPE[t].capture_id == persisted_capture_id
        ).count()
        for t in LOG_TYPES
    }
    assert counts == {"conn": 3, "dns": 2, "http": 2, "ssl": 1, "notice": 1}


def test_persist_logs_normalizes_values(persisted_capture_id, db_session):
    db_events = zeek_svc.events_for_capture(db_session, persisted_capture_id, log_type="conn")
    assert len(db_events) == 3
    conn = db_events[0]
    assert conn["fields"]["id.orig_p"] == 52345
    assert conn["fields"]["id.resp_p"] == 80
    assert conn["src"] == "192.168.1.10"
    assert conn["dst"] == "93.184.216.34"
    assert conn["ts"] == 1609459200.0


def test_dns_rcode_nxdomain(persisted_capture_id, db_session):
    events = zeek_svc.events_for_capture(db_session, persisted_capture_id, log_type="dns")
    rcodes = {e["fields"].get("rcode_name") for e in events}
    assert "NXDOMAIN" in rcodes


def test_notice_fields(persisted_capture_id, db_session):
    events = zeek_svc.events_for_capture(db_session, persisted_capture_id, log_type="notice")
    assert len(events) == 1
    fields = events[0]["fields"]
    assert fields["note"] == "DNS::NXDOMAIN"
    assert fields["id.orig_p"] == 54321
    assert fields["id.resp_p"] == 53


def test_http_mapping(persisted_capture_id, db_session):
    events = zeek_svc.events_for_capture(db_session, persisted_capture_id, log_type="http")
    assert len(events) == 2
    first = events[0]["fields"]
    assert first["method"] == "GET"
    assert first["host"] == "example.com"
    assert first["status_code"] == 200


def test_events_unknown_log_type(db_session):
    assert zeek_svc.events_for_capture(db_session, "nope", log_type="bogus") == []


def _seed_via_service(db):
    """Create a capture row and persist all fixture logs; return (cap_id, counts)."""
    cap = Capture(name="zeek-api-test", source="upload", status="done")
    db.add(cap)
    db.commit()
    db.refresh(cap)
    cap_id = cap.id
    logs = {t: parse_zeek_tsv(_fixture(t)) for t in LOG_TYPES}
    counts = zeek_svc.persist_logs(db, cap_id, logs)
    return cap_id, counts


def test_zeek_status_endpoint(client):
    resp = client.get("/api/v1/zeek/status")
    assert resp.status_code == 200
    body = resp.json()
    assert "available" in body
    assert "zeek_dir" in body


def test_zeek_process_missing_capture(client):
    resp = client.post("/api/v1/zeek/process", params={"capture_id": "nope"})
    assert resp.status_code == 404


def test_zeek_events_endpoint(client):
    # Seed a capture + events via the service directly.
    db = SessionLocal()
    try:
        cap_id, _ = _seed_via_service(db)
    finally:
        db.close()
    resp = client.get("/api/v1/zeek/events", params={"capture_id": cap_id})
    assert resp.status_code == 200
    events = resp.json()
    assert isinstance(events, list)
    assert any(e["log_type"] == "conn" for e in events)


def test_zeek_events_bad_log_type(client):
    resp = client.get("/api/v1/zeek/events", params={"capture_id": "x", "log_type": "bogus"})
    assert resp.status_code == 400
