"""Tests for the normalization/correlation layer (MILESTONE 9).

Two tracks:
* Fixture-driven correlation tests run regardless of installed tools — they
  validate the canonical 5-tuple key, Zeek conn->Connection correlation, and
  Zeek dns/http -> DnsEvent/HttpEvent promotion against the real-format Zeek
  TSV fixtures.
* A live TShark test (skipped when TShark is absent) builds a small PCAP by
  hand and confirms TShark packet evidence is parsed and normalized without
  fabricating data.
"""
from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest

from app.analysis.tshark import parse_packets, tshark_available
from app.analysis.zeek import LOG_TYPES, parse_zeek_tsv, zeek_available
from app.core.database import SessionLocal
from app.models.capture import Capture
from app.models.normalized import Connection, DnsEvent, HttpEvent
from app.services import normalize as normalize_svc

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
def zeek_seeded_capture(db_session):
    """Create a capture and persist all Zeek fixture logs to it."""
    cap = Capture(name="normalize-zeek", source="upload", status="done")
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)
    logs = {t: parse_zeek_tsv(_fixture(t)) for t in LOG_TYPES}
    from app.services import zeek as zeek_svc

    zeek_svc.persist_logs(db_session, cap.id, logs)
    return cap.id


# ---------------------------------------------------------------- key logic


def test_canonical_conn_key_direction_agnostic():
    a = normalize_svc.canonical_conn_key("10.0.0.1", "10.0.0.2", "tcp", 1234, 80)
    b = normalize_svc.canonical_conn_key("10.0.0.2", "10.0.0.1", "tcp", 80, 1234)
    assert a == b
    # Different port changes the key.
    c = normalize_svc.canonical_conn_key("10.0.0.1", "10.0.0.2", "tcp", 9999, 80)
    assert a != c
    # Protocol participates.
    d = normalize_svc.canonical_conn_key("10.0.0.1", "10.0.0.2", "udp", 1234, 80)
    assert a != d


def test_canonical_conn_key_matches_zeek_orig_resp():
    # Zeek conn row orig=192.168.1.20:54321 resp=8.8.8.8:53 has same key as
    # the reverse-direction packet.
    zeek_key = normalize_svc.canonical_conn_key("192.168.1.20", "8.8.8.8", "udp", 54321, 53)
    pkt_key = normalize_svc.canonical_conn_key("8.8.8.8", "192.168.1.20", "udp", 53, 54321)
    assert zeek_key == pkt_key


# ------------------------------------------------- Zeek -> Connection merge


def test_zeek_conn_to_connections(db_session, zeek_seeded_capture):
    matched = normalize_svc.correlate_zeek_conn(db_session, zeek_seeded_capture)
    assert matched == 3

    conns = (
        db_session.query(Connection)
        .filter(Connection.capture_id == zeek_seeded_capture)
        .all()
    )
    assert len(conns) == 3

    by_uid = {c.zeek_uid: c for c in conns}
    c1 = by_uid["C1"]
    assert c1.service == "http"
    assert c1.conn_state == "SF"
    assert c1.orig_bytes == 520
    assert c1.resp_bytes == 1350
    c3 = by_uid["C3"]
    assert c3.service == "dns"
    assert c3.proto == "udp"


# ------------------------------------------------ Zeek dns/http promotion


def test_zeek_dns_promoted_with_connection(db_session, zeek_seeded_capture):
    normalize_svc.correlate_zeek_conn(db_session, zeek_seeded_capture)
    count = normalize_svc.promote_zeek_dns(db_session, zeek_seeded_capture)
    assert count == 2

    events = (
        db_session.query(DnsEvent)
        .filter(DnsEvent.capture_id == zeek_seeded_capture)
        .all()
    )
    by_query = {e.query: e for e in events}
    ok = by_query["example.com"]
    assert ok.zeek_uid == "C3"
    assert ok.rcode_name == "NOERROR"
    # The C3 query shares a connection with the C3 conn row (matched by uid).
    assert ok.connection_id is not None
    assert ok.source == "zeek"

    nx = by_query["nonexistent.invalid"]
    assert nx.zeek_uid == "C4"
    assert nx.rcode_name == "NXDOMAIN"
    # No C4 conn row exists and the 5-tuple has no matching connection.
    assert nx.connection_id is None


def test_zeek_http_promoted_with_connection(db_session, zeek_seeded_capture):
    normalize_svc.correlate_zeek_conn(db_session, zeek_seeded_capture)
    count = normalize_svc.promote_zeek_http(db_session, zeek_seeded_capture)
    assert count == 2

    events = (
        db_session.query(HttpEvent)
        .filter(HttpEvent.capture_id == zeek_seeded_capture)
        .all()
    )
    by_uri = {e.uri: e for e in events}
    index = by_uri["/index.html"]
    assert index.zeek_uid == "C1"
    assert index.method == "GET"
    assert index.host == "example.com"
    assert index.status_code == 200
    assert index.connection_id is not None  # matched to C1 conn by uid

    login = by_uri["/login.php"]
    assert login.zeek_uid == "C5"
    assert login.connection_id is None  # no matching conn row


def test_idempotent_rerun(db_session, zeek_seeded_capture):
    normalize_svc.correlate_zeek_conn(db_session, zeek_seeded_capture)
    normalize_svc.promote_zeek_dns(db_session, zeek_seeded_capture)
    normalize_svc.promote_zeek_http(db_session, zeek_seeded_capture)
    # Rerun promotion: dedup by (uid, query)/(uid, uri) keeps counts stable.
    d2 = normalize_svc.promote_zeek_dns(db_session, zeek_seeded_capture)
    h2 = normalize_svc.promote_zeek_http(db_session, zeek_seeded_capture)
    assert d2 == 0
    assert h2 == 0


# ------------------------------------------------------- live TShark parsing


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _ipv4(src, dst, proto, payload: bytes) -> bytes:
    total = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, 0x1234, 0, 64, proto, 0,
        bytes(int(o) for o in src.split(".")),
        bytes(int(o) for o in dst.split(".")),
    )
    chk = _checksum(header)
    header = header[:10] + struct.pack("!H", chk) + header[12:]
    return header + payload


def build_test_pcap(path: Path) -> None:
    """Write a small valid PCAP with an HTTP request and a DNS query."""
    records = []
    now = time.time()

    # HTTP request frame.
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    tcp = struct.pack(
        "!HHIIBBHHH", 12340, 80, 1, 1, 0x50, 0x18, 65535, 0, 0
    ) + http_payload
    ip = _ipv4("10.0.0.5", "10.0.0.6", 6, tcp)
    eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00" + ip
    records.append((now, eth))

    # DNS query frame (A record for example.com over UDP).
    name = b"\x07example\x03com\x00"
    dns = struct.pack("!HHHHHH", 0x3039, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
    ip = _ipv4("10.0.0.5", "10.0.0.6", 17, udp)
    eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00" + ip
    records.append((now + 0.1, eth))

    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in records:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)


def test_tshark_parse_real_pcap(tmp_path):
    if not tshark_available():
        pytest.skip("TShark not installed")
    pcap = tmp_path / "sample.pcap"
    build_test_pcap(pcap)
    packets = parse_packets(pcap)
    assert len(packets) == 2

    http = next(p for p in packets if p.http_method == "GET")
    assert http.src == "10.0.0.5"
    assert http.dst == "10.0.0.6"
    assert http.http_host == "example.com"
    assert http.http_uri == "/index.html"
    assert http.sport == 12340
    assert http.dport == 80
    assert http.proto == "tcp"

    dns = next(p for p in packets if p.dns_qname is not None)
    assert dns.dns_qname == "example.com"
    assert dns.proto == "udp"
    assert dns.sport == 53000
    assert dns.dport == 53


def test_tshark_missing_pcap_degrades(tmp_path):
    if not tshark_available():
        pytest.skip("TShark not installed")
    assert parse_packets(tmp_path / "nope.pcap") == []


def test_tshark_to_normalized_pipeline(tmp_path, db_session):
    if not tshark_available():
        pytest.skip("TShark not installed")
    cap = Capture(name="normalize-tshark", source="upload", status="done",
                  file_path=str(tmp_path / "sample.pcap"))
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)
    build_test_pcap(Path(cap.file_path))

    summary = normalize_svc.normalize_capture(db_session, Path(cap.file_path), capture_id=cap.id)
    assert summary.packets_parsed == 2
    assert summary.packets_persisted == 2
    assert summary.connections == 2  # HTTP flow + DNS flow (different ports)
    assert summary.tshark_available is True

    conns = (
        db_session.query(Connection).filter(Connection.capture_id == cap.id).all()
    )
    assert {c.proto for c in conns} == {"tcp", "udp"}
    tcp_conn = next(c for c in conns if c.proto == "tcp")
    assert tcp_conn.zeek_uid is None  # no Zeek evidence -> not fabricated

    dns_events = (
        db_session.query(DnsEvent).filter(DnsEvent.capture_id == cap.id).all()
    )
    assert len(dns_events) == 1
    assert dns_events[0].source == "tshark"
    assert dns_events[0].query == "example.com"
    assert dns_events[0].connection_id is not None

    http_events = (
        db_session.query(HttpEvent).filter(HttpEvent.capture_id == cap.id).all()
    )
    assert len(http_events) == 1
    assert http_events[0].source == "tshark"
    assert http_events[0].method == "GET"


def test_normalize_status_endpoint(client):
    resp = client.get("/api/v1/normalize/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tshark_available"] is tshark_available()
    assert "zeek_available" in body


def test_normalize_run_missing_capture(client):
    resp = client.post("/api/v1/normalize/run", params={"capture_id": "nope"})
    assert resp.status_code == 404


def test_tshark_path_works_without_zeek(tmp_path, db_session):
    """When Zeek is absent (or simply not run), TShark evidence still normalizes."""
    if not tshark_available():
        pytest.skip("TShark not installed")
    cap = Capture(name="normalize-nok", source="upload", status="done",
                  file_path=str(tmp_path / "sample.pcap"))
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)
    build_test_pcap(Path(cap.file_path))
    summary = normalize_svc.normalize_capture(db_session, Path(cap.file_path), capture_id=cap.id)
    assert summary.connections == 2
    assert summary.dns_events == 1
    assert summary.http_events == 1
