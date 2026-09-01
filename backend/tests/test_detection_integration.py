"""End-to-end detection integration (MILESTONE 10).

Builds a real PCAP with TCP SYNs to many distinct ports and NXDOMAIN DNS
responses, parses it with the installed TShark via the M9 normalize pipeline,
then runs detection and confirms the findings are based on real normalized
records (evidence ids point at actual Connection/DnsEvent rows).

This uses the project's real TShark PCAP pipeline (not synthetic in-memory
rule fixtures). Skipped only when TShark is genuinely unavailable.
"""
from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest

from app.analysis.tshark import tshark_available
from app.core.database import SessionLocal
from app.models.capture import Capture
from app.models.detection import DetectionFinding as FindingRow
from app.models.normalized import Connection, DnsEvent
from app.services import normalize as norm_svc


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
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


def _frame(payload: bytes) -> bytes:
    eth = b"\x00" * 6 + b"\x00" * 6 + b"\x08\x00"
    return eth + payload


def build_trigger_pcap(path: Path) -> None:
    """A PCAP that genuinely triggers port_scan and dns_anomaly."""
    records = []
    now = time.time()

    # 12 TCP SYN packets to distinct destination ports (port scan evidence).
    for i, sport in enumerate(range(12340, 12352)):
        dport = 80 + i
        tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x02, 65535, 0, 0)
        records.append((now + i * 0.001, _frame(_ipv4("10.0.0.5", "10.0.0.6", 6, tcp))))

    # 7 DNS responses with rcode=3 (NXDOMAIN) to distinct names.
    for i in range(7):
        qname = f"q{i}.invalid".encode("ascii")
        labels = b"".join(bytes([len(part)]) + part for part in qname.split(b".")) + b"\x00"
        dns = struct.pack("!HHHHHH", 0x4000 + i, 0x8003, 1, 1, 0, 0) + labels + struct.pack("!HH", 1, 1)
        udp = struct.pack("!HHHH", 53000 + i, 53, 8 + len(dns), 0) + dns
        records.append((now + 100.0 + i * 0.001, _frame(_ipv4("10.0.0.5", "10.0.0.6", 17, udp))))

    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in records:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)


@pytest.fixture()
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_tshark_end_to_end_detection(tmp_path, db_session, client):
    if not tshark_available():
        pytest.skip("TShark not installed; cannot parse a real PCAP")

    # 1. Build a real PCAP and normalize it through the M9 pipeline.
    pcap = tmp_path / "trigger.pcap"
    build_trigger_pcap(pcap)

    cap = Capture(name="detect-e2e", source="upload", status="done", file_path=str(pcap))
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)

    summary = norm_svc.normalize_capture(db_session, pcap, capture_id=cap.id)
    assert summary.packets_parsed >= 19
    conn_ids = {r.id for r in db_session.query(Connection).filter(Connection.capture_id == cap.id).all()}
    dns_ids = {r.id for r in db_session.query(DnsEvent).filter(DnsEvent.capture_id == cap.id).all()}
    assert len(conn_ids) >= 12
    assert len(dns_ids) >= 7

    # 2. Run detection and inspect the API result.
    run_resp = client.post("/api/v1/detect/run", params={"capture_id": cap.id})
    assert run_resp.status_code == 200
    body = run_resp.json()
    assert body["findings"] >= 2

    findings = client.get("/api/v1/detect/findings", params={"capture_id": cap.id}).json()
    by_rule = {f["rule_id"]: f for f in findings}
    assert "port_scan" in by_rule
    assert "dns_anomaly" in by_rule

    # 3. Evidence must reference real normalized records.
    port_scan = by_rule["port_scan"]
    assert port_scan["evidence"]
    for ev in port_scan["evidence"]:
        assert ev["type"] == "connection"
        assert ev["id"] in conn_ids

    dns = by_rule["dns_anomaly"]
    assert dns["evidence"]
    for ev in dns["evidence"]:
        assert ev["type"] == "dns"
        assert ev["id"] in dns_ids

    # 4. Summary endpoint reflects persisted findings.
    summary_resp = client.get("/api/v1/detect/summary", params={"capture_id": cap.id}).json()
    assert summary_resp["total"] == body["findings"]

    # 5. Idempotent re-run via API: same count, no duplicates.
    run2 = client.post("/api/v1/detect/run", params={"capture_id": cap.id}).json()
    assert run2["findings"] == body["findings"]
    total_db = db_session.query(FindingRow).filter(
        FindingRow.capture_id == cap.id
    ).count()
    assert total_db == body["findings"]
