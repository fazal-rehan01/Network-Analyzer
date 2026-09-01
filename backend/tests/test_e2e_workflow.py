"""End-to-end security analysis workflow (MILESTONE 15).

One real, deterministic workflow exercised from the public API on a real PCAP
parsed by the installed TShark: capture -> normalize/correlate -> detect ->
incident -> analytics -> compare -> report PDF. It asserts honest invariants at
each stage (evidence points at real normalized rows, correlations are real,
the PDF is a valid non-trivial document). Skipped only when TShark is missing.
"""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from app.analysis.tshark import tshark_available
from app.core.database import SessionLocal
from app.models.capture import Capture
from app.models.incident import Incident
from app.models.normalized import Connection
from app.services import normalize as norm_svc
from tests.test_detection_integration import build_trigger_pcap


@pytest.fixture()
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_full_e2e_security_analysis_workflow(tmp_path, db_session, client):
    if not tshark_available():
        pytest.skip("TShark not installed; cannot parse a real PCAP")

    # 1. Real PCAP -> metadata + normalize (TShark parse + correlate).
    pcap = tmp_path / "e2e.pcap"
    build_trigger_pcap(pcap)
    cap = Capture(
        name=f"e2e-{uuid.uuid4().hex}", source="upload", status="done", file_path=str(pcap)
    )
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)

    norm = norm_svc.normalize_capture(db_session, pcap, capture_id=cap.id)
    assert norm.packets_parsed >= 19
    conns = db_session.query(Connection).filter(Connection.capture_id == cap.id).all()
    assert len(conns) >= 12

    # 2. Detection via API; findings reference the real normalized rows.
    run = client.post("/api/v1/detect/run", params={"capture_id": cap.id})
    assert run.status_code == 200
    body = run.json()
    assert body["findings"] >= 2

    findings = client.get("/api/v1/detect/findings", params={"capture_id": cap.id}).json()
    by_rule = {f["rule_id"]: f for f in findings}
    assert "port_scan" in by_rule and "dns_anomaly" in by_rule
    conn_ids = {c.id for c in conns}
    for ev in by_rule["port_scan"]["evidence"]:
        assert ev["type"] == "connection"
        assert ev["id"] in conn_ids

    # 3. Incident lifecycle on a real finding.
    inc = client.post(
        "/api/v1/incidents/from-finding",
        json={"detection_finding_id": by_rule["port_scan"]["id"], "title": "e2e incident"},
    ).json()["incident"]
    assert inc["capture_id"] == cap.id
    detail = client.get(f"/api/v1/incidents/{inc['id']}").json()
    assert detail["evidence_resolved"], "incident must resolve evidence to real records"

    # 4. Analytics reflect this capture (per-capture scope is deterministic).
    anal = client.get("/api/v1/analytics/dashboard", params={"capture_id": cap.id})
    assert anal.status_code == 200
    a = anal.json()
    assert a["scope"] == "capture"
    assert a["capture_id"] == cap.id
    assert a["summary"]["connections"] >= 12
    assert a["summary"]["packets"] >= 19
    assert a["detection"]["total"] >= 2
    assert a["traffic_over_time"]
    assert any(r["id"] == inc["id"] for r in a["recent_incidents"])

    # 5. Comparison over the same capture: TShark side is real for every row.
    comp = client.get(f"/api/v1/compare/capture/{cap.id}")
    assert comp.status_code == 200
    c = comp.json()
    assert c["summary"]["connections_total"] >= 12
    assert c["summary"]["packets_tshark"] >= 19
    assert all(r["correlation_status"] in {"both", "tshark_only", "zeek_only"} for r in c["connections"])
    # At least one row is real packet evidence (guaranteed by the PCAP).
    assert c["summary"]["tshark_only"] + c["summary"]["both"] >= 1

    # A real connection's packet-level detail matches its normalized record.
    sample_id = c["connections"][0]["id"]
    conn_detail = client.get(f"/api/v1/compare/connection/{sample_id}")
    assert conn_detail.status_code == 200
    d = conn_detail.json()
    assert d["tshark"]["present"] is True
    assert d["tshark"]["packet_count"] >= 1
    assert d["tshark"]["packets"][0]["src"]
    assert isinstance(d["zeek"]["present"], bool)

    # 6. Reporting: the PDF for this capture is a valid, substantial document.
    opts = client.get("/api/v1/reports/options").json()
    assert cap.id in {o["id"] for o in opts["captures"]}
    pdf = client.post("/api/v1/reports/generate", json={"capture_id": cap.id})
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF")
    assert len(pdf.content) > 4000

    # 7. The incident created above is real and triageable in the dashboard scope.
    incidents = client.get("/api/v1/incidents", params={"status": "NEW"})
    assert incidents.status_code == 200
    assert any(i["id"] == inc["id"] for i in incidents.json()["items"])
    assert db_session.query(Incident).filter(Incident.id == inc["id"]).count() == 1


def test_e2e_compare_status_and_global_report(client):
    """Tool availability + whole-database report are always reachable."""
    st = client.get("/api/v1/compare/status")
    assert st.status_code == 200
    body = st.json()
    assert "tshark_available" in body and "zeek_available" in body

    pdf = client.post("/api/v1/reports/generate", json={"capture_id": None})
    assert pdf.status_code == 200
    assert pdf.content.startswith(b"%PDF")
    assert len(pdf.content) > 1000