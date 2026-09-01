"""Tests for the incident management workflow (MILESTONE 11).

Incidents are created from M10 DetectionFindings, tracked through a validated
lifecycle (NEW -> INVESTIGATING -> CONTAINED -> RESOLVED, or -> FALSE_POSITIVE),
gain analyst notes, and retain full traceability back to the finding and its
normalized evidence. Creation from a finding is idempotent (no duplicates).
These tests use the real SQLite database (same engine as the API).
"""
from __future__ import annotations

import json
import uuid

import pytest

from app.core.database import SessionLocal
from app.core.enums import INCIDENT_STATUSES
from app.models.capture import Capture
from app.models.detection import DetectionFinding as FindingRow
from app.models.incident import Incident, IncidentEvent, IncidentNote
from app.models.normalized import Connection
from app.services import incident as incident_svc


def make_capture(db, name="inc-test"):
    cap = Capture(name=name, source="upload", status="done")
    db.add(cap)
    db.commit()
    db.refresh(cap)
    return cap


def make_finding(db, capture_id, rule_id="port_scan", rule_name="Possible Port Scan",
                 severity="high", score=1.5, evidence=None):
    if evidence is None:
        evidence = [
            {"type": "connection", "id": f"conn-{uuid.uuid4()}", "src": "10.0.0.1", "dst": "10.0.0.2", "detail": "12 dst ports"},
        ]
    finding = FindingRow(
        capture_id=capture_id,
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        score=score,
        summary="12 dst ports from one source",
        detail="Deterministic rule output",
        evidence=json.dumps(evidence),
        ref_type="connection",
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


@pytest.fixture()
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def seeded_finding(db_session):
    import uuid as _uuid

    cap = make_capture(db_session)
    conn_id = str(_uuid.uuid4())
    # A real normalized record the evidence references (unique id per test).
    db_session.add(Connection(
        id=conn_id, capture_id=cap.id, conn_key="tcp|10.0.0.1|10.0.0.2|1|80",
        src="10.0.0.1", dst="10.0.0.2", proto="tcp", sport=1, dport=80,
        source="tshark", bytes_total=500,
    ))
    db_session.commit()
    evidence = [
        {"type": "connection", "id": conn_id, "src": "10.0.0.1", "dst": "10.0.0.2", "detail": "12 dst ports"},
    ]
    finding = make_finding(db_session, cap.id, evidence=evidence)
    return cap, finding, conn_id


def test_create_incident_from_finding(seeded_finding, db_session):
    cap, finding, _ = seeded_finding
    res = incident_svc.create_from_finding(db_session, finding.id)
    assert res.created == 1
    assert res.skipped == 0
    inc = res.incident
    assert inc.id is not None
    assert inc.detection_finding_id == finding.id
    assert inc.capture_id == cap.id
    assert inc.rule_id == "port_scan"
    assert inc.rule_name == "Possible Port Scan"


def test_duplicate_incident_prevention(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    first = incident_svc.create_from_finding(db_session, finding.id)
    second = incident_svc.create_from_finding(db_session, finding.id)
    assert first.created == 1
    assert second.created == 0
    assert second.skipped == 1
    assert second.existing == first.incident.id

    count = db_session.query(Incident).filter(
        Incident.detection_finding_id == finding.id
    ).count()
    assert count == 1


def test_idempotent_repeated_creation_same_logical_occurrence(db_session):
    """A re-detected finding (new id, same evidence) maps to ONE incident."""
    cap = make_capture(db_session)
    evidence = [
        {"type": "connection", "id": f"conn-{uuid.uuid4()}", "src": "10.0.0.1", "dst": "10.0.0.2", "detail": "12 dst ports"}
    ]
    finding_a = make_finding(db_session, cap.id, severity="medium", score=2.5, evidence=evidence)
    finding_b = make_finding(db_session, cap.id, severity="medium", score=2.5, evidence=evidence)

    res_a = incident_svc.create_from_finding(db_session, finding_a.id)
    res_b = incident_svc.create_from_finding(db_session, finding_b.id)
    assert res_a.created == 1
    assert res_b.created == 0  # same logical occurrence -> deduped
    assert res_b.existing == res_a.incident.id
    total = db_session.query(Incident).filter(
        Incident.detection_finding_id.in_([finding_a.id, finding_b.id])
    ).count()
    assert total == 1


def test_severity_preserved_from_finding(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    res = incident_svc.create_from_finding(db_session, finding.id)
    assert res.incident.severity == "high"
    assert res.incident.score == 1.5


def test_evidence_preserved(seeded_finding, db_session):
    _, finding, conn_id = seeded_finding
    res = incident_svc.create_from_finding(db_session, finding.id)
    detail = incident_svc.incident_detail(db_session, res.incident.id)
    assert detail is not None
    assert detail.evidence == [
        {"type": "connection", "id": conn_id, "src": "10.0.0.1", "dst": "10.0.0.2", "detail": "12 dst ports"}
    ]
    # Evidence resolves to the real normalized record.
    assert detail.evidence_resolved[0]["status"] == "ok"
    assert detail.evidence_resolved[0]["type"] == "connection"
    assert detail.evidence_resolved[0]["record"]["dport"] == 80


def test_create_from_missing_finding(db_session):
    with pytest.raises(incident_svc.IncidentNotFound):
        incident_svc.create_from_finding(db_session, "does-not-exist")


def test_incident_retrieval(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    inc = incident_svc.create_from_finding(db_session, finding.id).incident
    detail = incident_svc.incident_detail(db_session, inc.id)
    assert detail is not None
    assert detail.id == inc.id
    assert detail.status == "NEW"
    assert detail.capture_name == "inc-test"


def test_incident_detail_missing_returns_none(db_session):
    assert incident_svc.incident_detail(db_session, "nope") is None


def test_incident_list(seeded_finding, db_session):
    cap, finding, _ = seeded_finding
    incident_svc.create_from_finding(db_session, finding.id)
    result = incident_svc.list_incidents(db_session, capture_id=cap.id)
    assert result.total == 1
    assert all(i.severity == "high" for i in result.items)


def test_filter_by_status(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    res = incident_svc.create_from_finding(db_session, finding.id)
    incident = db_session.get(Incident, res.incident.id)
    incident_svc.change_status(db_session, incident, "INVESTIGATING")
    only_new = incident_svc.list_incidents(db_session, status="NEW")
    only_inv = incident_svc.list_incidents(db_session, status="INVESTIGATING")
    assert all(i.status == "NEW" for i in only_new.items)
    assert all(i.status == "INVESTIGATING" for i in only_inv.items)


def test_filter_by_severity(db_session):
    cap = make_capture(db_session)
    f1 = make_finding(db_session, cap.id, rule_id="conn_rate", rule_name="Abnormal Connection Rate", severity="medium", score=1.2)
    f2 = make_finding(db_session, cap.id, rule_id="dns_anomaly", rule_name="Possible DNS Anomaly", severity="critical", score=6.0)
    incident_svc.create_from_finding(db_session, f1.id)
    incident_svc.create_from_finding(db_session, f2.id)
    medium = incident_svc.list_incidents(db_session, severity="medium")
    critical = incident_svc.list_incidents(db_session, severity="critical")
    assert all(i.severity == "medium" for i in medium.items)
    assert all(i.severity == "critical" for i in critical.items)


def test_filter_by_capture(seeded_finding, db_session):
    cap, finding, _ = seeded_finding
    incident_svc.create_from_finding(db_session, finding.id)
    result = incident_svc.list_incidents(db_session, capture_id=cap.id)
    assert all(i.capture_id == cap.id for i in result.items)


def test_filter_by_rule_and_search(db_session):
    cap = make_capture(db_session)
    f = make_finding(db_session, cap.id, rule_id="dns_anomaly", rule_name="Possible DNS Anomaly", severity="low", score=1.1)
    incident_svc.create_from_finding(db_session, f.id)
    by_rule = incident_svc.list_incidents(db_session, rule_id="dns_anomaly", capture_id=cap.id)
    assert len(by_rule.items) == 1
    by_search = incident_svc.list_incidents(db_session, search="DNS Anomaly", capture_id=cap.id)
    assert len(by_search.items) == 1


# ------------------------------------------------------------------ status


def test_all_statuses_have_transitions_defined():
    assert set(INCIDENT_STATUSES) == set(incident_svc.ALLOWED_TRANSITIONS)


def test_valid_status_flow_new_to_resolved(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    incident = db_session.get(Incident, incident_svc.create_from_finding(db_session, finding.id).incident.id)
    incident = incident_svc.change_status(db_session, incident, "INVESTIGATING")
    assert incident.status == "INVESTIGATING"
    incident = incident_svc.change_status(db_session, incident, "CONTAINED")
    assert incident.status == "CONTAINED"
    incident = incident_svc.change_status(db_session, incident, "RESOLVED")
    assert incident.status == "RESOLVED"
    assert incident.closed_at is not None


def test_invalid_transition_rejected(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    incident = db_session.get(Incident, incident_svc.create_from_finding(db_session, finding.id).incident.id)
    # NEW -> RESOLVED is not allowed directly.
    with pytest.raises(incident_svc.InvalidTransitionError):
        incident_svc.change_status(db_session, incident, "RESOLVED")


def test_false_positive_workflow(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    incident = db_session.get(Incident, incident_svc.create_from_finding(db_session, finding.id).incident.id)
    incident = incident_svc.change_status(db_session, incident, "INVESTIGATING")
    incident = incident_svc.change_status(db_session, incident, "FALSE_POSITIVE", resolution_notes="benign recon lab tooling")
    assert incident.status == "FALSE_POSITIVE"
    assert incident.closed_at is not None
    assert incident.resolution == "false_positive"


def test_reopen_resolved_clears_closed(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    incident = db_session.get(Incident, incident_svc.create_from_finding(db_session, finding.id).incident.id)
    for st in ("INVESTIGATING", "RESOLVED"):
        incident = incident_svc.change_status(db_session, incident, st)
    assert incident.closed_at is not None
    incident = incident_svc.change_status(db_session, incident, "INVESTIGATING")
    assert incident.closed_at is None
    assert incident.resolution is None
    assert incident.status == "INVESTIGATING"


def test_assignment_records_history(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    incident = db_session.get(Incident, incident_svc.create_from_finding(db_session, finding.id).incident.id)
    incident = incident_svc.assign(db_session, incident, "soc-user")
    assert incident.assigned_to == "soc-user"
    events = db_session.query(IncidentEvent).filter(IncidentEvent.incident_id == incident.id).all()
    assert any(e.event_type == "assigned" for e in events)


# ------------------------------------------------------------------ notes


def test_note_creation(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    incident = db_session.get(Incident, incident_svc.create_from_finding(db_session, finding.id).incident.id)
    note = incident_svc.add_note(db_session, incident, "Confirmed from 10.0.0.1", author="analyst-1")
    assert note.text == "Confirmed from 10.0.0.1"
    assert note.author == "analyst-1"
    notes = db_session.query(IncidentNote).filter(IncidentNote.incident_id == incident.id).all()
    assert len(notes) == 1


def test_empty_note_rejected(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    incident = db_session.get(Incident, incident_svc.create_from_finding(db_session, finding.id).incident.id)
    with pytest.raises(incident_svc.EmptyNoteError):
        incident_svc.add_note(db_session, incident, "   ")
    count = db_session.query(IncidentNote).filter(IncidentNote.incident_id == incident.id).count()
    assert count == 0


def test_blank_note_via_schema_rejected(seeded_finding, client):
    _, finding, _ = seeded_finding
    client.post("/api/v1/incidents/from-finding", json={"detection_finding_id": finding.id})
    resp = client.post("/api/v1/incidents/from-finding", json={"detection_finding_id": finding.id})
    inc_id = resp.json()["incident"]["id"]
    bad = client.post(f"/api/v1/incidents/{inc_id}/notes", json={"text": "   "})
    assert bad.status_code == 422


# ------------------------------------------------------------------ history


def test_incident_history_lifecycle(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    incident = db_session.get(Incident, incident_svc.create_from_finding(db_session, finding.id).incident.id)
    incident = incident_svc.change_status(db_session, incident, "INVESTIGATING")
    incident_svc.add_note(db_session, incident, "Starting analysis")
    incident = incident_svc.change_status(db_session, incident, "CONTAINED")
    incident = incident_svc.change_status(db_session, incident, "RESOLVED")

    rows = (
        db_session.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident.id)
        .order_by(IncidentEvent.created_at.asc())
        .all()
    )
    types = [e.event_type for e in rows]
    assert types[0] == "created"
    assert "status_changed" in types
    assert "note_added" in types
    assert "resolved" in types
    resolved_event = next(e for e in rows if e.event_type == "resolved")
    assert resolved_event.old_status == "CONTAINED"
    assert resolved_event.new_status == "RESOLVED"


def test_timestamps_update(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    created = incident_svc.create_from_finding(db_session, finding.id).incident
    assert created.first_seen_at is not None
    incident = db_session.get(Incident, created.id)
    old_updated = incident.updated_at
    incident = incident_svc.change_status(db_session, incident, "INVESTIGATING")
    assert incident.updated_at >= old_updated
    assert incident.closed_at is None


def test_resolve_populates_closed_at_and_updated_at(seeded_finding, db_session):
    _, finding, _ = seeded_finding
    incident = db_session.get(Incident, incident_svc.create_from_finding(db_session, finding.id).incident.id)
    incident = incident_svc.change_status(db_session, incident, "INVESTIGATING")
    incident = incident_svc.change_status(db_session, incident, "RESOLVED", resolution="resolved", resolution_notes="contained and closed")
    assert incident.closed_at is not None
    assert incident.resolution == "resolved"
    assert incident.resolution_notes == "contained and closed"


# ------------------------------------------------------------------ API


def test_api_create_and_get(seeded_finding, client):
    _, finding, _ = seeded_finding
    resp = client.post("/api/v1/incidents/from-finding", json={"detection_finding_id": finding.id})
    assert resp.status_code == 200
    body = resp.json()
    assert body["created"] == 1
    inc_id = body["incident"]["id"]

    detail = client.get(f"/api/v1/incidents/{inc_id}").json()
    assert detail["severity"] == "high"
    assert detail["rule_id"] == "port_scan"
    assert detail["evidence"]
    assert detail["history"][0]["event_type"] == "created"


def test_api_duplicate_returns_existing(seeded_finding, client):
    _, finding, _ = seeded_finding
    first = client.post("/api/v1/incidents/from-finding", json={"detection_finding_id": finding.id}).json()
    second = client.post("/api/v1/incidents/from-finding", json={"detection_finding_id": finding.id}).json()
    assert second["created"] == 0
    assert second["existing"] == first["incident"]["id"]


def test_api_list_filters(seeded_finding, client):
    _, finding, _ = seeded_finding
    client.post("/api/v1/incidents/from-finding", json={"detection_finding_id": finding.id})
    resp = client.get("/api/v1/incidents", params={"severity": "high", "status": "NEW"})
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert all(i["severity"] == "high" and i["status"] == "NEW" for i in items)
    assert resp.json()["total"] >= 1


def test_api_invalid_filter_rejected(client):
    resp = client.get("/api/v1/incidents", params={"severity": "BOGUS"})
    assert resp.status_code == 422
    resp2 = client.get("/api/v1/incidents", params={"status": "BOGUS"})
    assert resp2.status_code == 422


def test_api_transition_and_reject(seeded_finding, client):
    _, finding, _ = seeded_finding
    inc_id = client.post("/api/v1/incidents/from-finding", json={"detection_finding_id": finding.id}).json()["incident"]["id"]

    ok = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "INVESTIGATING"})
    assert ok.status_code == 200
    assert ok.json()["status"] == "INVESTIGATING"

    # INVESTIGATING -> NEW is invalid (no backwards jumps).
    bad = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "NEW"})
    assert bad.status_code == 400


def test_api_patch_to_resolved(seeded_finding, client):
    _, finding, _ = seeded_finding
    inc_id = client.post("/api/v1/incidents/from-finding", json={"detection_finding_id": finding.id}).json()["incident"]["id"]
    client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "INVESTIGATING"})
    client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "CONTAINED"})
    resp = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "RESOLVED", "resolution_notes": "done"})
    assert resp.status_code == 200
    assert resp.json()["closed_at"] is not None
    assert resp.json()["resolution"] == "resolved"


def test_api_assign_and_note(seeded_finding, client):
    _, finding, _ = seeded_finding
    inc_id = client.post("/api/v1/incidents/from-finding", json={"detection_finding_id": finding.id}).json()["incident"]["id"]
    assign = client.patch(f"/api/v1/incidents/{inc_id}", json={"assigned_to": "case-owner"})
    assert assign.status_code == 200
    assert assign.json()["assigned_to"] == "case-owner"

    note = client.post(f"/api/v1/incidents/{inc_id}/notes", json={"text": "checking logs", "author": "analyst-x"})
    assert note.status_code == 201
    detail = client.get(f"/api/v1/incidents/{inc_id}").json()
    assert any(n["author"] == "analyst-x" for n in detail["notes"])


def test_api_incident_not_found(client):
    assert client.get("/api/v1/incidents/nope").status_code == 404
    assert client.patch("/api/v1/incidents/nope", json={"title": "x"}).status_code == 404
    assert client.post("/api/v1/incidents/nope/notes", json={"text": "x"}).status_code == 404
    assert client.delete("/api/v1/incidents/nope").status_code == 404


def test_api_from_capture_promotes_all(seeded_finding, client):
    cap, finding, _ = seeded_finding
    resp = client.post("/api/v1/incidents/from-capture", params={"capture_id": cap.id})
    assert resp.status_code == 200
    assert resp.json()["created"] == 1
    # Idempotent on re-run.
    resp2 = client.post("/api/v1/incidents/from-capture", params={"capture_id": cap.id})
    assert resp2.json()["created"] == 0
    assert resp2.json()["skipped"] == 1


def test_api_summary_counts(client):
    resp = client.get("/api/v1/incidents/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert "total" in body
    assert "open" in body
    assert "critical" in body
    assert "resolved" in body
    # Counters are additive across the whole session DB; just ensure shape + types.
    assert isinstance(body["total"], int)
    assert isinstance(body["open"], int)


def test_api_delete(seeded_finding, client):
    _, finding, _ = seeded_finding
    inc_id = client.post("/api/v1/incidents/from-finding", json={"detection_finding_id": finding.id}).json()["incident"]["id"]
    assert client.delete(f"/api/v1/incidents/{inc_id}").status_code == 204
    assert client.get(f"/api/v1/incidents/{inc_id}").status_code == 404