"""Tests for health and system-status endpoints (MILESTONE 2)."""
from __future__ import annotations


def test_health_ok(client):
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["app"]


def test_system_status_reports_components(client):
    resp = client.get("/api/v1/system/status")
    assert resp.status_code == 200
    body = resp.json()
    names = {c["name"] for c in body["components"]}
    assert "TShark" in names
    assert "Zeek" in names
    assert "Python" in names
    # Python must be installed.
    py = next(c for c in body["components"] if c["name"] == "Python")
    assert py["installed"] is True


def test_system_status_tshark_detected_on_this_machine(client):
    """TShark is installed on this dev machine at a known path."""
    body = client.get("/api/v1/system/status").json()
    tshark = next(c for c in body["components"] if c["name"] == "TShark")
    assert tshark["installed"] is True
