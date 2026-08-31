"""Tests for the simulation engine (MILESTONE 4)."""
from __future__ import annotations

import time


def test_list_scenarios(client):
    resp = client.get("/api/v1/simulations/scenarios")
    assert resp.status_code == 200
    body = resp.json()
    keys = {s["key"] for s in body}
    for expected in ("normal", "http", "dns", "icmp", "port_scan", "connection_burst", "data_transfer", "dns_anomaly"):
        assert expected in keys


def test_create_simulation(client):
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "icmp", "name": "test ping", "target": "127.0.0.1"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["scenario"] == "icmp"
    assert body["status"] == "idle"
    assert body["target"] == "127.0.0.1"
    assert "id" in body


def test_refuses_unsafe_target(client):
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "icmp", "target": "8.8.8.8"},
    )
    assert resp.status_code == 400
    assert "non-lab" in resp.json()["detail"]


def test_unknown_scenario_rejected(client):
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "does_not_exist", "target": "127.0.0.1"},
    )
    assert resp.status_code == 400


def test_run_icmp_completes(client):
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "icmp", "target": "127.0.0.1", "config": {"packet_count": 5, "interval_ms": 10}},
    )
    sim_id = resp.json()["id"]

    start = client.post(f"/api/v1/simulations/{sim_id}/start")
    assert start.status_code == 200

    # Wait for the background thread to finish.
    status = None
    for _ in range(50):
        cur = client.get(f"/api/v1/simulations/{sim_id}").json()
        status = cur["status"]
        if status in ("completed", "failed", "stopped"):
            break
        time.sleep(0.1)

    assert status == "completed"
    final = client.get(f"/api/v1/simulations/{sim_id}").json()
    assert final["duration_sec"] is not None
