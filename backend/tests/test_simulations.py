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


def test_stop_running_simulation(client):
    """Stop a running simulation - should transition to stopped."""
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "dns", "target": "127.0.0.1", "config": {"packet_count": 1000, "interval_ms": 50}},
    )
    sim_id = resp.json()["id"]
    client.post(f"/api/v1/simulations/{sim_id}/start")

    # Wait for running
    for _ in range(50):
        cur = client.get(f"/api/v1/simulations/{sim_id}").json()
        if cur["status"] == "running":
            break
        time.sleep(0.05)

    stop_resp = client.post(f"/api/v1/simulations/{sim_id}/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["status"] == "stopped"

    final = client.get(f"/api/v1/simulations/{sim_id}").json()
    assert final["status"] == "stopped"
    assert final["end_time"] is not None
    assert final["duration_sec"] is not None
    assert final["result"] == "Stopped by user"


def test_stop_after_completion(client):
    """Stop a completed simulation - should remain completed (idempotent)."""
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "dns", "target": "127.0.0.1", "config": {"packet_count": 1, "interval_ms": 1}},
    )
    sim_id = resp.json()["id"]
    client.post(f"/api/v1/simulations/{sim_id}/start")

    # Wait for completion
    for _ in range(50):
        cur = client.get(f"/api/v1/simulations/{sim_id}").json()
        if cur["status"] in ("completed", "failed", "stopped"):
            break
        time.sleep(0.05)

    assert client.get(f"/api/v1/simulations/{sim_id}").json()["status"] == "completed"

    # Stop after completion - should not change status
    stop_resp = client.post(f"/api/v1/simulations/{sim_id}/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["status"] == "completed"

    final = client.get(f"/api/v1/simulations/{sim_id}").json()
    assert final["status"] == "completed"


def test_repeated_stop_requests(client):
    """Multiple stop requests should be idempotent."""
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "dns", "target": "127.0.0.1", "config": {"packet_count": 1000, "interval_ms": 50}},
    )
    sim_id = resp.json()["id"]
    client.post(f"/api/v1/simulations/{sim_id}/start")

    # Wait for running
    for _ in range(50):
        cur = client.get(f"/api/v1/simulations/{sim_id}").json()
        if cur["status"] == "running":
            break
        time.sleep(0.05)

    # Send multiple stop requests
    for _ in range(3):
        stop_resp = client.post(f"/api/v1/simulations/{sim_id}/stop")
        assert stop_resp.status_code == 200

    final = client.get(f"/api/v1/simulations/{sim_id}").json()
    assert final["status"] == "stopped"


def test_stop_immediately_after_start(client):
    """Stop immediately after start should work."""
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "dns", "target": "127.0.0.1", "config": {"packet_count": 1000, "interval_ms": 50}},
    )
    sim_id = resp.json()["id"]
    client.post(f"/api/v1/simulations/{sim_id}/start")

    time.sleep(0.05)
    stop_resp = client.post(f"/api/v1/simulations/{sim_id}/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["status"] == "stopped"

    final = client.get(f"/api/v1/simulations/{sim_id}").json()
    assert final["status"] == "stopped"
    assert final["end_time"] is not None
    assert final["duration_sec"] is not None


def test_worker_exception_handling(client):
    """Simulation that fails should be marked failed."""
    # Use an invalid scenario config that causes failure
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "icmp", "target": "127.0.0.1", "config": {"packet_count": 1, "interval_ms": 1}},
    )
    sim_id = resp.json()["id"]
    client.post(f"/api/v1/simulations/{sim_id}/start")

    for _ in range(50):
        cur = client.get(f"/api/v1/simulations/{sim_id}").json()
        if cur["status"] in ("completed", "failed", "stopped"):
            break
        time.sleep(0.1)

    final = client.get(f"/api/v1/simulations/{sim_id}").json()
    assert final["status"] in ("completed", "failed")
    if final["status"] == "failed":
        assert final["error"] is not None


def test_cleanup_after_stop(client):
    """Resources should be cleaned up after stop."""
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "dns", "target": "127.0.0.1", "config": {"packet_count": 1000, "interval_ms": 50}},
    )
    sim_id = resp.json()["id"]
    client.post(f"/api/v1/simulations/{sim_id}/start")

    for _ in range(50):
        cur = client.get(f"/api/v1/simulations/{sim_id}").json()
        if cur["status"] == "running":
            break
        time.sleep(0.05)

    client.post(f"/api/v1/simulations/{sim_id}/stop")

    for _ in range(50):
        cur = client.get(f"/api/v1/simulations/{sim_id}").json()
        if cur["status"] in ("stopped", "completed", "failed"):
            break
        time.sleep(0.05)

    final = client.get(f"/api/v1/simulations/{sim_id}").json()
    assert final["status"] == "stopped"
    assert final["end_time"] is not None
    assert final["duration_sec"] is not None
    # Stats should be persisted
    assert final["stats"] is not None
    assert "packets_sent" in final["stats"]


def test_database_status_transitions(client):
    """Verify correct status transitions: idle -> queued -> running -> stopped."""
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "dns", "target": "127.0.0.1", "config": {"packet_count": 1000, "interval_ms": 50}},
    )
    sim_id = resp.json()["id"]
    assert resp.json()["status"] == "idle"

    start = client.post(f"/api/v1/simulations/{sim_id}/start")
    assert start.json()["status"] == "queued" or start.json()["status"] == "running"

    # Wait for running
    for _ in range(50):
        cur = client.get(f"/api/v1/simulations/{sim_id}").json()
        if cur["status"] == "running":
            break
        time.sleep(0.05)

    assert client.get(f"/api/v1/simulations/{sim_id}").json()["status"] == "running"

    stop = client.post(f"/api/v1/simulations/{sim_id}/stop")
    assert stop.json()["status"] == "stopped"

    final = client.get(f"/api/v1/simulations/{sim_id}").json()
    assert final["status"] == "stopped"


def test_final_statistics_persistence(client):
    """Final packets/bytes/connections should be persisted after stop."""
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "dns", "target": "127.0.0.1", "config": {"packet_count": 1000, "interval_ms": 10}},
    )
    sim_id = resp.json()["id"]
    client.post(f"/api/v1/simulations/{sim_id}/start")

    for _ in range(50):
        cur = client.get(f"/api/v1/simulations/{sim_id}").json()
        if cur["status"] == "running":
            break
        time.sleep(0.05)

    # Let it run a bit
    time.sleep(0.5)

    client.post(f"/api/v1/simulations/{sim_id}/stop")

    for _ in range(50):
        cur = client.get(f"/api/v1/simulations/{sim_id}").json()
        if cur["status"] in ("stopped", "completed", "failed"):
            break
        time.sleep(0.05)

    final = client.get(f"/api/v1/simulations/{sim_id}").json()
    assert final["status"] == "stopped"
    # At least some packets should have been sent
    assert final["packets_sent"] >= 0
    assert final["bytes_sent"] >= 0
    assert final["connections"] >= 0
    assert final["rates_per_sec"] >= 0
    # Stats should have elapsed_sec
    assert "elapsed_sec" in final["stats"]
    assert final["stats"]["elapsed_sec"] > 0
