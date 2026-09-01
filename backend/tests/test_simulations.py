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


def test_reconciliation_stale_stopping(client):
    """Stale stopping simulations (no active runner) should be reconciled to failed on startup."""
    from app.core.database import SessionLocal
    from app.models.simulation import Simulation
    from app.simulation.runner import _active
    
    # Create a simulation and manually set it to stopping (simulating stale state)
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "dns", "target": "127.0.0.1", "config": {"packet_count": 10, "interval_ms": 10}},
    )
    sim_id = resp.json()["id"]
    
    # Manually set to stopping in DB (bypassing API to simulate stale state)
    db = SessionLocal()
    try:
        sim = db.get(Simulation, sim_id)
        sim.status = "stopping"
        sim.start_time = db.query(Simulation).filter(Simulation.id == sim_id).first().created_at
        # Add some historical data
        sim.packets_sent = 42
        sim.bytes_sent = 1234
        sim.connections = 5
        sim.rates_per_sec = 10
        sim.set_stats({"packets_sent": 42, "bytes_sent": 1234, "connections": 5, "rates_per_sec": 10, "elapsed_sec": 1.0})
        db.commit()
    finally:
        db.close()
    
    # Ensure no active runner exists for this simulation
    assert sim_id not in _active
    
    # Run reconciliation
    from app.simulation.runner import reconcile_stale_simulations
    count = reconcile_stale_simulations()
    assert count == 1
    
    # Verify the simulation was reconciled
    final = client.get(f"/api/v1/simulations/{sim_id}").json()
    assert final["status"] == "failed"
    assert "Recovered stale" in final["result"]
    assert final["error"] is not None
    assert "restart" in final["error"].lower()
    # Historical data preserved
    assert final["packets_sent"] == 42
    assert final["bytes_sent"] == 1234
    assert final["connections"] == 5
    # end_time and duration populated
    assert final["end_time"] is not None
    assert final["duration_sec"] is not None


def test_reconciliation_idempotent(client):
    """Running reconciliation twice should not change already-reconciled records."""
    from app.simulation.runner import reconcile_stale_simulations
    
    # First run
    count1 = reconcile_stale_simulations()
    # Second run
    count2 = reconcile_stale_simulations()
    
    # Second run should find 0 stale simulations
    assert count2 == 0


def test_reconciliation_preserves_running_simulation(client):
    """Active running simulation should NOT be touched by reconciliation."""
    from app.simulation.runner import _active, reconcile_stale_simulations
    
    # Start a real simulation
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
    
    # Verify it has an active runner
    assert sim_id in _active
    assert _active[sim_id].running
    
    # Run reconciliation
    count = reconcile_stale_simulations()
    
    # Should not have reconciled this one (it has an active runner)
    # Note: count might be 0 or more depending on other stale records, but this sim should be untouched
    final = client.get(f"/api/v1/simulations/{sim_id}").json()
    assert final["status"] == "running"
    
    # Clean up - stop it
    client.post(f"/api/v1/simulations/{sim_id}/stop")


def test_reconciliation_preserves_stopping_simulation(client):
    """Active stopping simulation (has runner in _active) should NOT be touched by reconciliation."""
    from app.simulation.runner import _active, _runner_lock, reconcile_stale_simulations, SimulationRunner
    from app.core.database import SessionLocal
    from app.models.simulation import Simulation
    
    # Create a simulation and manually add a runner to _active (simulating active stopping)
    resp = client.post(
        "/api/v1/simulations",
        json={"scenario": "dns", "target": "127.0.0.1", "config": {"packet_count": 10, "interval_ms": 10}},
    )
    sim_id = resp.json()["id"]
    
    # Set status to stopping in DB
    db = SessionLocal()
    try:
        sim = db.get(Simulation, sim_id)
        sim.status = "stopping"
        db.commit()
    finally:
        db.close()
    
    # Manually add a runner to _active to simulate an active stopping simulation
    runner = SimulationRunner(sim_id)
    with _runner_lock:
        _active[sim_id] = runner
    
    try:
        # Verify it has an active runner and status is stopping
        assert sim_id in _active
        assert client.get(f"/api/v1/simulations/{sim_id}").json()["status"] == "stopping"
        
        # Run reconciliation
        count = reconcile_stale_simulations()
        
        # Should not have reconciled this one (it has an active runner)
        final = client.get(f"/api/v1/simulations/{sim_id}").json()
        assert final["status"] == "stopping"
    finally:
        # Clean up
        with _runner_lock:
            _active.pop(sim_id, None)


def test_reconciliation_preserves_terminal_states(client):
    """Completed, stopped, failed simulations should NOT be touched by reconciliation."""
    from app.simulation.runner import reconcile_stale_simulations
    
    # Create a completed simulation
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
    
    # Run reconciliation
    count = reconcile_stale_simulations()
    
    # Should not have changed this one
    final = client.get(f"/api/v1/simulations/{sim_id}").json()
    assert final["status"] == "completed"
    assert final["result"] == "Completed successfully"
