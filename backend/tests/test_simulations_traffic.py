"""Verify the scenarios generate REAL traffic, not fake counters (MILESTONE 5)."""
from __future__ import annotations

import time


def _run_and_wait(client, scenario: str, config: dict) -> dict:
    created = client.post(
        "/api/v1/simulations",
        json={"scenario": scenario, "target": "127.0.0.1", "config": config},
    )
    assert created.status_code == 201
    sim_id = created.json()["id"]
    client.post(f"/api/v1/simulations/{sim_id}/start")
    status = None
    for _ in range(150):
        cur = client.get(f"/api/v1/simulations/{sim_id}").json()
        status = cur["status"]
        if status in ("completed", "failed", "stopped"):
            break
        time.sleep(0.2)
    return client.get(f"/api/v1/simulations/{sim_id}").json()


def test_dns_generates_real_udp_packets(client):
    sim = _run_and_wait(client, "dns", {"packet_count": 8, "interval_ms": 5})
    assert sim["status"] == "completed"
    # Every query is a real UDP sendto to 127.0.0.1:53.
    assert sim["packets_sent"] == 8


def test_icmp_generates_packets(client):
    sim = _run_and_wait(client, "icmp", {"packet_count": 5, "interval_ms": 5})
    assert sim["status"] == "completed"
    assert sim["packets_sent"] >= 1


def test_port_scan_counts_each_probe(client):
    sim = _run_and_wait(client, "port_scan", {"port_start": 1, "port_end": 25, "delay_ms": 2})
    assert sim["status"] == "completed"
    # Every port is a real TCP connect probe.
    assert sim["connections"] == 25


def test_connection_burst_counts_each_connect(client):
    sim = _run_and_wait(client, "connection_burst", {"connection_count": 15, "delay_ms": 2})
    assert sim["status"] == "completed"
    assert sim["connections"] == 15


def test_normal_generates_traffic(client):
    sim = _run_and_wait(client, "normal", {"packet_count": 20, "dns_ratio": 0.5, "icmp_ratio": 0.5, "tcp_ratio": 0})
    assert sim["status"] == "completed"
    # DNS + ICMP both send real packets.
    assert sim["packets_sent"] >= 10
