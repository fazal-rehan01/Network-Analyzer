"""Tests for live packet capture and PCAP analysis (MILESTONE 6 - TShark)."""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from app.services.capture import analyze_pcap, list_interfaces


def _find_loopback(client) -> int | None:
    ifaces = client.get("/api/v1/captures/interfaces").json()
    for iface in ifaces:
        if iface.get("loopback"):
            return iface["index"]
    # Fall back to first interface if none is flagged as loopback.
    return ifaces[0]["index"] if ifaces else None


def test_list_interfaces(client):
    resp = client.get("/api/v1/captures/interfaces")
    assert resp.status_code == 200
    ifaces = resp.json()
    assert isinstance(ifaces, list)
    if ifaces:
        assert "index" in ifaces[0]
        assert "name" in ifaces[0]


def test_empty_capture_list(client):
    resp = client.get("/api/v1/captures")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.skipif(
    not __import__("app.utils.tools", fromlist=["detect_tshark"]).detect_tshark().installed,
    reason="TShark not installed",
)
def test_live_capture_loopback_produces_packets(client):
    idx = _find_loopback(client)
    if idx is None:
        pytest.skip("No capture interface available")

    created = client.post(
        "/api/v1/captures",
        json={"name": "test-live", "interface_index": idx, "duration_sec": 3},
    )
    assert created.status_code == 201, created.text
    cap = created.json()
    assert cap["status"] == "running"
    cap_id = cap["id"]

    # Generate real traffic while capturing (ICMP pings to loopback).
    ping = __import__("subprocess").run(
        ["ping", "-n", "5", "-w", "300", "127.0.0.1"], capture_output=True
    )

    # Wait for auto-finalization (duration 3s + margin).
    final = None
    for _ in range(40):
        final = client.get(f"/api/v1/captures/{cap_id}").json()
        if final["status"] in ("done", "error"):
            break
        time.sleep(0.5)
    assert final["status"] == "done", final

    # Traffic should have been captured on the loopback interface.
    if ping.returncode == 0:
        assert final["packet_count"] > 0

    stats = client.get(f"/api/v1/captures/{cap_id}/stats").json()
    assert "protocols" in stats


def test_capture_not_found(client):
    assert client.get("/api/v1/captures/does-not-exist").status_code == 404


def test_upload_pcap_parses_correctly(client, tmp_path):
    # Create a simple PCAP with known content using tshark if available
    from app.utils.tools import detect_tshark
    tshark = detect_tshark()
    if not tshark.installed:
        pytest.skip("TShark not installed")

    # Use scapy to create a test PCAP file
    try:
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
    except Exception:
        pytest.skip("Scapy not available")

    test_pcap = tmp_path / "test_upload.pcap"
    import time
    base = time.time()
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80) / Raw(b"GET / HTTP/1.1"),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234) / Raw(b"HTTP/1.1 200 OK"),
    ]
    pkts[0].time = base
    pkts[1].time = base + 0.1
    wrpcap(str(test_pcap), pkts)

    with open(test_pcap, "rb") as f:
        resp = client.post("/api/v1/captures/upload", files={"file": (test_pcap.name, f, "application/vnd.tcpdump.pcap")})
    assert resp.status_code == 201, resp.text
    cap = resp.json()
    assert cap["source"] == "upload"
    assert cap["status"] == "done"
    assert cap["packet_count"] == 2
    assert cap["byte_count"] > 0

    # Stats endpoint should return protocols
    stats = client.get(f"/api/v1/captures/{cap['id']}/stats").json()
    assert stats["protocols"]
    proto_names = {p["protocol"] for p in stats["protocols"]}
    assert "eth" in proto_names or "ip" in proto_names or "tcp" in proto_names
