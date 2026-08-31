"""Low-level helpers for generating real controlled traffic (Scapy + stdlib sockets).

All traffic stays on the loopback / lab interface. These helpers are shared by
the scenario implementations.
"""
from __future__ import annotations

import socket
import time
import uuid

from app.simulation.base import ScenarioContext

# DNS query/response codes
_OK = 0
_NXDOMAIN = 3


def sleep_or_stop(ctx: ScenarioContext, seconds: float) -> None:
    """Sleep in small slices so cancellation is responsive."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        ctx.check_stop()
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))


def _tcp_connect(host: str, port: int, timeout: float = 0.5) -> bool:
    """Attempt a real TCP connect; returns True if the connection was established."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def tcp_handshake(ctx: ScenarioContext, port: int, count: int = 1) -> int:
    """Open+close real TCP connections to a lab target. Returns established count."""
    established = 0
    for _ in range(count):
        ctx.check_stop()
        if _tcp_connect(ctx.target, port):
            established += 1
        ctx.connections += 1
    return established


def send_udp_packet(ctx: ScenarioContext, port: int, payload: bytes) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, (ctx.target, port))
        ctx.packets_sent += 1
        ctx.bytes_sent += len(payload) + 28  # ~ IP+UDP header overhead
    finally:
        sock.close()


def send_dns_query(ctx: ScenarioContext, qname: str, qtype: str = "A") -> int:
    """Send a real DNS query over UDP; returns the 16-bit DNS ID."""
    import struct

    dns_id = uuid.uuid4().int & 0xFFFF
    flags = 0x0100  # RD
    qdcount, ancount, nscount, arcount = 1, 0, 0, 0
    header = struct.pack(">HHHHHH", dns_id, flags, qdcount, ancount, nscount, arcount)

    question = b""
    for label in qname.rstrip(".").split("."):
        question += bytes([len(label)]) + label.encode("ascii", "ignore")
    question += b"\x00"
    qtype_map = {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "ANY": 255}
    question += struct.pack(">HH", qtype_map.get(qtype.upper(), 1), 1)

    payload = header + question
    send_udp_packet(ctx, 53, payload)
    return dns_id


def send_icmp_packet(ctx: ScenarioContext, count: int = 1) -> int:
    """Send real ICMP echo requests to the loopback/lab target."""
    try:
        from scapy.all import ICMP, IP, send
    except Exception:  # noqa: BLE001
        return 0
    sent = 0
    for i in range(count):
        ctx.check_stop()
        pkt = IP(dst=ctx.target) / ICMP(type=8, code=0, id=i, seq=i) / b"payload"
        try:
            send(pkt, verbose=False)
            sent += 1
            ctx.packets_sent += 1
            ctx.bytes_sent += len(pkt)
        except Exception:  # noqa: BLE001
            continue
    return sent
