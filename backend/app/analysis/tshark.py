"""TShark packet parsing: extract normalized per-packet metadata from a PCAP.

This module provides the "TShark evidence" side of the normalization layer.
Each packet is reduced to defensive, transport-level metadata (timestamp, IP
addresses, ports, protocol, length, and optional HTTP/DNS hints) — raw payloads
are never stored. All parsing is optional and degrades gracefully when TShark
is unavailable or a field is missing.
"""
from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from app.utils.tools import detect_tshark

# -E occurrence=a repeats the row when a field has multiple values.
_PACKET_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.reset",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.response.code",
    "dns.qry.name",
    "dns.qry.type",
    "dns.flags.rcode",
]

_PACKET_ARGUMENTS = ["-T", "fields", "-E", "occurrence=a"]
for _f in _PACKET_FIELDS:
    _PACKET_ARGUMENTS += ["-e", _f]


@dataclass
class PacketRecord:
    """Normalized, transport-level metadata for a single packet."""

    frame_number: str | None
    ts: float | None
    length: int | None
    src: str | None
    dst: str | None
    proto: str | None  # raw ip.proto number (1=ICMP, 6=TCP, 17=UDP)
    sport: int | None
    dport: int | None
    tcp_flags: dict | None = None
    http_method: str | None = None
    http_host: str | None = None
    http_uri: str | None = None
    http_status: int | None = None
    dns_qname: str | None = None
    dns_qtype: str | None = None
    dns_rcode: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def get_tshark_path() -> str | None:
    status = detect_tshark()
    if not status.installed or not status.path:
        return None
    return status.path


def tshark_available() -> bool:
    return get_tshark_path() is not None


def _run_tshark(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    exe = get_tshark_path()
    if exe is None:
        raise RuntimeError("TShark is not installed")
    return subprocess.run([exe, *args], capture_output=True, text=True, timeout=timeout)


def _field_index(index: int, fields: list[str]) -> str | None:
    try:
        value = fields[index]
        return value if value not in ("", "-") else None
    except IndexError:
        return None


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_line(fields: list[str]) -> PacketRecord | None:
    ts = _to_float(_field_index(1, fields))
    if ts is None and _field_index(0, fields) is None:
        return None

    proto = _ip_proto_name(_field_index(5, fields))
    tcp_sport = _to_int(_field_index(6, fields))
    tcp_dport = _to_int(_field_index(7, fields))
    udp_sport = _to_int(_field_index(8, fields))
    udp_dport = _to_int(_field_index(9, fields))

    sport = tcp_sport if tcp_sport is not None else udp_sport
    dport = tcp_dport if tcp_dport is not None else udp_dport

    flags: dict | None = None
    syn = _field_index(10, fields)
    ack = _field_index(11, fields)
    rst = _field_index(12, fields)
    if syn is not None or ack is not None or rst is not None:
        flags = {"syn": syn == "1", "ack": ack == "1", "reset": rst == "1"}

    return PacketRecord(
        frame_number=_field_index(0, fields),
        ts=ts,
        length=_to_int(_field_index(2, fields)),
        src=_field_index(3, fields),
        dst=_field_index(4, fields),
        proto=proto,
        sport=sport,
        dport=dport,
        tcp_flags=flags,
        http_method=_field_index(13, fields),
        http_host=_field_index(14, fields),
        http_uri=_field_index(15, fields),
        http_status=_to_int(_field_index(16, fields)),
        dns_qname=_field_index(17, fields),
        dns_qtype=_field_index(18, fields),
        dns_rcode=_field_index(19, fields),
    )


def parse_packets(pcap: Path, limit: int = 5000) -> list[PacketRecord]:
    """Parse per-packet metadata from a PCAP using TShark.

    Returns an empty list when TShark is unavailable or parsing fails.
    The ``proto`` field is filled from the ``ip.proto`` column (numeric).
    """
    if not tshark_available() or not pcap.exists():
        return []
    try:
        args = ["-r", str(pcap), *_PACKET_ARGUMENTS, "-c", str(limit)]
        proc = _run_tshark(*args)
    except Exception:  # noqa: BLE001
        return []
    out = proc.stdout or ""
    records: list[PacketRecord] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        fields = line.split("\t")
        rec = _parse_line(fields)
        if rec is not None:
            records.append(rec)
    return records


def _ip_proto_name(proto: str | None) -> str | None:
    if proto is None:
        return None
    mapping = {"1": "icmp", "6": "tcp", "17": "udp"}
    return mapping.get(proto, proto)
