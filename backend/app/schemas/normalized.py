"""Pydantic schemas for normalized/correlated data."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class PacketRead(BaseModel):
    """A single normalized packet (metadata only)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str | None = None
    frame_number: int | None = None
    ts: float | None = None
    src: str | None = None
    dst: str | None = None
    proto: str | None = None
    sport: int | None = None
    dport: int | None = None
    length: int | None = None
    tcp_flags: str | None = None
    http_method: str | None = None
    http_host: str | None = None
    http_uri: str | None = None
    http_status: int | None = None
    dns_qname: str | None = None
    dns_qtype: str | None = None
    dns_rcode: str | None = None
    source: str = "tshark"
    created_at: datetime


class ConnectionRead(BaseModel):
    """A normalized 5-tuple flow."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str | None = None
    conn_key: str
    src: str | None = None
    dst: str | None = None
    proto: str | None = None
    sport: int | None = None
    dport: int | None = None
    service: str | None = None
    zeek_uid: str | None = None
    conn_state: str | None = None
    packets: int = 0
    bytes_total: int = 0
    orig_bytes: int | None = None
    resp_bytes: int | None = None
    duration: float | None = None
    first_ts: float | None = None
    last_ts: float | None = None
    source: str = "tshark"
    created_at: datetime


class DnsEventRead(BaseModel):
    """A normalized DNS query correlated from TShark and/or Zeek."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str | None = None
    connection_id: str | None = None
    ts: float | None = None
    src: str | None = None
    dst: str | None = None
    query: str | None = None
    qtype_name: str | None = None
    rcode_name: str | None = None
    answers: str | None = None
    proto: str | None = None
    trans_id: int | None = None
    source: str = "zeek"
    zeek_uid: str | None = None
    packet_ref: str | None = None
    raw: str | None = None
    created_at: datetime


class HttpEventRead(BaseModel):
    """A normalized HTTP request correlated from TShark and/or Zeek."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    capture_id: str | None = None
    connection_id: str | None = None
    ts: float | None = None
    src: str | None = None
    dst: str | None = None
    method: str | None = None
    host: str | None = None
    uri: str | None = None
    user_agent: str | None = None
    status_code: int | None = None
    resp_len: int | None = None
    referrer: str | None = None
    source: str = "zeek"
    zeek_uid: str | None = None
    packet_ref: str | None = None
    raw: str | None = None
    created_at: datetime


class NormalizeSummary(BaseModel):
    """Summary of a normalization/correlation run."""

    capture_id: str | None = None
    tshark_available: bool = False
    zeek_available: bool = False
    packets_parsed: int = 0
    packets_persisted: int = 0
    connections: int = 0
    dns_events: int = 0
    http_events: int = 0
    connections_with_zeek: int = 0
    error: str | None = None
