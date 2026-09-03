"""Shared normalized models: Packet, Connection, DnsEvent, HttpEvent.

These tables hold normalized, transport-level data correlated from both
TShark (packet-level) and Zeek (event-level) evidence. Every row keeps a
traceable ``source`` (``tshark`` or ``zeek``) plus raw references (Zeek UID,
packet frame number, raw Zeek row) so it can be traced back to originating
evidence. Raw payloads are never stored.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.utils.timeutil import utcnow


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return utcnow()


class Packet(Base):
    """A single normalized packet (metadata only) parsed by TShark."""

    __tablename__ = "packets"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    capture_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    frame_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ts: Mapped[float | None] = mapped_column(nullable=True)
    src: Mapped[str | None] = mapped_column(String, nullable=True)
    dst: Mapped[str | None] = mapped_column(String, nullable=True)
    proto: Mapped[str | None] = mapped_column(String, nullable=True)
    sport: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dport: Mapped[int | None] = mapped_column(Integer, nullable=True)
    length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tcp_flags: Mapped[str | None] = mapped_column(String, nullable=True)
    http_method: Mapped[str | None] = mapped_column(String, nullable=True)
    http_host: Mapped[str | None] = mapped_column(String, nullable=True)
    http_uri: Mapped[str | None] = mapped_column(String, nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dns_qname: Mapped[str | None] = mapped_column(String, nullable=True)
    dns_qtype: Mapped[str | None] = mapped_column(String, nullable=True)
    dns_rcode: Mapped[str | None] = mapped_column(String, nullable=True)
    source: Mapped[str] = mapped_column(String, default="tshark")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Connection(Base):
    """A normalized 5-tuple flow aggregated from packets/Zeek conn records.

    ``conn_key`` is a canonical, direction-agnostic key derived from the 5-tuple
    so that packets traveling in both directions and Zeek orig/resp rows collapse
    onto the same connection. ``zeek_uid`` is captured when a Zeek conn.log row
    matched so downstream DNS/HTTP/SSL events can be correlated directly.
    """

    __tablename__ = "connections"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    capture_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    conn_key: Mapped[str] = mapped_column(String, index=True)
    src: Mapped[str | None] = mapped_column(String, nullable=True)
    dst: Mapped[str | None] = mapped_column(String, nullable=True)
    proto: Mapped[str | None] = mapped_column(String, nullable=True)
    sport: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dport: Mapped[int | None] = mapped_column(Integer, nullable=True)
    service: Mapped[str | None] = mapped_column(String, nullable=True)
    zeek_uid: Mapped[str | None] = mapped_column(String, nullable=True)
    conn_state: Mapped[str | None] = mapped_column(String, nullable=True)
    packets: Mapped[int] = mapped_column(Integer, default=0)
    bytes_total: Mapped[int] = mapped_column(Integer, default=0)
    orig_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resp_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration: Mapped[float | None] = mapped_column(nullable=True)
    first_ts: Mapped[float | None] = mapped_column(nullable=True)
    last_ts: Mapped[float | None] = mapped_column(nullable=True)
    source: Mapped[str] = mapped_column(String, default="tshark")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class DnsEvent(Base):
    """A normalized DNS query correlated from TShark and/or Zeek."""

    __tablename__ = "dns_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    capture_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    connection_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    ts: Mapped[float | None] = mapped_column(nullable=True)
    src: Mapped[str | None] = mapped_column(String, nullable=True)
    dst: Mapped[str | None] = mapped_column(String, nullable=True)
    query: Mapped[str | None] = mapped_column(String, nullable=True)
    qtype_name: Mapped[str | None] = mapped_column(String, nullable=True)
    rcode_name: Mapped[str | None] = mapped_column(String, nullable=True)
    answers: Mapped[str | None] = mapped_column(Text, nullable=True)
    proto: Mapped[str | None] = mapped_column(String, nullable=True)
    trans_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source: Mapped[str] = mapped_column(String, default="zeek")
    zeek_uid: Mapped[str | None] = mapped_column(String, nullable=True)
    packet_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class HttpEvent(Base):
    """A normalized HTTP request correlated from TShark and/or Zeek."""

    __tablename__ = "http_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    capture_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    connection_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    ts: Mapped[float | None] = mapped_column(nullable=True)
    src: Mapped[str | None] = mapped_column(String, nullable=True)
    dst: Mapped[str | None] = mapped_column(String, nullable=True)
    method: Mapped[str | None] = mapped_column(String, nullable=True)
    host: Mapped[str | None] = mapped_column(String, nullable=True)
    uri: Mapped[str | None] = mapped_column(String, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resp_len: Mapped[int | None] = mapped_column(Integer, nullable=True)
    referrer: Mapped[str | None] = mapped_column(String, nullable=True)
    source: Mapped[str] = mapped_column(String, default="zeek")
    zeek_uid: Mapped[str | None] = mapped_column(String, nullable=True)
    packet_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
