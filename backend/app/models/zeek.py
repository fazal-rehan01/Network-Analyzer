"""Zeek log event models.

These tables store normalized rows parsed from Zeek's conn/dns/http/ssl/notice
logs. They are intentionally defensive: nullable columns, no eager joins, and
no assumptions that Zeek produced every log type.
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


class _ZeekEventBase(Base):
    """Shared columns and behaviour for all Zeek event rows."""

    __abstract__ = True

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    capture_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    ts: Mapped[float | None] = mapped_column(nullable=True)
    uid: Mapped[str | None] = mapped_column(String, nullable=True)
    src: Mapped[str | None] = mapped_column(String, nullable=True)
    dst: Mapped[str | None] = mapped_column(String, nullable=True)
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ZeekConn(_ZeekEventBase):
    """One row from conn.log (a connection/flow)."""

    __tablename__ = "zeek_conn"

    proto: Mapped[str | None] = mapped_column(String, nullable=True)
    sport: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dport: Mapped[int | None] = mapped_column(Integer, nullable=True)
    orig_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resp_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    conn_state: Mapped[str | None] = mapped_column(String, nullable=True)
    duration: Mapped[float | None] = mapped_column(nullable=True)
    service: Mapped[str | None] = mapped_column(String, nullable=True)


class ZeekDns(_ZeekEventBase):
    """One row from dns.log (a DNS query/answer)."""

    __tablename__ = "zeek_dns"

    query: Mapped[str | None] = mapped_column(String, nullable=True)
    qtype_name: Mapped[str | None] = mapped_column(String, nullable=True)
    rcode_name: Mapped[str | None] = mapped_column(String, nullable=True)
    answers: Mapped[str | None] = mapped_column(Text, nullable=True)
    proto: Mapped[str | None] = mapped_column(String, nullable=True)
    trans_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rtt: Mapped[float | None] = mapped_column(nullable=True)


class ZeekHttp(_ZeekEventBase):
    """One row from http.log (an HTTP request)."""

    __tablename__ = "zeek_http"

    method: Mapped[str | None] = mapped_column(String, nullable=True)
    host: Mapped[str | None] = mapped_column(String, nullable=True)
    uri: Mapped[str | None] = mapped_column(String, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resp_len: Mapped[int | None] = mapped_column(Integer, nullable=True)
    referrer: Mapped[str | None] = mapped_column(String, nullable=True)


class ZeekSsl(_ZeekEventBase):
    """One row from ssl.log (a TLS handshake)."""

    __tablename__ = "zeek_ssl"

    server_name: Mapped[str | None] = mapped_column(String, nullable=True)
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    cipher: Mapped[str | None] = mapped_column(String, nullable=True)
    established: Mapped[bool | None] = mapped_column(nullable=True)
    client_subject: Mapped[str | None] = mapped_column(String, nullable=True)
    server_subject: Mapped[str | None] = mapped_column(String, nullable=True)


class ZeekNotice(_ZeekEventBase):
    """One row from notice.log (a Zeek-generated notice/alert)."""

    __tablename__ = "zeek_notice"

    note: Mapped[str | None] = mapped_column(String, nullable=True)
    msg: Mapped[str | None] = mapped_column(Text, nullable=True)
    sub: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String, nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actions: Mapped[str | None] = mapped_column(String, nullable=True)


# Mapping from log type to model class, used by the service layer.
ZEK_MODEL_BY_TYPE: dict[str, type] = {
    "conn": ZeekConn,
    "dns": ZeekDns,
    "http": ZeekHttp,
    "ssl": ZeekSsl,
    "notice": ZeekNotice,
}
