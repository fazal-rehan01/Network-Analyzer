"""Wireshark/TShark vs Zeek comparison service (MILESTONE 13).

Presents the same normalized traffic from two analytical perspectives:

* **Wireshark / TShark** = packet-level visibility (frame + timestamp + src/dst
  + protocol + ports + length).
* **Zeek** = connection/event-level visibility (conn.log flows + service +
  duration + bytes, plus dns/http/ssl/notice events).

Correlation is driven by the M9 normalization layer: a ``Connection`` row knows
its ``source`` (``tshark``/``zeek``/``tshark+zeek``), its ``zeek_uid`` and its
5-tuple, so we can report honestly whether each side has evidence. We never
claim a Zeek event where none exists, and when Zeek is unavailable the TShark
side still works.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.analysis.tshark import tshark_available
from app.analysis.zeek import zeek_available
from app.models.capture import Capture
from app.models.normalized import Connection, DnsEvent, HttpEvent, Packet
from app.models.zeek import ZeekConn, ZeekDns, ZeekHttp, ZeekNotice, ZeekSsl
from app.schemas.compare import (
    CaptureComparison,
    CaptureComparisonSummary,
    ConnectionComparison,
    TsharkSide,
    ZeekConnSide,
    ZeekSide,
)

MAX_PACKETS = 50


def _has_tshark(conn: Connection) -> bool:
    return "tshark" in (conn.source or "") or (conn.packets or 0) > 0


def _has_zeek(conn: Connection) -> bool:
    return "zeek" in (conn.source or "") or bool(conn.zeek_uid)


def _correlation_status(conn: Connection) -> str:
    t = _has_tshark(conn)
    z = _has_zeek(conn)
    if t and z:
        return "both"
    if z:
        return "zeek_only"
    return "tshark_only"


def _packet_snapshot(p: Packet) -> dict:
    return {
        "id": p.id,
        "frame_number": p.frame_number,
        "ts": p.ts,
        "src": p.src,
        "dst": p.dst,
        "proto": p.proto,
        "sport": p.sport,
        "dport": p.dport,
        "length": p.length,
        "tcp_flags": p.tcp_flags,
        "http_method": p.http_method,
        "http_host": p.http_host,
        "http_uri": p.http_uri,
        "dns_qname": p.dns_qname,
        "dns_rcode": p.dns_rcode,
    }


def _match_packets(db: Session, conn: Connection) -> list[dict]:
    q = db.query(Packet).filter(
        Packet.capture_id == conn.capture_id,
        Packet.src == conn.src,
        Packet.dst == conn.dst,
    )
    if conn.proto:
        q = q.filter(Packet.proto == conn.proto)
    if conn.sport is not None:
        q = q.filter(Packet.sport == conn.sport)
    if conn.dport is not None:
        q = q.filter(Packet.dport == conn.dport)
    rows = q.order_by(Packet.ts.asc()).limit(MAX_PACKETS).all()
    return [_packet_snapshot(p) for p in rows]


def _tshark_side(db: Session, conn: Connection) -> TsharkSide:
    packets = _match_packets(db, conn) if _has_tshark(conn) else []
    present = _has_tshark(conn)
    return TsharkSide(
        present=present,
        src=conn.src,
        dst=conn.dst,
        proto=conn.proto,
        sport=conn.sport,
        dport=conn.dport,
        packet_count=conn.packets or 0,
        bytes=conn.bytes_total or 0,
        first_ts=conn.first_ts,
        last_ts=conn.last_ts,
        packets=packets,
    )


def _find_zeek_conn(db: Session, conn: Connection) -> ZeekConn | None:
    if conn.zeek_uid:
        match = (
            db.query(ZeekConn)
            .filter(ZeekConn.capture_id == conn.capture_id, ZeekConn.uid == conn.zeek_uid)
            .first()
        )
        if match is not None:
            return match
    # Fallback: canonical 5-tuple match.
    return (
        db.query(ZeekConn)
        .filter(
            ZeekConn.capture_id == conn.capture_id,
            ZeekConn.src == conn.src,
            ZeekConn.dst == conn.dst,
            ZeekConn.proto == conn.proto,
        )
        .first()
    )


def _dns_dict(r: DnsEvent) -> dict:
    return {
        "id": r.id,
        "ts": r.ts,
        "src": r.src,
        "dst": r.dst,
        "query": r.query,
        "qtype_name": r.qtype_name,
        "rcode_name": r.rcode_name,
        "answers": r.answers,
        "zeek_uid": r.zeek_uid,
        "packet_ref": r.packet_ref,
        "source": r.source,
    }


def _http_dict(r: HttpEvent) -> dict:
    return {
        "id": r.id,
        "ts": r.ts,
        "src": r.src,
        "dst": r.dst,
        "method": r.method,
        "host": r.host,
        "uri": r.uri,
        "status_code": r.status_code,
        "user_agent": r.user_agent,
        "zeek_uid": r.zeek_uid,
        "packet_ref": r.packet_ref,
        "source": r.source,
    }


def _ssl_dict(r: ZeekSsl) -> dict:
    return {
        "id": r.id,
        "ts": r.ts,
        "uid": r.uid,
        "src": r.src,
        "dst": r.dst,
        "server_name": r.server_name,
        "version": r.version,
        "cipher": r.cipher,
        "established": r.established,
    }


def _notice_dict(r: ZeekNotice) -> dict:
    return {
        "id": r.id,
        "ts": r.ts,
        "uid": r.uid,
        "src": r.src,
        "dst": r.dst,
        "note": r.note,
        "msg": r.msg,
        "severity": r.severity,
    }


def _zeek_side(db: Session, conn: Connection) -> ZeekSide:
    if not _has_zeek(conn):
        return ZeekSide(present=False, uid=conn.zeek_uid)

    zconn = _find_zeek_conn(db, conn)
    conn_side = None
    if zconn is not None:
        conn_side = ZeekConnSide(
            present=True,
            uid=zconn.uid or conn.zeek_uid,
            service=zconn.service or conn.service,
            conn_state=zconn.conn_state or conn.conn_state,
            duration=zconn.duration if zconn.duration is not None else conn.duration,
            orig_bytes=zconn.orig_bytes,
            resp_bytes=zconn.resp_bytes,
            src=zconn.src or conn.src,
            dst=zconn.dst or conn.dst,
            proto=zconn.proto or conn.proto,
            sport=zconn.sport if zconn.sport is not None else conn.sport,
            dport=zconn.dport if zconn.dport is not None else conn.dport,
        )

    dns = [_dns_dict(r) for r in db.query(DnsEvent).filter(DnsEvent.connection_id == conn.id).order_by(DnsEvent.ts.asc()).all()]
    http = [_http_dict(r) for r in db.query(HttpEvent).filter(HttpEvent.connection_id == conn.id).order_by(HttpEvent.ts.asc()).all()]

    ssl = [
        _ssl_dict(r)
        for r in db.query(ZeekSsl)
        .filter(
            ZeekSsl.capture_id == conn.capture_id,
            ZeekSsl.src == conn.src,
            ZeekSsl.dst == conn.dst,
        )
        .order_by(ZeekSsl.ts.asc())
        .all()
    ]
    notices = [
        _notice_dict(r)
        for r in db.query(ZeekNotice)
        .filter(
            ZeekNotice.capture_id == conn.capture_id,
            ZeekNotice.src == conn.src,
            ZeekNotice.dst == conn.dst,
        )
        .order_by(ZeekNotice.ts.asc())
        .all()
    ]

    event_count = len(dns) + len(http) + len(ssl) + len(notices)
    return ZeekSide(
        present=True,
        uid=conn.zeek_uid,
        conn=conn_side,
        dns=dns,
        http=http,
        ssl=ssl,
        notices=notices,
        event_count=event_count,
    )


def _correlation_summary(conn: Connection) -> str:
    status = _correlation_status(conn)
    if status == "both":
        return "Both packet-level and Zeek event-level evidence are present for this flow."
    if status == "zeek_only":
        return "Only Zeek event-level evidence exists (small/no packet samples captured)."
    return "Only packet-level (TShark) evidence exists; no correlated Zeek event found."


def compare_connection(db: Session, connection_id: str) -> ConnectionComparison | None:
    conn = db.get(Connection, connection_id)
    if conn is None:
        return None
    status = _correlation_status(conn)
    tshark = _tshark_side(db, conn)
    zeek = _zeek_side(db, conn)
    return ConnectionComparison(
        id=conn.id,
        src=conn.src,
        dst=conn.dst,
        proto=conn.proto,
        sport=conn.sport,
        dport=conn.dport,
        service=conn.service,
        packets=conn.packets or 0,
        bytes_total=conn.bytes_total or 0,
        zeek_uid=conn.zeek_uid,
        source=conn.source or "tshark",
        correlation_status=status,
        correlation_summary=_correlation_summary(conn),
        tshark=tshark,
        zeek=zeek,
        evidence={
            "tshark": [p["id"] for p in tshark.packets],
            "zeek": (
                [zeek.uid] if zeek.uid else []
            ) + [e["id"] for e in zeek.dns] + [e["id"] for e in zeek.http]
            + [e["id"] for e in zeek.ssl] + [e["id"] for e in zeek.notices],
        },
    )


def compare_capture(db: Session, capture_id: str) -> CaptureComparison | None:
    cap = db.get(Capture, capture_id)
    if cap is None:
        return None
    rows = (
        db.query(Connection)
        .filter(Connection.capture_id == capture_id)
        .order_by(Connection.first_ts.asc())
        .all()
    )
    both = zeek_only = tshark_only = 0
    packets_tshark = 0
    zeek_events = 0
    connections: list[dict] = []
    for conn in rows:
        status = _correlation_status(conn)
        if status == "both":
            both += 1
        elif status == "zeek_only":
            zeek_only += 1
        else:
            tshark_only += 1
        packets_tshark += conn.packets or 0
        # Zeek event count for a connection.
        zeek_conn = _find_zeek_conn(db, conn)
        dns_n = db.query(DnsEvent).filter(DnsEvent.connection_id == conn.id).count()
        http_n = db.query(HttpEvent).filter(HttpEvent.connection_id == conn.id).count()
        ssl_n = (
            db.query(ZeekSsl)
            .filter(ZeekSsl.capture_id == capture_id, ZeekSsl.src == conn.src, ZeekSsl.dst == conn.dst)
            .count()
        )
        if zeek_conn is not None:
            zeek_events += 1 + dns_n + http_n + ssl_n
        else:
            zeek_events += dns_n + http_n + ssl_n

        connections.append(
            {
                "id": conn.id,
                "src": conn.src,
                "dst": conn.dst,
                "proto": conn.proto,
                "sport": conn.sport,
                "dport": conn.dport,
                "service": conn.service,
                "packets": conn.packets or 0,
                "bytes_total": conn.bytes_total or 0,
                "zeek_uid": conn.zeek_uid,
                "source": conn.source or "tshark",
                "correlation_status": status,
                "correlation_summary": _correlation_summary(conn),
            }
        )

    return CaptureComparison(
        capture_id=capture_id,
        capture_name=cap.name,
        tshark_available=tshark_available(),
        zeek_available=zeek_available(),
        summary=CaptureComparisonSummary(
            connections_total=len(rows),
            both=both,
            tshark_only=tshark_only,
            zeek_only=zeek_only,
            packets_tshark=packets_tshark,
            zeek_events=zeek_events,
        ),
        connections=connections,
    )


def compare_status() -> dict:
    return {
        "tshark_available": tshark_available(),
        "zeek_available": zeek_available(),
    }
