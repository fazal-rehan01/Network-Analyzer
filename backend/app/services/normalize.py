"""Normalization and correlation service.

Merges TShark packet-level evidence with Zeek event-level evidence into shared
normalized Connection / DnsEvent / HttpEvent records. Correlation uses
defensible keys:

* Connections are keyed by a canonical, direction-agnostic 5-tuple
  (proto|src|dst|sport|dport) so packets and Zeek conn rows collapse together.
* Zeek DNS/HTTP events are correlated to a connection by the strongest key
  available: the Zeek ``uid`` (when that connection had a matching conn row),
  falling back to the 5-tuple plus time-window proximity.
* TShark packet HTTP/DNS hints are promoted to normalized events only when the
  field evidence is present (never fabricated).
* Every normalized record keeps ``source`` plus Zeek UID / packet frame / raw
  references so it can be traced back to its evidence.

Graceful degradation: with no TShark and no Zeek, the service returns an empty,
non-erroring result. With Zeek missing (but TShark present), connections and
TShark-derived DNS/HTTTP events are still produced.
"""
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.analysis.tshark import parse_packets, tshark_available
from app.analysis.zeek import zeek_available
from app.models.normalized import Connection, DnsEvent, HttpEvent, Packet
from app.models.zeek import ZeekConn, ZeekDns, ZeekHttp
from app.schemas.normalized import NormalizeSummary

# Time window (seconds) used for 5-tuple correlation fallback.
_TIME_TOLERANCE = 3.0


def canonical_conn_key(src, dst, proto, sport, dport) -> str:
    """Build a direction-agnostic connection key from a 5-tuple."""
    a = src or ""
    b = dst or ""
    pa = sport
    pb = dport
    if (a, pa if pa is not None else 0) <= (b, pb if pb is not None else 0):
        left, right, lp, rp = a, b, pa, pb
    else:
        left, right, lp, rp = b, a, pb, pa
    return f"{proto or '?'}|{left}|{right}|{lp if lp is not None else ''}|{rp if rp is not None else ''}"


def _packet_conn_key(p: Packet) -> str | None:
    if not p.src or not p.dst:
        return None
    return canonical_conn_key(p.src, p.dst, p.proto, p.sport, p.dport)


def _zeek_conn_key(row: ZeekConn) -> str | None:
    if not row.src or not row.dst:
        return None
    return canonical_conn_key(row.src, row.dst, row.proto, row.sport, row.dport)


def _within_window(ts, first, last, tolerance: float = _TIME_TOLERANCE) -> bool:
    if ts is None:
        return False
    if first is not None and ts < first - tolerance:
        return False
    if last is not None and ts > last + tolerance:
        return False
    return True


def persist_packets(db: Session, capture_id: str | None, records) -> int:
    """Persist parsed TShark packet records. Returns count inserted."""
    count = 0
    for rec in records:
        if rec.src is None and rec.dst is None:
            continue
        flags = json.dumps(rec.tcp_flags) if rec.tcp_flags else None
        db.add(
            Packet(
                capture_id=capture_id,
                frame_number=int(rec.frame_number) if rec.frame_number else None,
                ts=rec.ts,
                src=rec.src,
                dst=rec.dst,
                proto=rec.proto,
                sport=rec.sport,
                dport=rec.dport,
                length=rec.length,
                tcp_flags=flags,
                http_method=rec.http_method,
                http_host=rec.http_host,
                http_uri=rec.http_uri,
                http_status=rec.http_status,
                dns_qname=rec.dns_qname,
                dns_qtype=rec.dns_qtype,
                dns_rcode=rec.dns_rcode,
                source="tshark",
            )
        )
        count += 1
    db.commit()
    return count


def _existing_conns(db: Session, capture_id: str) -> dict[str, Connection]:
    rows = db.query(Connection).filter(Connection.capture_id == capture_id).all()
    return {r.conn_key: r for r in rows}


def build_connections_from_packets(db: Session, capture_id: str) -> int:
    """Aggregate persisted packets into Connection records. Returns count."""
    packets = db.query(Packet).filter(Packet.capture_id == capture_id).all()
    existing = _existing_conns(db, capture_id)

    # packet_key -> Connection
    found: dict[str, Connection] = {}
    for conn in existing.values():
        found[conn.conn_key] = conn

    for p in packets:
        key = _packet_conn_key(p)
        if key is None:
            continue
        conn = found.get(key)
        if conn is None:
            conn = Connection(
                capture_id=capture_id,
                conn_key=key,
                src=p.src,
                dst=p.dst,
                proto=p.proto,
                sport=p.sport,
                dport=p.dport,
                source="tshark",
            )
            found[key] = conn
            db.add(conn)
        conn.packets = (conn.packets or 0) + 1
        conn.bytes_total = (conn.bytes_total or 0) + (p.length or 0)
        if p.ts is not None:
            if conn.first_ts is None or p.ts < conn.first_ts:
                conn.first_ts = p.ts
            if conn.last_ts is None or p.ts > conn.last_ts:
                conn.last_ts = p.ts
    db.commit()
    return len(found)


def _entity_conn_key(src, dst, sport, dport, proto) -> str | None:
    if not src or not dst:
        return None
    return canonical_conn_key(src, dst, proto, sport, dport)


def correlate_zeek_conn(db: Session, capture_id: str) -> int:
    """Attach Zeek conn row details to matching normalized connections.

    Uses the canonical 5-tuple key. Creates a Connection when a Zeek conn row
    has no matching TShark packets (so pure-Zeek connections are recorded too).
    Sets zeek_uid, conn_state, service, byte counts and duration when not
    already present from TShark evidence. Returns the number of connections
    matched/enriched.
    """
    conns = {
        c.conn_key: c
        for c in db.query(Connection).filter(Connection.capture_id == capture_id).all()
    }
    packet_keys = {
        k
        for p in db.query(Packet).filter(Packet.capture_id == capture_id).all()
        if (k := _packet_conn_key(p)) is not None
    }
    matched = 0
    for row in db.query(ZeekConn).filter(ZeekConn.capture_id == capture_id).all():
        key = _zeek_conn_key(row)
        if key is None:
            continue
        conn = conns.get(key)
        if conn is None:
            conn = Connection(
                capture_id=capture_id,
                conn_key=key,
                src=row.src,
                dst=row.dst,
                proto=row.proto,
                sport=row.sport,
                dport=row.dport,
                source="zeek",
            )
            conns[key] = conn
            db.add(conn)
        if row.uid:
            conn.zeek_uid = row.uid
        if row.service and not conn.service:
            conn.service = row.service
        if row.conn_state and not conn.conn_state:
            conn.conn_state = row.conn_state
        if row.orig_bytes is not None and conn.orig_bytes is None:
            conn.orig_bytes = row.orig_bytes
        if row.resp_bytes is not None and conn.resp_bytes is None:
            conn.resp_bytes = row.resp_bytes
        if row.duration is not None and conn.duration is None:
            conn.duration = row.duration
        if row.ts is not None:
            if conn.first_ts is None or row.ts < conn.first_ts:
                conn.first_ts = row.ts
            if conn.last_ts is None or row.ts > conn.last_ts:
                conn.last_ts = row.ts
        if key in packet_keys:
            conn.source = "tshark+zeek" if conn.source == "tshark" else conn.source
        matched += 1
    db.commit()
    return matched


def _find_connection(db: Session, capture_id: str, uid: str | None, src, dst, sport, dport, proto, ts) -> Connection | None:
    """Resolve a connection for aggregation using uid (strong) then 5-tuple+time."""
    if uid:
        conn = (
            db.query(Connection)
            .filter(
                Connection.capture_id == capture_id,
                Connection.zeek_uid == uid,
            )
            .first()
        )
        if conn:
            return conn
    key = _entity_conn_key(src, dst, sport, dport, proto)
    if key is None:
        return None
    conn = (
        db.query(Connection)
        .filter(
            Connection.capture_id == capture_id,
            Connection.conn_key == key,
        )
        .first()
    )
    if conn and _within_window(ts, conn.first_ts, conn.last_ts):
        return conn
    return None


def promote_zeek_dns(db: Session, capture_id: str) -> int:
    """Promote Zeek dns.log rows into normalized DnsEvent rows (dedup by uid)."""
    existing = {
        (d.zeek_uid, d.query)
        for d in db.query(DnsEvent)
        .filter(DnsEvent.capture_id == capture_id, DnsEvent.zeek_uid.isnot(None))
        .all()
    }
    count = 0
    for row in db.query(ZeekDns).filter(ZeekDns.capture_id == capture_id).all():
        if row.uid and (row.uid, row.query) in existing:
            continue
        conn = _find_connection(
            db,
            capture_id,
            row.uid,
            row.src,
            row.dst,
            None,
            None,
            row.proto,
            row.ts,
        )
        db.add(
            DnsEvent(
                capture_id=capture_id,
                connection_id=conn.id if conn else None,
                ts=row.ts,
                src=row.src,
                dst=row.dst,
                query=row.query,
                qtype_name=row.qtype_name,
                rcode_name=row.rcode_name,
                answers=row.answers,
                proto=row.proto,
                trans_id=row.trans_id,
                source="zeek",
                zeek_uid=row.uid,
                raw=row.raw,
            )
        )
        count += 1
    db.commit()
    return count


def promote_zeek_http(db: Session, capture_id: str) -> int:
    """Promote Zeek http.log rows into normalized HttpEvent rows (dedup by uid)."""
    existing = {
        (h.zeek_uid, h.uri)
        for h in db.query(HttpEvent)
        .filter(HttpEvent.capture_id == capture_id, HttpEvent.zeek_uid.isnot(None))
        .all()
    }
    count = 0
    for row in db.query(ZeekHttp).filter(ZeekHttp.capture_id == capture_id).all():
        if row.uid and (row.uid, row.uri) in existing:
            continue
        conn = _find_connection(
            db,
            capture_id,
            row.uid,
            row.src,
            row.dst,
            None,
            None,
            "tcp",
            row.ts,
        )
        db.add(
            HttpEvent(
                capture_id=capture_id,
                connection_id=conn.id if conn else None,
                ts=row.ts,
                src=row.src,
                dst=row.dst,
                method=row.method,
                host=row.host,
                uri=row.uri,
                user_agent=row.user_agent,
                status_code=row.status_code,
                resp_len=row.resp_len,
                referrer=row.referrer,
                source="zeek",
                zeek_uid=row.uid,
                raw=row.raw,
            )
        )
        count += 1
    db.commit()
    return count


def promote_packet_dns(db: Session, capture_id: str) -> int:
    """Promote DNS hints from TShark packets into DnsEvent rows (source=tshark)."""
    count = 0
    for row in db.query(Packet).filter(
        Packet.capture_id == capture_id,
        Packet.dns_qname.isnot(None),
    ).all():
        conn = _find_connection(
            db,
            capture_id,
            None,
            row.src,
            row.dst,
            row.sport,
            row.dport,
            row.proto,
            row.ts,
        )
        db.add(
            DnsEvent(
                capture_id=capture_id,
                connection_id=conn.id if conn else None,
                ts=row.ts,
                src=row.src,
                dst=row.dst,
                query=row.dns_qname,
                qtype_name=row.dns_qtype,
                rcode_name=row.dns_rcode,
                proto=row.proto,
                source="tshark",
                packet_ref=str(row.frame_number) if row.frame_number else None,
            )
        )
        count += 1
    db.commit()
    return count


def promote_packet_http(db: Session, capture_id: str) -> int:
    """Promote HTTP hints from TShark packets into HttpEvent rows (source=tshark)."""
    count = 0
    for row in db.query(Packet).filter(
        Packet.capture_id == capture_id,
        Packet.http_method.isnot(None),
    ).all():
        conn = _find_connection(
            db,
            capture_id,
            None,
            row.src,
            row.dst,
            row.sport,
            row.dport,
            row.proto,
            row.ts,
        )
        db.add(
            HttpEvent(
                capture_id=capture_id,
                connection_id=conn.id if conn else None,
                ts=row.ts,
                src=row.src,
                dst=row.dst,
                method=row.http_method,
                host=row.http_host,
                uri=row.http_uri,
                status_code=row.http_status,
                source="tshark",
                packet_ref=str(row.frame_number) if row.frame_number else None,
            )
        )
        count += 1
    db.commit()
    return count


def clear_normalized(db: Session, capture_id: str) -> None:
    """Remove existing normalized rows for a capture (idempotent re-run)."""
    for model in (Packet, Connection, DnsEvent, HttpEvent):
        db.query(model).filter(model.capture_id == capture_id).delete()
    db.commit()


def normalize_capture(db: Session, pcap: Path, capture_id: str | None = None) -> NormalizeSummary:
    """Run the full normalization + correlation pipeline for a capture."""
    # Idempotent: start from a clean slate for this capture.
    if capture_id:
        clear_normalized(db, capture_id)

    # 1. TShark packet parse + persist.
    records = parse_packets(pcap) if tshark_available() else []
    packets_persisted = 0
    if records:
        packets_persisted = persist_packets(db, capture_id, records)

    # 2. Connections from packets.
    connections = build_connections_from_packets(db, capture_id) if records else 0

    zeek_on = zeek_available()
    zeek_conn_matched = 0
    dns_events = 0
    http_events = 0
    if zeek_on:
        # 3. Attach Zeek conn details (also creates pure-Zeek connections).
        zeek_conn_matched = correlate_zeek_conn(db, capture_id)
        connections = (
            db.query(Connection).filter(Connection.capture_id == capture_id).count()
        )
        # 4. Promote Zeek dns/http into normalized events.
        dns_events = promote_zeek_dns(db, capture_id)
        http_events = promote_zeek_http(db, capture_id)

    # 5. Promote TShark packet DNS/HTTP hints (works with or without Zeek).
    dns_events += promote_packet_dns(db, capture_id)
    http_events += promote_packet_http(db, capture_id)

    connections_with_zeek = (
        db.query(Connection)
        .filter(Connection.capture_id == capture_id, Connection.zeek_uid.isnot(None))
        .count()
    )

    return NormalizeSummary(
        capture_id=capture_id,
        tshark_available=tshark_available(),
        zeek_available=zeek_on,
        packets_parsed=len(records),
        packets_persisted=packets_persisted,
        connections=connections,
        dns_events=dns_events,
        http_events=http_events,
        connections_with_zeek=connections_with_zeek,
    )
