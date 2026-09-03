"""Zeek orchestration service.

Runs Zeek over a capture's PCAP, parses the resulting logs, persists normalized
event rows into the database, and returns a summary. Every step degrades
gracefully when Zeek is missing or a log type is absent.
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.analysis.zeek import parse_zeek_tsv, process_pcap
from app.core.config import get_settings
from app.models.capture import Capture
from app.models.zeek import ZEK_MODEL_BY_TYPE, ZeekConn, ZeekDns, ZeekHttp, ZeekNotice, ZeekSsl
from app.schemas.zeek import ZeekLogSummary, ZeekProcessResult

# Numeric columns per model to coerce from Zeek's string/NaN cell values.
_COERCIONS: dict[str, dict[str, str]] = {
    "conn": {
        "sport": "int", "dport": "int", "orig_bytes": "int", "resp_bytes": "int",
        "duration": "float", "ts": "float",
    },
    "dns": {
        "trans_id": "int", "rtt": "float", "ts": "float",
    },
    "http": {
        "status_code": "int", "resp_len": "int", "ts": "float",
    },
    "ssl": {
        "established": "bool", "ts": "float",
    },
    "notice": {
        "src_port": "int", "dst_port": "int", "ts": "float",
    },
}

# Column name mapping from Zeek field -> model attribute (snake_case camelCase in Zeek).
_FIELD_MAP: dict[str, dict[str, str]] = {
    "conn": {
        "proto": "proto", "id.orig_p": "sport", "id.resp_p": "dport",
        "orig_bytes": "orig_bytes", "resp_bytes": "resp_bytes",
        "conn_state": "conn_state", "duration": "duration", "service": "service",
    },
    "dns": {
        "query": "query", "qtype_name": "qtype_name", "rcode_name": "rcode_name",
        "answers": "answers", "proto": "proto", "trans_id": "trans_id", "rtt": "rtt",
    },
    "http": {
        "method": "method", "host": "host", "uri": "uri", "user_agent": "user_agent",
        "status_code": "status_code", "resp_len": "resp_len", "referrer": "referrer",
    },
    "ssl": {
        "server_name": "server_name", "version": "version", "cipher": "cipher",
        "established": "established", "client_subject": "client_subject",
        "server_subject": "server_subject",
    },
    "notice": {
        "note": "note", "msg": "msg", "sub": "sub", "severity": "severity",
        "id.orig_p": "src_port", "id.resp_p": "dst_port", "actions": "actions",
    },
}

_COMMON_FIELDS = {
    "ts": "ts",
    "uid": "uid",
    "id.orig_h": "src",
    "id.resp_h": "dst",
}


def _coerce(value, kind: str):
    if value is None or value == "" or value == "-" or value == "nan":
        return None
    try:
        if kind == "int":
            return int(value)
        if kind == "float":
            return float(value)
        if kind == "bool":
            if isinstance(value, bool):
                return value
            return str(value).strip().lower() in ("t", "true", "1", "y", "yes")
        return value
    except (TypeError, ValueError):
        return None


def _row_to_kwargs(log_type: str, row: dict) -> dict:
    """Map a parsed Zeek row dict into model constructor kwargs."""
    mapping = _FIELD_MAP.get(log_type, {})
    coercions = _COERCIONS.get(log_type, {})
    kwargs: dict = {}
    for zfield, attr in _COMMON_FIELDS.items():
        if zfield in row:
            kwargs[attr] = _coerce(row[zfield], coercions.get(attr, "str"))
    for zfield, attr in mapping.items():
        if zfield in row:
            kwargs[attr] = _coerce(row[zfield], coercions.get(attr, "str"))
    kwargs["raw"] = "\t".join(f"{k}={v}" for k, v in row.items())
    return kwargs


def persist_logs(db: Session, capture_id: str | None, logs: dict[str, list[dict]]) -> dict[str, int]:
    """Insert normalized Zeek event rows for each present log type.

    Returns a dict of log_type -> count inserted.
    """
    counts: dict[str, int] = {}
    model_by_type: dict[str, type] = {
        "conn": ZeekConn, "dns": ZeekDns, "http": ZeekHttp,
        "ssl": ZeekSsl, "notice": ZeekNotice,
    }
    for log_type, rows in logs.items():
        model = model_by_type.get(log_type)
        if model is None or not rows:
            counts[log_type] = 0
            continue
        for row in rows:
            kwargs = _row_to_kwargs(log_type, row)
            kwargs["capture_id"] = capture_id
            db.add(model(**kwargs))
        counts[log_type] = len(rows)
    db.commit()
    return counts


def process_capture(db: Session, pcap: Path, capture_id: str | None = None) -> ZeekProcessResult:
    """Run Zeek on a capture PCAP and persist normalized events."""
    result = process_pcap(pcap)

    counts: dict[str, int] = {}
    if result["logs"]:
        counts = persist_logs(db, capture_id, result["logs"])
    elif result.get("error") is None:
        # No logs produced but no error (e.g. empty capture). Nothing to store.
        pass

    summary = [ZeekLogSummary(**s) for s in result["summary"]]
    return ZeekProcessResult(
        available=result["available"],
        summary=summary,
        logs=result["logs"],
        error=result["error"],
        capture_id=capture_id,
    )


def events_for_capture(db: Session, capture_id: str, log_type: str | None = None, limit: int = 200) -> list[dict]:
    """Return normalized Zeek events persisted for a capture."""
    names = ["conn", "dns", "http", "ssl", "notice"]
    if log_type:
        if log_type not in ZEK_MODEL_BY_TYPE:
            return []
        names = [log_type]

    results: list[dict] = []
    for name in names:
        model = ZEK_MODEL_BY_TYPE[name]
        rows = (
            db.query(model)
            .filter(model.capture_id == capture_id)
            .order_by(model.ts)
            .limit(limit)
            .all()
        )
        for r in rows:
            results.append(_event_dict(name, r))
    results.sort(key=lambda e: e["ts"] or 0)
    return results[:limit]


def _event_dict(log_type: str, row) -> dict:
    """Convert an ORM Zeek row into a JSON event dict for the API/UI."""
    mapping = _FIELD_MAP.get(log_type, {})
    fields: dict = {}
    # Include mapped non-common columns.
    for zfield, attr in mapping.items():
        value = getattr(row, attr, None)
        if value is not None:
            fields[zfield] = value
    return {
        "id": row.id,
        "log_type": log_type,
        "capture_id": row.capture_id,
        "ts": row.ts,
        "uid": row.uid,
        "src": row.src,
        "dst": row.dst,
        "fields": fields,
        "created_at": row.created_at.isoformat(),
    }


def log_list_available() -> dict:
    """Return available Zeek tool + default storage info (lightweight, non-DB)."""
    from app.analysis.zeek import zeek_available

    settings = get_settings()
    return {
        "available": zeek_available(),
        "zeek_dir": str(settings.zeek_dir_abs),
    }
