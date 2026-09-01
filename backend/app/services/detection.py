"""Detection service: run the rule engine over normalized data and persist findings.

Reads the normalized records produced by the M9 correlation layer, runs the
deterministic rules, and stores resulting DetectionFinding rows. Gracefully
handles captures with no normalized data (no findings, non-erroring).
"""
from __future__ import annotations

import json

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.detection.rules import (
    ALL_RULES,
    DetectionFinding,
    RuleContext,
    run_all_rules,
)
from app.models.capture import Capture
from app.models.detection import DetectionFinding as FindingRow
from app.models.normalized import Connection, DnsEvent, HttpEvent, Packet
from app.schemas.detection import DetectionRunResult, DetectionSummary, RuleInfo

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def _thresholds_from_settings() -> dict:
    s = get_settings()
    return {
        "portscan_min_ports": s.detect_portscan_min_ports,
        "conn_rate_window_sec": s.detect_conn_rate_window_sec,
        "conn_rate_max_per_window": s.detect_conn_rate_max_per_window,
        "dns_nxdomain_min": s.detect_dns_nxdomain_min,
        "dns_query_diversity_min": s.detect_dns_query_diversity_min,
        "severity_high_multiplier": s.detect_severity_high_multiplier,
        "severity_critical_multiplier": s.detect_severity_critical_multiplier,
        "data_transfer_min_bytes": 10_000_000,
    }


def list_rule_info() -> list[RuleInfo]:
    """Return metadata for every registered rule."""
    return [
        RuleInfo(id=r["id"], name=r["name"], default_severity=r["default_severity"])
        for r in ALL_RULES
    ]


def run_detection(db: Session, capture_id: str) -> DetectionRunResult:
    """Run all rules over a capture's normalized data and persist findings."""
    # Clear prior findings for an idempotent re-run.
    db.query(FindingRow).filter(FindingRow.capture_id == capture_id).delete()

    connections = (
        db.query(Connection).filter(Connection.capture_id == capture_id).all()
    )
    dns = db.query(DnsEvent).filter(DnsEvent.capture_id == capture_id).all()
    http = db.query(HttpEvent).filter(HttpEvent.capture_id == capture_id).all()
    packets = db.query(Packet).filter(Packet.capture_id == capture_id).all()

    ctx = RuleContext(
        connections=connections,
        dns=dns,
        http=http,
        packets=packets,
        thresholds=_thresholds_from_settings(),
    )
    findings = run_all_rules(ctx)

    persisted = 0
    for f in findings:
        row = FindingRow(
            capture_id=capture_id,
            rule_id=f.rule_id,
            rule_name=f.rule_name,
            severity=f.severity,
            score=f.score,
            summary=f.summary,
            detail=f.detail,
            evidence=json.dumps(f.evidence) if f.evidence else None,
            ref_type=f.ref_type,
        )
        db.add(row)
        persisted += 1
    db.commit()

    return DetectionRunResult(
        capture_id=capture_id,
        findings=persisted,
        rules_evaluated=len(ALL_RULES),
        by_severity=_counts_by_severity(db, capture_id),
    )


def _counts_by_severity(db: Session, capture_id: str) -> dict[str, int]:
    rows = db.query(FindingRow.severity).filter(FindingRow.capture_id == capture_id).all()
    counts = {s: 0 for s in SEVERITY_ORDER}
    for (sev,) in rows:
        if sev in counts:
            counts[sev] += 1
    return counts


def findings_for_capture(db: Session, capture_id: str, severity: str | None = None, limit: int = 200) -> list[dict]:
    """Return persisted findings (optionally filtered by severity)."""
    q = db.query(FindingRow).filter(FindingRow.capture_id == capture_id)
    if severity:
        q = q.filter(FindingRow.severity == severity)
    rows = q.order_by(FindingRow.created_at.desc()).limit(limit).all()
    return [_finding_to_dict(r) for r in rows]


def _finding_to_dict(r: FindingRow) -> dict:
    return {
        "id": r.id,
        "capture_id": r.capture_id,
        "rule_id": r.rule_id,
        "rule_name": r.rule_name,
        "severity": r.severity,
        "score": r.score,
        "summary": r.summary,
        "detail": r.detail,
        "evidence": json.loads(r.evidence) if r.evidence else [],
        "ref_type": r.ref_type,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def summary_for_capture(db: Session, capture_id: str) -> DetectionSummary:
    rows = db.query(FindingRow).filter(FindingRow.capture_id == capture_id).all()
    by_sev = _counts_by_severity(db, capture_id)
    return DetectionSummary(capture_id=capture_id, total=len(rows), by_severity=by_sev)
