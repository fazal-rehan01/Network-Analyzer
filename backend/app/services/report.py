"""Security analysis PDF report builder (MILESTONE 14).

Composes a professional PDF via reportlab directly from persisted records:
capture info, simulation history, traffic summary, detection findings, packet
level (TShark) analysis, event level (Zeek) analysis, the TShark vs Zeek
comparison, and data-driven recommendations. Nothing is fabricated: every
number in the PDF traces to the database or to genuine tool availability.
"""
from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.analysis.tshark import tshark_available
from app.analysis.zeek import zeek_available
from app.models.capture import Capture
from app.models.detection import DetectionFinding
from app.models.incident import Incident
from app.models.normalized import Connection, DnsEvent, HttpEvent, Packet
from app.models.simulation import Simulation
from app.models.zeek import ZeekConn, ZeekDns, ZeekHttp, ZeekNotice, ZeekSsl
from app.schemas.report import ReportCaptureOption, ReportOptions
from app.services import analytics as analytics_svc
from app.services import compare as compare_svc

BPAD = 140

_SEV_ORDER = ("critical", "high", "medium", "low", "info")

_SLATE = colors.HexColor("#334155")
_LIGHT = colors.HexColor("#f1f5f9")
_CYAN = colors.HexColor("#06b6d4")
_VIOLET = colors.HexColor("#8b5cf6")
_AMBER = colors.HexColor("#d97706")
_GREEN = colors.HexColor("#059669")
_RULE = colors.HexColor("#cbd5e1")


def _esc(value: object) -> str:
    """Escape value for use inside a reportlab Paragraph."""
    return str(value or "—").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _dt(value) -> str:
    if not value:
        return "—"
    try:
        return value.isoformat(timespec="seconds")
    except (AttributeError, ValueError):
        return str(value)


def _num(value) -> str:
    if value is None:
        return "—"
    return f"{int(value):,}"


class _Styles:
    def __init__(self) -> None:
        base = getSampleStyleSheet()
        self.h1 = ParagraphStyle(
            "h1", parent=base["Heading1"], fontSize=22, leading=26,
            textColor=colors.HexColor("#0f172a"), spaceAfter=2,
        )
        self.subtitle = ParagraphStyle(
            "subtitle", parent=base["Normal"], fontSize=11, leading=15,
            textColor=colors.HexColor("#475569"), spaceAfter=8,
        )
        self.h2 = ParagraphStyle(
            "h2", parent=base["Heading2"], fontSize=13, leading=17,
            textColor=_CYAN, spaceBefore=12, spaceAfter=4,
        )
        self.h3 = ParagraphStyle(
            "h3", parent=base["Heading3"], fontSize=10.5, leading=14,
            textColor=_SLATE, spaceBefore=8, spaceAfter=2,
        )
        self.body = ParagraphStyle(
            "body", parent=base["Normal"], fontSize=9, leading=13,
            textColor=colors.HexColor("#1e293b"),
        )
        self.note = ParagraphStyle(
            "note", parent=base["Normal"], fontSize=8, leading=11,
            textColor=colors.HexColor("#64748b"),
        )
        self.hcell = ParagraphStyle(
            "hcell", parent=base["Normal"], fontSize=8, leading=10,
            textColor=colors.white, fontName="Helvetica-Bold",
        )
        self.cell = ParagraphStyle(
            "cell", parent=base["Normal"], fontSize=8, leading=10,
            textColor=colors.HexColor("#1e293b"),
        )


STYLES = _Styles()


def _table(headers: list[str], rows: list[list], widths: list[float]) -> Table:
    data = [[Paragraph(_esc(h), STYLES.hcell) for h in headers]]
    for row in rows:
        data.append([Paragraph(_esc(v), STYLES.cell) for v in row])
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _SLATE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _LIGHT]),
                ("GRID", (0, 0), (-1, -1), 0.4, _RULE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return t


def _header_block(story, title: str, subtitle: str) -> None:
    story.append(Paragraph(title, STYLES.h1))
    story.append(Paragraph(subtitle, STYLES.subtitle))
    story.append(Spacer(1, 6))


def _section(story, title: str) -> None:
    story.append(Paragraph(title, STYLES.h2))
    story.append(Spacer(1, 2))


def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(2.2 * cm, 1.1 * cm, "Traffic Analyzer - Security Analysis Report")
    canvas.drawRightString(A4[0] - 2.2 * cm, 1.1 * cm, f"Page {doc.page}")
    canvas.restoreState()


def list_report_options(db: Session) -> ReportOptions:
    rows = (
        db.query(Capture)
        .order_by(Capture.created_at.desc())
        .limit(100)
        .all()
    )
    captures = [
        ReportCaptureOption(
            id=c.id,
            name=c.name,
            source=c.source,
            status=c.status,
            packet_count=int(c.packet_count or 0),
            byte_count=int(c.byte_count or 0),
            created_at=c.created_at,
        )
        for c in rows
    ]
    return ReportOptions(global_available=True, captures=captures)


# ------------------------------------------------------------- section data


def _capture_info(db: Session, capture_id: str | None) -> Optional[dict]:
    if not capture_id:
        return None
    cap = db.get(Capture, capture_id)
    if cap is None:
        return None
    return {
        "id": cap.id,
        "name": cap.name or "untitled",
        "source": cap.source or "—",
        "filename": cap.filename or "—",
        "interface": cap.interface or "—",
        "filter_expr": cap.filter_expr or "—",
        "start_time": _dt(cap.start_time),
        "end_time": _dt(cap.end_time),
        "duration_sec": f"{cap.duration_sec:.1f}s" if cap.duration_sec is not None else "—",
        "packet_count": _num(cap.packet_count),
        "byte_count": _num(cap.byte_count),
        "status": cap.status or "—",
        "created_at": _dt(cap.created_at),
    }


def _simulation_rows(db: Session, limit: int = 10) -> list[dict]:
    rows = db.query(Simulation).order_by(Simulation.created_at.desc()).limit(limit).all()
    return [
        {
            "created": _dt(r.created_at),
            "scenario": r.scenario or "—",
            "name": r.name or "—",
            "target": r.target or "—",
            "status": r.status or "—",
            "packets": _num(r.packets_sent),
            "bytes": _num(r.bytes_sent),
            "conns": _num(r.connections),
            "rate": _num(r.rates_per_sec),
            "duration": f"{r.duration_sec:.1f}s" if r.duration_sec is not None else "—",
        }
        for r in rows
    ]


def _detection_findings(db: Session, capture_id: str | None, limit: int = 15) -> list[dict]:
    q = db.query(DetectionFinding)
    if capture_id:
        q = q.filter(DetectionFinding.capture_id == capture_id)
    q = q.order_by(DetectionFinding.created_at.desc()).limit(limit)
    return [
        {
            "time": _dt(r.created_at),
            "severity": r.severity or "info",
            "rule": r.rule_name or r.rule_id or "—",
            "summary": r.summary or r.detail or "—",
        }
        for r in q.all()
    ]


def _severity_summary(db: Session, capture_id: str | None) -> dict:
    counts = {s: 0 for s in _SEV_ORDER}
    q = db.query(DetectionFinding.severity)
    if capture_id:
        q = q.filter(DetectionFinding.capture_id == capture_id)
    for (sev,) in q.all():
        if sev in counts:
            counts[sev] += 1
    return counts


def _tshark_analysis(db: Session, capture_id: str | None) -> dict:
    proto_q = db.query(Packet.proto, func.count(Packet.id)).group_by(Packet.proto)
    src_q = db.query(Packet.src, func.count(Packet.id)).group_by(Packet.src)
    dst_q = db.query(Packet.dst, func.count(Packet.id)).group_by(Packet.dst)
    if capture_id:
        f = Packet.capture_id == capture_id
        proto_q = proto_q.filter(f)
        src_q = src_q.filter(f)
        dst_q = dst_q.filter(f)
    protos = proto_q.order_by(func.count(Packet.id).desc()).limit(8).all()
    srcs = src_q.order_by(func.count(Packet.id).desc()).limit(5).all()
    dsts = dst_q.order_by(func.count(Packet.id).desc()).limit(5).all()
    return {
        "protos": [[_esc(p or "unknown"), _num(c)] for p, c in protos],
        "srcs": [[_esc(s or "unknown"), _num(c)] for s, c in srcs],
        "dsts": [[_esc(d or "unknown"), _num(c)] for d, c in dsts],
        "packet_count": _num(
            db.query(func.count(Packet.id)).filter(
                Packet.capture_id == capture_id
            ).scalar() if capture_id else db.query(func.count(Packet.id)).scalar()
        ),
    }


def _zeek_analysis(db: Session, capture_id: str | None) -> dict:
    model_counts: list[tuple[str, type]] = [
        ("conn.log", ZeekConn),
        ("dns.log", ZeekDns),
        ("http.log", ZeekHttp),
        ("ssl.log", ZeekSsl),
        ("notice.log", ZeekNotice),
    ]
    rows: list[list[str]] = []
    for label, model in model_counts:
        q = db.query(func.count(model.id))
        if capture_id:
            q = q.filter(model.capture_id == capture_id)
        rows.append([label, _num(q.scalar() or 0)])

    conns_q = db.query(Connection.service, func.count(Connection.id)).group_by(Connection.service)
    if capture_id:
        conns_q = conns_q.filter(Connection.capture_id == capture_id)
    services = conns_q.order_by(func.count(Connection.id).desc()).limit(8).all()

    def _count(model):
        q = db.query(func.count(model.id))
        if capture_id:
            q = q.filter(model.capture_id == capture_id)
        return int(q.scalar() or 0)

    return {
        "rows": rows,
        "services": [[_esc(s or "unknown"), _num(c)] for s, c in services],
        "dns_normalized": _count(DnsEvent),
        "http_normalized": _count(HttpEvent),
        "connections": _count(Connection),
    }


def _comparison_summary(db: Session, capture_id: str | None) -> dict:
    avail = {"tshark": tshark_available(), "zeek": zeek_available()}
    if capture_id:
        comp = compare_svc.compare_capture(db, capture_id)
        if comp is not None:
            return {
                **avail,
                "connections_total": comp.summary.connections_total,
                "both": comp.summary.both,
                "tshark_only": comp.summary.tshark_only,
                "zeek_only": comp.summary.zeek_only,
                "packets_tshark": comp.summary.packets_tshark,
                "zeek_events": comp.summary.zeek_events,
            }
    q = db.query(Connection.source, func.count(Connection.id)).group_by(Connection.source)
    if capture_id:
        q = q.filter(Connection.capture_id == capture_id)
    by_source = {src or "unknown": int(c) for src, c in q.all()}
    return {
        **avail,
        "connections_total": sum(by_source.values()),
        "both": int(by_source.get("tshark+zeek", 0)),
        "tshark_only": int(by_source.get("tshark", 0)),
        "zeek_only": int(by_source.get("zeek", 0)),
        "packets_tshark": int(
            db.query(func.count(Packet.id)).filter(
                Packet.capture_id == capture_id
            ).scalar() if capture_id else db.query(func.count(Packet.id)).scalar()
        ),
        "zeek_events": int(_count_raw(db, ZeekConn, capture_id))
        + int(_count_raw(db, ZeekDns, capture_id))
        + int(_count_raw(db, ZeekHttp, capture_id))
        + int(_count_raw(db, ZeekSsl, capture_id))
        + int(_count_raw(db, ZeekNotice, capture_id)),
    }


def _count_raw(db: Session, model, capture_id: str | None) -> int:
    q = db.query(func.count(model.id))
    if capture_id:
        q = q.filter(model.capture_id == capture_id)
    return int(q.scalar() or 0)


def _recommendations(db: Session, capture_id: str | None, comparison: dict) -> list[tuple[str, str]]:
    recs: list[tuple[str, str]] = []

    d_count = db.query(DetectionFinding.severity)
    i_count = db.query(Incident.severity)
    if capture_id:
        d_count = d_count.filter(DetectionFinding.capture_id == capture_id)
        i_count = i_count.filter(Incident.capture_id == capture_id)
    d_sev = {s: 0 for s in _SEV_ORDER}
    i_sev = {s: 0 for s in _SEV_ORDER}
    for (sev,) in d_count.all():
        if sev in d_sev:
            d_sev[sev] += 1
    for (sev,) in i_count.all():
        if sev in i_sev:
            i_sev[sev] += 1

    hi = d_sev["critical"] + d_sev["high"] + i_sev["critical"] + i_sev["high"]
    if hi:
        recs.append(
            ("Remediate high/critical findings",
             f"{d_sev['high'] + d_sev['critical']} high/critical detection finding(s) and "
             f"{i_sev['high'] + i_sev['critical']} high/critical incident(s) were recorded. "
             "Prioritize containment and resolution before the evidence is rotated out."))

    rules = {
        r for (r,) in db.query(DetectionFinding.rule_id)
        if r
    }
    if "port_scan" in rules:
        recs.append(
            ("Harden against port scanning",
             "A scan pattern was detected. Restrict externally reachable ports, apply "
             "firewall/edge allow-lists, and tune IDS/IPS thresholds for the observed "
             "source address."))
    if "dns_anomaly" in rules or "dns_query_diversity" in rules:
        recs.append(
            ("Harden DNS usage",
             "DNS anomalies were observed. Validate recursive resolution, block high-"
             "volume/malformed queries at the resolver, and baseline normal query "
             "diversity."))
    if "conn_rate" in rules:
        recs.append(
            ("Investigate abnormal connection rate",
             "An unusual connection rate was flagged. Correlate with the sources above, "
             "check for bursty automation/misconfiguration, and rate-limit where "
             "appropriate."))
    if "high_data_transfer" in rules:
        recs.append(
            ("Review large transfers",
             "A large data transfer exceeded the configured threshold. Verify it was "
             "expected business traffic rather than an exfiltration attempt."))

    open_inc = db.query(Incident).filter(Incident.status.in_(["NEW", "INVESTIGATING", "CONTAINED"]))
    if capture_id:
        open_inc = open_inc.filter(Incident.capture_id == capture_id)
    open_count = open_inc.count()
    if open_count:
        recs.append(
            ("Triage open incidents",
             f"{open_count} incident(s) are still open (New/Investigating/Contained). "
             "Review them in the Incidents view, add analyst notes, and move them to "
             "Resolved or False Positive."))

    if comparison["tshark"]:
        recs.append(
            ("Preserve packet evidence",
             "TShark packet-level evidence is available. Keep the raw PCAP for "
             "forensics/evidence retention and import it into Wireshark for "
             "inspection."))
    if comparison["zeek"]:
        recs.append(
            ("Leverage event-level coverage",
             "Zeek events are being produced. Keep the Zeek pipeline active so "
             "connection/application-layer anomalies (conn/dns/http/ssl/notice) "
             "continue to enrich packet-level analysis."))

    recs.append(
        ("Next steps",
         "Re-run detection and regeneration limits are respected (analysis is "
         "deterministic and explainable). Re-generate this report after triaging "
         "incidents to confirm remediation."))
    return recs


# ------------------------------------------------------------- PDF assembly


def build_report_pdf(
    db: Session, capture_id: str | None = None, title: str = "Security Analysis Report"
) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, rightMargin=2.2 * cm, leftMargin=2.2 * cm,
        topMargin=2.4 * cm, bottomMargin=2.2 * cm,
    )
    story: list = []

    scope_name = "Whole database"
    if capture_id:
        cap = db.get(Capture, capture_id)
        if cap is None:
            raise ValueError(f"Unknown capture: {capture_id}")
        scope_name = cap.name or cap.id

    _header_block(
        story, title,
        f"Scope: {scope_name} · Generated: {_dt(datetime.now())} · "
        "Traffic Analyzer",
    )

    # 1. Capture info ----------------------------------------------------
    _section(story, "1. Capture scope")
    info = _capture_info(db, capture_id)
    if info:
        story.append(
            _table(
                ["Name", "Source", "File", "Interface", "Filter"],
                [[info["name"], info["source"], info["filename"], info["interface"], info["filter_expr"]]],
                [4.2 * cm, 2.0 * cm, 4.0 * cm, 2.6 * cm, 3.4 * cm],
            )
        )
        story.append(Spacer(1, 3))
        story.append(
            _table(
                ["Started", "Ended", "Duration", "Packet count", "Byte count", "Status"],
                [[info["start_time"], info["end_time"], info["duration_sec"],
                  info["packet_count"], info["byte_count"], info["status"]]],
                [4.4 * cm, 4.4 * cm, 2.4 * cm, 2.6 * cm, 2.4 * cm, 2.0 * cm],
            )
        )
    else:
        story.append(
            Paragraph(
                "This report covers the <b>entire database</b> across all captures, "
                "simulations, detections and incidents. Scope to a single capture by "
                "passing its id.", STYLES.body))

    # 2. Simulation history ----------------------------------------------
    _section(story, "2. Simulation history")
    sims = _simulation_rows(db)
    if sims:
        story.append(
            _table(
                ["Created", "Scenario", "Name", "Target", "Status", "Packets", "Bytes", "Conns", "Rate/s", "Duration"],
                [
                    [r["created"], r["scenario"], r["name"], r["target"],
                     r["status"], r["packets"], r["bytes"], r["conns"], r["rate"], r["duration"]]
                    for r in sims
                ],
                [3.0 * cm, 1.9 * cm, 2.0 * cm, 2.0 * cm, 1.5 * cm, 1.3 * cm, 1.3 * cm, 1.1 * cm, 1.1 * cm, 1.3 * cm],
            )
        )
    else:
        story.append(Paragraph("No simulation runs recorded.", STYLES.body))

    # 3. Traffic summary -------------------------------------------------
    _section(story, "3. Traffic summary")
    analytics = analytics_svc.dashboard_analytics(db, capture_id)
    summ = analytics.summary
    story.append(
        _table(
            ["Captures", "Packets", "Connections", "Bytes", "Pkts/s", "Open incidents", "High/Critical", "Resolved"],
            [[_num(summ.captures), _num(summ.packets), _num(summ.connections),
              _num(summ.bytes_total), f"{summ.packets_per_sec:.2f}", _num(summ.open_incidents),
              _num(summ.high_critical_incidents), _num(summ.resolved_incidents)]],
            [3.2 * cm, 2.4 * cm, 2.8 * cm, 2.6 * cm, 2.0 * cm, 2.6 * cm, 2.6 * cm, 2.2 * cm],
        )
    )

    if analytics.protocol_distribution:
        story.append(Paragraph("Top protocols (by connections)", STYLES.h3))
        story.append(
            _table(
                ["Protocol", "Connections", "Bytes"],
                [[p.proto, _num(p.count), _num(p.bytes)] for p in analytics.protocol_distribution],
                [5.0 * cm, 4.0 * cm, 5.0 * cm],
            ))

    if analytics.top_sources or analytics.top_destinations:
        story.append(Paragraph("Top talkers", STYLES.h3))
        talker_rows = []
        for i in range(max(len(analytics.top_sources), len(analytics.top_destinations))):
            src = analytics.top_sources[i] if i < len(analytics.top_sources) else None
            dst = analytics.top_destinations[i] if i < len(analytics.top_destinations) else None
            talker_rows.append([
                src.ip if src else "—", _num(src.packets) if src else "—", _num(src.bytes) if src else "—",
                dst.ip if dst else "—", _num(dst.packets) if dst else "—", _num(dst.bytes) if dst else "—",
            ])
        story.append(
            _table(
                ["Source", "Packets", "Bytes", "Destination", "Packets", "Bytes"],
                talker_rows,
                [3.0 * cm, 1.8 * cm, 1.8 * cm, 3.2 * cm, 1.8 * cm, 1.8 * cm],
            ))

    if analytics.top_conversations:
        story.append(Paragraph("Top conversations (by bytes)", STYLES.h3))
        story.append(
            _table(
                ["Source", "Destination", "Proto", "Packets", "Bytes"],
                [[c.src, c.dst, c.proto, _num(c.packets), _num(c.bytes)] for c in analytics.top_conversations],
                [4.0 * cm, 4.0 * cm, 2.0 * cm, 2.0 * cm, 3.0 * cm],
            ))

    if analytics.traffic_over_time:
        story.append(Paragraph("Peak traffic moments", STYLES.h3))
        peaks = sorted(analytics.traffic_over_time, key=lambda p: p.packets, reverse=True)[:5]
        story.append(
            _table(
                ["Second", "Packets", "Bytes"],
                [[f"{p.ts:.0f}", _num(p.packets), _num(p.bytes)] for p in peaks],
                [5.0 * cm, 4.5 * cm, 5.5 * cm],
            ))

    if analytics.dns_stats.total:
        story.append(Paragraph("DNS activity", STYLES.h3))
        dns_rows = [["Total queries", _num(analytics.dns_stats.total)],
                    ["Unique queries", _num(analytics.dns_stats.unique_queries)]]
        for rcode, cnt in analytics.dns_stats.by_rcode.items():
            dns_rows.append([f"Rcode {rcode}", _num(cnt)])
        story.append(
            _table(["Metric", "Value"], dns_rows[:6], [7.5 * cm, 6.0 * cm]))

    if analytics.http_stats.total:
        story.append(Paragraph("HTTP activity", STYLES.h3))
        story.append(
            _table(
                ["Total requests", "↑ Top methods", "↑ Top statuses"],
                [[_num(analytics.http_stats.total),
                  ", ".join(analytics.http_stats.by_method) or "—",
                  ", ".join(analytics.http_stats.by_status) or "—"]],
                [5.0 * cm, 4.5 * cm, 5.5 * cm],
            ))

    # 4. Detection -------------------------------------------------------
    _section(story, "4. Detection findings")
    dsev = _severity_summary(db, capture_id)
    story.append(
        _table(
            ["Critical", "High", "Medium", "Low", "Info"],
            [[_num(dsev["critical"]), _num(dsev["high"]), _num(dsev["medium"]),
              _num(dsev["low"]), _num(dsev["info"])]],
            [3.4 * cm, 3.0 * cm, 3.4 * cm, 3.0 * cm, 3.0 * cm],
        ))
    findings = _detection_findings(db, capture_id)
    if findings:
        story.append(
            _table(
                ["Time", "Severity", "Rule", "Summary"],
                [[f["time"], f["severity"], f["rule"], f["summary"]] for f in findings],
                [3.2 * cm, 1.7 * cm, 3.0 * cm, 6.0 * cm],
            ))
    else:
        story.append(Paragraph("No detection findings for this scope.", STYLES.body))

    # 5. Packet-level (TShark) analysis ----------------------------------
    _section(story, "5. Packet-level analysis  (Wireshark / TShark)")
    tshark = _tshark_analysis(db, capture_id)
    story.append(Paragraph(
        f"Normalized packet records: <b>{tshark['packet_count']}</b>. The packet-level "
        "view shows individual frames with timestamps, addresses, protocols, ports, "
        "lengths and TCP flags - the raw evidence of what happened on the wire.",
        STYLES.body))
    if tshark["protos"]:
        story.append(Paragraph("Top protocols by packets", STYLES.h3))
        story.append(_table(["Protocol", "Packets"],
                            tshark["protos"], [7.5 * cm, 6.0 * cm]))
    if tshark["srcs"]:
        story.append(Paragraph("Busiest source addresses (by packets)", STYLES.h3))
        story.append(_table(["Source", "Packets"], tshark["srcs"], [7.5 * cm, 6.0 * cm]))
    if tshark["dsts"]:
        story.append(Paragraph("Busiest destination addresses (by packets)", STYLES.h3))
        story.append(_table(["Destination", "Packets"], tshark["dsts"], [7.5 * cm, 6.0 * cm]))

    # 6. Event-level (Zeek) analysis -------------------------------------
    _section(story, "6. Event-level analysis  (Zeek)")
    zeek = _zeek_analysis(db, capture_id)
    story.append(Paragraph(
        "Zeek reconstructs flows and application-layer activity from logs. The rows "
        "below are the raw log counts available for this scope, plus normalized "
        "DNS/HTTP events already correlated to connections.",
        STYLES.body))
    story.append(_table(["Zeek log", "Rows"],
                        zeek["rows"], [7.5 * cm, 6.0 * cm]))
    story.append(Paragraph(
        f"Normalized DNS events: <b>{_num(zeek['dns_normalized'])}</b>, "
        f"HTTP events: <b>{_num(zeek['http_normalized'])}</b>, "
        f"connections: <b>{_num(zeek['connections'])}</b>.",
        STYLES.body))
    if zeek["services"]:
        story.append(Paragraph("Top services (by connections)", STYLES.h3))
        story.append(_table(["Service", "Connections"], zeek["services"], [7.5 * cm, 6.0 * cm]))

    # 7. Comparison ------------------------------------------------------
    _section(story, "7. Wireshark/TShark vs Zeek")
    comp = _comparison_summary(db, capture_id)
    story.append(Paragraph(
        "Wireshark/TShark provides <b>packet-level</b> visibility; Zeek provides "
        "<b>higher-level network/event</b> visibility. Not every packet has a Zeek "
        "event and not every flow has packets - correlation statuses are reported "
        "honestly per connection.",
        STYLES.body))
    story.append(
        _table(
            ["Tool", "Available", "Correlated both", "TShark only", "Zeek only",
             "TShark packets", "Zeek events"],
            [[
                "TShark", "yes" if comp["tshark"] else "no",
                _num(comp["both"]), _num(comp["tshark_only"]), _num(comp["zeek_only"]),
                _num(comp["packets_tshark"]), _num(comp["zeek_events"]),
            ]],
            [1.6 * cm, 1.7 * cm, 2.9 * cm, 2.3 * cm, 2.2 * cm, 2.8 * cm, 2.4 * cm],
        ))

    # 8. Recommendations -------------------------------------------------
    _section(story, "8. Recommendations")
    recs = _recommendations(db, capture_id, comp)
    for i, (head, body) in enumerate(recs, 1):
        story.append(Paragraph(f"<b>{i}. {_esc(head)}</b>", ParagraphStyle(
            "rechead", parent=STYLES.body, spaceBefore=4, textColor=_SLATE)))
        story.append(Paragraph(body, STYLES.body))

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Generated by the Traffic Analyzer SOC toolkit. Detection is rule-based and "
        "explainable; every value above traces to persisted TShark/Zeek/normalized "
        "records - no values are fabricated.",
        STYLES.note))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()